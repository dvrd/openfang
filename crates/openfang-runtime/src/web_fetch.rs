//! Enhanced web fetch with SSRF protection, HTML→Markdown extraction,
//! in-memory caching, and external content markers.
//!
//! Pipeline: SSRF check → cache lookup → HTTP GET → detect HTML →
//! html_to_markdown() → truncate → wrap_external_content() → cache → return

use crate::ssrf::check_ssrf_async;
use crate::str_utils::safe_truncate_str;
use crate::web_cache::WebCache;
use crate::web_content::{html_to_markdown, wrap_external_content};
use openfang_types::config::WebFetchConfig;
use std::sync::Arc;
use tracing::debug;

/// Enhanced web fetch engine with SSRF protection and readability extraction.
pub struct WebFetchEngine {
    config: WebFetchConfig,
    client: reqwest::Client,
    cache: Arc<WebCache>,
}

impl WebFetchEngine {
    /// Create a new fetch engine from config with a shared cache.
    pub fn new(config: WebFetchConfig, cache: Arc<WebCache>) -> Self {
        // SECURITY: Disable automatic redirects to prevent SSRF bypass via
        // redirect from an allowed host to internal IPs (e.g. 169.254.169.254).
        let client = reqwest::Client::builder()
            .user_agent(crate::USER_AGENT)
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .gzip(true)
            .deflate(true)
            .brotli(true)
            .build()
            .unwrap_or_default();
        Self {
            config,
            client,
            cache,
        }
    }

    /// Fetch a URL with full security pipeline (GET only, for backwards compat).
    pub async fn fetch(&self, url: &str) -> Result<String, String> {
        self.fetch_with_options(url, "GET", None, None).await
    }

    /// Fetch a URL with configurable HTTP method, headers, and body.
    pub async fn fetch_with_options(
        &self,
        url: &str,
        method: &str,
        headers: Option<&serde_json::Map<String, serde_json::Value>>,
        body: Option<&str>,
    ) -> Result<String, String> {
        let method_upper = method.to_uppercase();

        // Step 1: SSRF protection — BEFORE any network I/O
        check_ssrf_async(url).await?;

        // Step 2: Cache lookup (only for GET)
        let cache_key = format!("fetch:{}:{}", method_upper, url);
        if method_upper == "GET" {
            if let Some(cached) = self.cache.get(&cache_key) {
                debug!(url, "Fetch cache hit");
                return Ok(cached);
            }
        }

        // Step 3: Build request with configured method
        let mut req = match method_upper.as_str() {
            "POST" => self.client.post(url),
            "PUT" => self.client.put(url),
            "PATCH" => self.client.patch(url),
            "DELETE" => self.client.delete(url),
            _ => self.client.get(url),
        };
        req = req.header(
            "User-Agent",
            format!("Mozilla/5.0 (compatible; {})", crate::USER_AGENT),
        );

        // Add custom headers
        if let Some(hdrs) = headers {
            for (k, v) in hdrs {
                if let Some(val) = v.as_str() {
                    req = req.header(k.as_str(), val);
                }
            }
        }

        // Add body for non-GET methods
        if let Some(b) = body {
            // Auto-detect JSON body
            if b.trim_start().starts_with('{') || b.trim_start().starts_with('[') {
                req = req.header("Content-Type", "application/json");
            }
            req = req.body(b.to_string());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {e}"))?;

        let status = resp.status();

        // Check response size
        if let Some(len) = resp.content_length() {
            if len > self.config.max_response_bytes as u64 {
                return Err(format!(
                    "Response too large: {} bytes (max {})",
                    len, self.config.max_response_bytes
                ));
            }
        }

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let resp_body = resp
            .text()
            .await
            .map_err(|e| format!("Failed to read response body: {e}"))?;

        // Step 4: For GET requests, detect HTML and convert to Markdown.
        // For non-GET (API calls), return raw body — don't mangle JSON/XML responses.
        let processed = if method_upper == "GET"
            && self.config.readability
            && is_html(&content_type, &resp_body)
        {
            let markdown = html_to_markdown(&resp_body);
            if markdown.trim().is_empty() {
                resp_body
            } else {
                markdown
            }
        } else {
            resp_body
        };

        // Step 5: Truncate (char-boundary-safe to avoid panics on multi-byte UTF-8)
        let truncated = if processed.len() > self.config.max_chars {
            format!(
                "{}... [truncated, {} total chars]",
                safe_truncate_str(&processed, self.config.max_chars),
                processed.len()
            )
        } else {
            processed
        };

        // Step 6: Wrap with external content markers
        let result = format!(
            "HTTP {status}\n\n{}",
            wrap_external_content(url, &truncated)
        );

        // Step 7: Cache (only GET responses)
        if method_upper == "GET" {
            self.cache.put(cache_key, result.clone());
        }

        Ok(result)
    }
}

/// Detect if content is HTML based on Content-Type header or body sniffing.
fn is_html(content_type: &str, body: &str) -> bool {
    if content_type.contains("text/html") || content_type.contains("application/xhtml") {
        return true;
    }
    // Sniff: check if body starts with HTML-like content
    let trimmed = body.trim_start();
    trimmed.starts_with("<!DOCTYPE")
        || trimmed.starts_with("<!doctype")
        || trimmed.starts_with("<html")
}

// SSRF protection is provided by the shared `crate::ssrf` module.
// See `crate::ssrf::check_ssrf` — called above in `fetch_with_options`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssrf::check_ssrf;
    use crate::str_utils::safe_truncate_str;

    #[test]
    fn test_truncate_multibyte_no_panic() {
        // Simulate a gzip-decoded response containing multi-byte UTF-8
        // (Chinese, Japanese, emoji — common on international finance sites).
        // Old code: &s[..max] panics when max lands inside a multi-byte char.
        let content = "\u{4f60}\u{597d}\u{4e16}\u{754c}!"; // "你好世界!" = 13 bytes
                                                           // Truncate at byte 7 — lands inside the 3rd Chinese char (bytes 6..9).
                                                           // safe_truncate_str walks back to byte 6, returning "你好".
        let truncated = safe_truncate_str(content, 7);
        assert_eq!(truncated, "\u{4f60}\u{597d}");
        assert!(truncated.len() <= 7);
    }

    #[test]
    fn test_truncate_emoji_no_panic() {
        let content = "\u{1f4b0}\u{1f4c8}\u{1f4b9}"; // 💰📈💹 = 12 bytes
                                                     // Truncate at byte 5 — lands inside the 2nd emoji (bytes 4..8).
        let truncated = safe_truncate_str(content, 5);
        assert_eq!(truncated, "\u{1f4b0}"); // 4 bytes
    }

    // SSRF tests now live in crate::ssrf::tests.
    // This test verifies the integration still works via the re-exported check_ssrf.
    #[test]
    fn test_ssrf_integration_via_shared_module() {
        assert!(check_ssrf("http://localhost/admin").is_err());
        assert!(check_ssrf("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(check_ssrf("http://100.100.100.200/latest/meta-data/").is_err());
        assert!(check_ssrf("https://google.com").is_ok());
        assert!(check_ssrf("file:///etc/passwd").is_err());
    }
}
