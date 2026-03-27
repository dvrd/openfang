//! Production middleware for the OpenFang API server.
//!
//! Provides:
//! - Request ID generation and propagation
//! - Per-endpoint structured request logging
//! - In-memory rate limiting (per IP)

use axum::body::Body;
use axum::http::{HeaderValue, Request, Response, StatusCode};
use axum::middleware::Next;
use sha2::{Sha256, Digest}; // constant-time auth: sha2 + subtle used together
use std::time::Instant;
use subtle::ConstantTimeEq;
use tracing::info;

/// Request ID header name (standard).
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Middleware: inject a unique request ID and log the request/response.
pub async fn request_logging(request: Request<Body>, next: Next) -> Response<Body> {
    let request_id = uuid::Uuid::new_v4().to_string();
    let method = request.method().clone();
    let uri = request.uri().path().to_string();
    let start = Instant::now();

    let mut response = next.run(request).await;

    let elapsed = start.elapsed();
    let status = response.status().as_u16();

    info!(
        request_id = %request_id,
        method = %method,
        path = %uri,
        status = status,
        latency_ms = elapsed.as_millis() as u64,
        "API request"
    );

    // Inject the request ID into the response
    if let Ok(header_val) = request_id.parse() {
        response.headers_mut().insert(REQUEST_ID_HEADER, header_val);
    }

    response
}

/// Authentication state passed to the auth middleware.
#[derive(Clone)]
pub struct AuthState {
    pub api_key: String,
    pub auth_enabled: bool,
    pub session_secret: String,
}

/// Bearer token authentication middleware.
///
/// When `api_key` is non-empty (after trimming), requests to non-public
/// endpoints must include `Authorization: Bearer <api_key>`.
/// If the key is empty or whitespace-only, auth is disabled entirely
/// (public/local development mode).
///
/// When dashboard auth is enabled, session cookies are also accepted.
pub async fn auth(
    axum::extract::State(auth_state): axum::extract::State<AuthState>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    // SECURITY: Capture method early for method-aware public endpoint checks.
    let method = request.method().clone();

    // SECURITY: Reject path-traversal sequences before any allowlist check.
    // Without this, a raw path like /a2a/../api/admin would pass starts_with("/a2a/")
    // in the public allowlist below, while the router resolves it to /api/admin.
    // Patterns covered:
    //   /../ or /..  — literal dot-dot
    //   %2e%2e       — percent-encoded dot-dot (both cases)
    //   ..%2f / ..%2F — dot-dot followed by encoded slash
    //   %252e        — double-encoded dot (decodes to %2e on a second pass)
    //   %255c        — double-encoded backslash (Windows path separator)
    // Note: bare %2F (encoded slash) is NOT blocked — it is valid in path segments
    // (e.g. /api/providers/github-copilot/oauth/poll/abc%2Fdef) and does not form
    // a traversal sequence on its own.
    let path = request.uri().path();
    let path_lower = path.to_ascii_lowercase();
    if path_lower.contains("/../")
        || path_lower.ends_with("/..")
        || path_lower.contains("%2e%2e")
        || path_lower.contains("..%2f")
        || path_lower.contains("%252e")
        || path_lower.contains("%255c")
    {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(r#"{"error":"Invalid path"}"#))
            .unwrap_or_default();
    }
    if path == "/api/shutdown" {
        let is_loopback = request
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip().is_loopback())
            .unwrap_or(false); // SECURITY: default-deny — unknown origin is NOT loopback
        if is_loopback {
            return next.run(request).await;
        }
    }

    // Public endpoints that don't require auth (dashboard needs these).
    // SECURITY: /api/agents is GET-only (listing). POST (spawn) requires auth.
    // SECURITY: Public endpoints are GET-only unless explicitly noted.
    // POST/PUT/DELETE to any endpoint ALWAYS requires auth to prevent
    // unauthenticated writes (cron job creation, skill install, etc.).
    let is_get = method == axum::http::Method::GET;
    let is_options = method == axum::http::Method::OPTIONS;

    // SECURITY: Public allowlist. All other endpoints require auth.
    // Auth endpoints must be public so users can log in.
    // A2A federation endpoints must be public for inter-agent protocol.
    // Dashboard read endpoints are public GET-only so the SPA can render.
    let is_public = is_options  // CORS preflight
        || (path == "/" && is_get)
        || (path == "/logo.png" && is_get)
        || (path == "/favicon.ico" && is_get)
        || (path == "/manifest.json" && is_get)
        || (path == "/sw.js" && is_get)
        || (path == "/api/health" && is_get)
        || (path == "/api/version" && is_get)
        // Auth flow — must be reachable without a session
        || path == "/api/auth/login"
        || path == "/api/auth/logout"
        || (path == "/api/auth/check" && is_get)
        // A2A federation protocol — external agents call these.
        // GET for status/discovery, POST for task submission per A2A spec.
        // Use path_lower for the prefix check so non-conforming clients that
        // uppercase the path segment (/A2A/tasks) are still handled correctly.
        || (path_lower == "/.well-known/agent.json" && is_get)
        || (path_lower.starts_with("/a2a/") && (is_get || method == axum::http::Method::POST))
        // OAuth callbacks — only the specific Copilot device flow endpoints
        || (path == "/api/providers/github-copilot/oauth/start" && method == axum::http::Method::POST)
        || (path.starts_with("/api/providers/github-copilot/oauth/poll/") && is_get);

    if is_public {
        return next.run(request).await;
    }

    // If no API key configured (empty or missing), skip auth entirely.
    // Users who don't set api_key accept that all endpoints are open.
    // To secure the dashboard, set a non-empty api_key in config.toml.
    // Note: api_key is already trimmed at startup in server.rs.
    if auth_state.api_key.is_empty() && !auth_state.auth_enabled {
        return next.run(request).await;
    }
    let api_key = auth_state.api_key.as_str();

    // Check Authorization: Bearer <token> header, then fallback to X-API-Key
    let bearer_token = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let api_token = bearer_token.or_else(|| {
        request
            .headers()
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
    });

    // SECURITY: Use constant-time comparison to prevent timing attacks.
    let header_auth = api_token.map(|token| constant_time_key_match(token, api_key));

    // WARNING: ?token= in the URL leaks the API key to browser history, server
    // logs, and any intermediary proxies. This is a fallback for clients that
    // cannot set HTTP headers (e.g. EventSource/SSE, WebSocket from browsers).
    // Prefer the Authorization: Bearer <key> header whenever possible.
    // TODO: Replace ?token= with short-lived session tokens to limit exposure.
    let query_token = request
        .uri()
        .query()
        .and_then(|q| q.split('&').find_map(|pair| pair.strip_prefix("token=")));

    if query_token.is_some() {
        tracing::warn!(
            path = %path,
            "API key passed via ?token= query parameter — this leaks the key to logs and proxies. \
             Use the Authorization: Bearer <key> header instead."
        );
    }

    // SECURITY: Use constant-time comparison to prevent timing attacks.
    let query_auth = query_token.map(|token| constant_time_key_match(token, api_key));

    // Accept if either auth method matches
    if header_auth == Some(true) || query_auth == Some(true) {
        return next.run(request).await;
    }

    // Check session cookie (dashboard login sessions)
    if auth_state.auth_enabled {
        if let Some(token) = extract_session_cookie(&request) {
            if crate::session_auth::verify_session_token(&token, &auth_state.session_secret)
                .is_some()
            {
                return next.run(request).await;
            }
        }
    }

    // Determine error message: was a credential provided but wrong, or missing entirely?
    let credential_provided = header_auth.is_some() || query_auth.is_some();
    let error_msg = if credential_provided {
        "Invalid API key"
    } else {
        "Missing Authorization: Bearer <api_key> header"
    };

    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("www-authenticate", "Bearer")
        .body(Body::from(
            serde_json::json!({"error": error_msg}).to_string(),
        ))
        .unwrap_or_default()
}

/// Constant-time comparison of a candidate token against the expected API key.
/// Hashes both values first so the comparison is always on fixed-length digests,
/// preventing length-leaking short-circuit.
fn constant_time_key_match(candidate: &str, expected: &str) -> bool {
    let candidate_hash = Sha256::digest(candidate.as_bytes());
    let expected_hash = Sha256::digest(expected.as_bytes());
    candidate_hash.ct_eq(&expected_hash).into()
}

/// Extract the `openfang_session` cookie value from a request.
fn extract_session_cookie(request: &Request<Body>) -> Option<String> {
    request
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                c.trim()
                    .strip_prefix("openfang_session=")
                    .map(|v| v.to_string())
            })
        })
}

/// Security headers middleware — applied to ALL API responses.
pub async fn security_headers(request: Request<Body>, next: Next) -> Response<Body> {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    // Use HeaderValue::from_static for compile-time-validated static values.
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    // Note: x-xss-protection is deprecated in all modern browsers and omitted.
    // Content-Security-Policy (below) is the correct mitigation for XSS.
    // The dashboard handler (webchat_page) sets its own nonce-based CSP.
    // For all other responses (API endpoints), apply a strict default.
    if !headers.contains_key("content-security-policy") {
        headers.insert(
            "content-security-policy",
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        );
    }
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "cache-control",
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_id_header_constant() {
        assert_eq!(REQUEST_ID_HEADER, "x-request-id");
    }
}
