//! Unified SSRF protection module.
//!
//! Provides a single blocklist and IP-range check used by both
//! `host_functions.rs` (WASM sandbox fetch) and `web_fetch.rs` (builtin tools).
//! Any addition to the blocklist applies everywhere automatically.

use std::net::{IpAddr, ToSocketAddrs};

/// Hostnames and literal IPs that must never be contacted.
/// Covers cloud IMDS endpoints, loopback variants, and link-local sentinels.
const BLOCKED_HOSTNAMES: &[&str] = &[
    "localhost",
    "ip6-localhost",
    "metadata.google.internal",
    "metadata.aws.internal",
    "instance-data",
    "169.254.169.254",
    "100.100.100.200", // Alibaba Cloud IMDS
    "192.0.0.192",     // Azure IMDS alternative
    "0.0.0.0",
    "::1",
    "[::1]",
];

/// Check whether a URL targets a private/internal network resource.
///
/// Validates:
/// 1. Scheme is `http://` or `https://` (blocks `file://`, `gopher://`, etc.)
/// 2. Hostname is not on the static blocklist (cloud metadata, loopback, etc.)
/// 3. Every resolved IP is not loopback, unspecified, or in a private range.
///
/// Must be called **before** any network I/O.
pub fn check_ssrf(url: &str) -> Result<(), String> {
    // Step 1: scheme gate
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("Only http:// and https:// URLs are allowed".to_string());
    }

    let host = extract_host(url);

    // For IPv6 bracket notation like [::1]:80, extract [::1] as hostname
    let hostname = if host.starts_with('[') {
        host.find(']').map(|i| &host[..=i]).unwrap_or(&host)
    } else {
        host.split(':').next().unwrap_or(&host)
    };

    // Step 2: hostname blocklist
    if BLOCKED_HOSTNAMES.contains(&hostname) {
        return Err(format!(
            "SSRF blocked: {hostname} is a restricted hostname"
        ));
    }

    // Step 3: DNS resolution — check every returned IP
    let port = if url.starts_with("https") { 443 } else { 80 };
    let socket_addr = format!("{hostname}:{port}");
    if let Ok(addrs) = socket_addr.to_socket_addrs() {
        for addr in addrs {
            let ip = addr.ip();
            if ip.is_loopback() || ip.is_unspecified() || is_private_ip(&ip) {
                return Err(format!(
                    "SSRF blocked: {hostname} resolves to private IP {ip}"
                ));
            }
        }
    }

    Ok(())
}

/// Check if an IP address falls in a private/reserved range.
///
/// IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 (link-local)
/// IPv6: fc00::/7 (ULA), fe80::/10 (link-local)
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            matches!(
                octets,
                [10, ..] | [172, 16..=31, ..] | [192, 168, ..] | [169, 254, ..]
            )
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            (segments[0] & 0xfe00) == 0xfc00 || (segments[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Extract `host:port` from a URL string.
///
/// Handles IPv6 bracket notation (`[::1]:8080`), explicit ports, and
/// defaults to 443 for `https` / 80 for `http`.
pub fn extract_host(url: &str) -> String {
    if let Some(after_scheme) = url.split("://").nth(1) {
        let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);
        // Handle IPv6 bracket notation: [::1]:8080
        if host_port.starts_with('[') {
            if let Some(bracket_end) = host_port.find(']') {
                let ipv6_host = &host_port[..=bracket_end]; // includes brackets
                let after_bracket = &host_port[bracket_end + 1..];
                if let Some(port) = after_bracket.strip_prefix(':') {
                    return format!("{ipv6_host}:{port}");
                }
                let default_port = if url.starts_with("https") { 443 } else { 80 };
                return format!("{ipv6_host}:{default_port}");
            }
        }
        if host_port.contains(':') {
            host_port.to_string()
        } else if url.starts_with("https") {
            format!("{host_port}:443")
        } else {
            format!("{host_port}:80")
        }
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssrf_blocks_localhost() {
        assert!(check_ssrf("http://localhost/admin").is_err());
        assert!(check_ssrf("http://localhost:8080/api").is_err());
    }

    #[test]
    fn test_ssrf_blocks_ip6_localhost() {
        assert!(check_ssrf("http://ip6-localhost/admin").is_err());
    }

    #[test]
    fn test_ssrf_blocks_metadata() {
        assert!(check_ssrf("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(check_ssrf("http://metadata.google.internal/computeMetadata/v1/").is_err());
        assert!(check_ssrf("http://metadata.aws.internal/latest/").is_err());
        assert!(check_ssrf("http://instance-data/latest/").is_err());
    }

    #[test]
    fn test_ssrf_blocks_cloud_metadata() {
        assert!(check_ssrf("http://100.100.100.200/latest/meta-data/").is_err());
        assert!(check_ssrf("http://192.0.0.192/metadata/instance").is_err());
    }

    #[test]
    fn test_ssrf_blocks_zero_and_ipv6() {
        assert!(check_ssrf("http://0.0.0.0/").is_err());
        assert!(check_ssrf("http://[::1]/admin").is_err());
        assert!(check_ssrf("http://[::1]:8080/api").is_err());
    }

    #[test]
    fn test_ssrf_blocks_non_http() {
        assert!(check_ssrf("file:///etc/passwd").is_err());
        assert!(check_ssrf("ftp://internal.corp/data").is_err());
        assert!(check_ssrf("gopher://evil.com").is_err());
    }

    #[test]
    fn test_ssrf_allows_public() {
        assert!(check_ssrf("https://api.openai.com/v1/chat").is_ok());
        assert!(check_ssrf("https://google.com").is_ok());
    }

    #[test]
    fn test_private_ip_v4() {
        assert!(is_private_ip(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"192.168.1.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"169.254.169.254".parse::<IpAddr>().unwrap()));
        assert!(!is_private_ip(&"8.8.8.8".parse::<IpAddr>().unwrap()));
        assert!(!is_private_ip(&"1.1.1.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_private_ip_v6() {
        // fc00::/7 (ULA)
        assert!(is_private_ip(&"fd00::1".parse::<IpAddr>().unwrap()));
        // fe80::/10 (link-local)
        assert!(is_private_ip(&"fe80::1".parse::<IpAddr>().unwrap()));
        // public
        assert!(!is_private_ip(
            &"2607:f8b0:4004:800::200e".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn test_extract_host_standard() {
        assert_eq!(extract_host("https://api.openai.com/v1/chat"), "api.openai.com:443");
        assert_eq!(extract_host("http://localhost:8080/api"), "localhost:8080");
        assert_eq!(extract_host("http://example.com"), "example.com:80");
    }

    #[test]
    fn test_extract_host_ipv6() {
        assert_eq!(extract_host("http://[::1]:8080/path"), "[::1]:8080");
        assert_eq!(extract_host("https://[::1]/path"), "[::1]:443");
        assert_eq!(extract_host("http://[::1]/path"), "[::1]:80");
    }
}
