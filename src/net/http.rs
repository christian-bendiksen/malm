//! Bounded HTTPS downloads without external processes.
//!
//! HTTPS and public-host checks run for the initial URL and every redirect.
//! Redirects, connection time, total transfer time, and streamed bytes are
//! bounded without trusting `Content-Length`.
//!
//! The logic is written against a small transport trait so the redirect and
//! limit handling is unit-testable without a network.

use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

pub(crate) struct DownloadLimits {
    pub max_redirects: usize,
    pub connect_timeout: Duration,
    pub total_deadline: Duration,
    pub max_bytes: u64,
    /// Allow private, loopback, link-local, or internal hosts.
    /// False by default to prevent SSRF through config-supplied asset URLs.
    pub allow_ssrf: bool,
}

impl Default for DownloadLimits {
    fn default() -> Self {
        Self {
            max_redirects: 10,
            connect_timeout: Duration::from_secs(15),
            total_deadline: Duration::from_secs(300),
            max_bytes: 2 * 1024 * 1024 * 1024,
            allow_ssrf: false,
        }
    }
}

pub(crate) struct HttpResponse {
    pub status: u16,
    pub location: Option<String>,
    pub body: Box<dyn Read>,
}

pub(crate) trait HttpTransport {
    fn get(&self, url: &str) -> Result<HttpResponse>;
}

/// Stream `url` into `out`, following redirects manually so every hop is
/// re-validated as https and counted. Returns the number of bytes written.
pub(crate) fn download_https(
    transport: &dyn HttpTransport,
    url: &str,
    limits: &DownloadLimits,
    out: &mut dyn Write,
) -> Result<u64> {
    let started = Instant::now();
    let mut current = url.to_owned();

    for _ in 0..=limits.max_redirects {
        require_https(&current)?;
        if !limits.allow_ssrf {
            require_public_host(&current)
                .context("refusing SSRF-class host (set MALM_ALLOW_SSRF=1 to override)")?;
        }
        let response = transport.get(&current)?;

        match response.status {
            200..=299 => {
                return copy_limited(response.body, out, limits, started).with_context(|| {
                    format!("stream response body ({} bytes max)", limits.max_bytes)
                });
            }
            301 | 302 | 303 | 307 | 308 => {
                let location = response
                    .location
                    .context("redirect response carries no Location header")?;
                current = resolve_redirect(&current, &location)?;
            }
            status => anyhow::bail!("server responded with HTTP {status}"),
        }
    }
    anyhow::bail!("too many redirects (max {})", limits.max_redirects);
}

fn copy_limited(
    mut body: Box<dyn Read>,
    out: &mut dyn Write,
    limits: &DownloadLimits,
    started: Instant,
) -> Result<u64> {
    let mut total: u64 = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        if started.elapsed() > limits.total_deadline {
            anyhow::bail!(
                "download exceeded the {}s transfer deadline",
                limits.total_deadline.as_secs()
            );
        }
        let read = body.read(&mut buf).context("read response body")?;
        if read == 0 {
            return Ok(total);
        }
        total += read as u64;
        if total > limits.max_bytes {
            anyhow::bail!("download exceeds {} bytes", limits.max_bytes);
        }
        out.write_all(&buf[..read])
            .context("write downloaded data")?;
    }
}

pub(crate) fn require_https(url: &str) -> Result<()> {
    if !url.starts_with("https://") {
        anyhow::bail!("only https:// URLs are allowed, got {url:?}");
    }
    Ok(())
}

/// Reject asset URLs whose host is not publicly routable.
///
/// This blocks literal metadata, loopback, private, and link-local addresses,
/// plus common internal DNS names. It runs on the initial URL and each
/// redirect. DNS is not resolved here, so rebinding to a private address is
/// not detected.
pub(crate) fn require_public_host(url: &str) -> Result<()> {
    let Some(host) = url_host(url) else {
        anyhow::bail!("URL has no host: {url:?}");
    };
    if is_ssrf_dangerous(host) {
        anyhow::bail!("host {host:?} is not publicly routable");
    }
    Ok(())
}

/// Extract the host component of an `https://` URL, handling userinfo, ports,
/// and bracketed IPv6 literals. Returns the bare host (no brackets, no port).
fn url_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() {
        return None;
    }
    // Parsing normally rejects userinfo, but keep host extraction defensive.
    let authority = authority.rsplit('@').next()?;
    if let Some(stripped) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal: `[::1]` or `[::1]:443`.
        let close = stripped.find(']')?;
        return Some(&stripped[..close]);
    }
    // Bare host, or host:port. The port (if any) follows the last ':'.
    Some(
        authority
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(authority),
    )
}

/// True if `host` is unsafe to fetch from because it cannot be publicly
/// routable (private/loopback/link-local/unspecified) or is a known internal
/// service-discovery name.
fn is_ssrf_dangerous(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return is_ssrf_dangerous_v4(&v4);
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return is_ssrf_dangerous_v6(&v6);
    }
    is_dangerous_dns_name(&host)
}

/// IPv4 ranges that must never be reached by an asset download: unspecified,
/// loopback, broadcast, documentation, RFC1918 private, link-local (which
/// includes the cloud metadata endpoints 169.254.169.254), and multicast.
fn is_ssrf_dangerous_v4(addr: &std::net::Ipv4Addr) -> bool {
    addr.is_unspecified()
        || addr.is_loopback()
        || addr.is_broadcast()
        || addr.is_documentation()
        || addr.is_private()
        || addr.is_link_local()
        || addr.is_multicast()
}

/// IPv6 ranges that must never be reached: loopback (::1), unspecified (::),
/// multicast (ff00::/8), link-local (fe80::/10), and unique-local (fc00::/7).
fn is_ssrf_dangerous_v6(addr: &std::net::Ipv6Addr) -> bool {
    let s = addr.segments();
    addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_multicast()
        || s[0] & 0xffc0 == 0xfe80 // link-local fe80::/10
        || s[0] & 0xfe00 == 0xfc00 // unique-local fc00::/7
}

fn is_dangerous_dns_name(name: &str) -> bool {
    if name.is_empty() || name == "localhost" {
        return true;
    }
    const DANGEROUS_SUFFIXES: &[&str] = &[
        ".localhost",
        ".local",
        ".internal", // RFC 8375 / AWS & cloud internal naming
        ".lan",
        ".home",
        ".home.arpa",
        ".localdomain",
    ];
    DANGEROUS_SUFFIXES
        .iter()
        .any(|suffix| name.ends_with(suffix))
        || name == "metadata"
        || name == "metadata.google.internal"
}

/// Resolve a Location header against the current URL. Absolute URLs are used
/// as-is (and later re-validated as https); host-relative and path-relative
/// locations are resolved manually.
fn resolve_redirect(current: &str, location: &str) -> Result<String> {
    if location.starts_with("https://") || location.starts_with("http://") {
        return Ok(location.to_owned());
    }
    if location.starts_with("//") {
        return Ok(format!("https:{location}"));
    }

    let after_scheme = current
        .strip_prefix("https://")
        .context("current URL is not https")?;
    let (host, path) = match after_scheme.split_once('/') {
        Some((host, rest)) => (host, format!("/{rest}")),
        None => (after_scheme, "/".to_owned()),
    };
    if host.is_empty() {
        anyhow::bail!("cannot resolve redirect against a URL without a host: {current:?}");
    }

    if location.starts_with('/') {
        return Ok(format!("https://{host}{location}"));
    }

    // Path-relative: replace the last path segment.
    let base = match path.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/"),
        None => "/".to_owned(),
    };
    Ok(format!("https://{host}{base}{location}"))
}

pub(crate) struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    pub fn new(limits: &DownloadLimits) -> Self {
        let config = ureq::config::Config::builder()
            // Non-2xx statuses and redirects are handled by the download
            // loop, not by ureq.
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_connect(Some(limits.connect_timeout))
            // Per-hop safety net; the read loop enforces the real deadline.
            .timeout_global(Some(limits.total_deadline))
            .build();
        Self {
            agent: config.new_agent(),
        }
    }
}

impl HttpTransport for UreqTransport {
    fn get(&self, url: &str) -> Result<HttpResponse> {
        let response = self
            .agent
            .get(url)
            .call()
            .with_context(|| format!("request {url}"))?;
        let status = response.status().as_u16();
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let (_, body) = response.into_parts();
        Ok(HttpResponse {
            status,
            location,
            body: Box::new(body.into_with_config().reader()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct FakeTransport {
        responses: RefCell<Vec<(String, HttpResponse)>>,
    }

    impl FakeTransport {
        fn new(responses: Vec<(&str, HttpResponse)>) -> Self {
            Self {
                responses: RefCell::new(
                    responses
                        .into_iter()
                        .rev()
                        .map(|(url, response)| (url.to_owned(), response))
                        .collect(),
                ),
            }
        }
    }

    impl HttpTransport for FakeTransport {
        fn get(&self, url: &str) -> Result<HttpResponse> {
            let (expected, response) = self
                .responses
                .borrow_mut()
                .pop()
                .expect("unexpected extra request");
            assert_eq!(url, expected, "unexpected request order");
            Ok(response)
        }
    }

    fn ok(bytes: &'static [u8]) -> HttpResponse {
        HttpResponse {
            status: 200,
            location: None,
            body: Box::new(bytes),
        }
    }

    fn redirect(to: &str) -> HttpResponse {
        HttpResponse {
            status: 302,
            location: Some(to.to_owned()),
            body: Box::new(&b""[..]),
        }
    }

    fn limits() -> DownloadLimits {
        DownloadLimits {
            max_redirects: 3,
            connect_timeout: Duration::from_secs(1),
            total_deadline: Duration::from_secs(5),
            max_bytes: 16,
            allow_ssrf: false,
        }
    }

    #[test]
    fn downloads_follow_https_redirects() {
        let transport = FakeTransport::new(vec![
            ("https://a.example/x", redirect("https://b.example/y")),
            ("https://b.example/y", ok(b"payload")),
        ]);
        let mut out = Vec::new();
        let written =
            download_https(&transport, "https://a.example/x", &limits(), &mut out).unwrap();
        assert_eq!(written, 7);
        assert_eq!(out, b"payload");
    }

    #[test]
    fn redirect_to_http_is_refused() {
        let transport = FakeTransport::new(vec![(
            "https://a.example/x",
            redirect("http://insecure.example/y"),
        )]);
        let mut out = Vec::new();
        let error = download_https(&transport, "https://a.example/x", &limits(), &mut out)
            .unwrap_err()
            .to_string();
        assert!(error.contains("https"), "{error}");
    }

    #[test]
    fn http_start_url_is_refused_before_any_request() {
        let transport = FakeTransport::new(vec![]);
        let mut out = Vec::new();
        assert!(download_https(&transport, "http://a.example/x", &limits(), &mut out).is_err());
    }

    #[test]
    fn redirect_loops_are_bounded() {
        let hop = |name: &str| format!("https://{name}.example/");
        let transport = FakeTransport::new(vec![
            (&hop("a") as &str, redirect(&hop("b"))),
            (&hop("b"), redirect(&hop("c"))),
            (&hop("c"), redirect(&hop("d"))),
            (&hop("d"), redirect(&hop("e"))),
        ]);
        let mut out = Vec::new();
        let error = download_https(&transport, &hop("a"), &limits(), &mut out)
            .unwrap_err()
            .to_string();
        assert!(error.contains("too many redirects"), "{error}");
    }

    #[test]
    fn byte_cap_is_enforced_while_streaming() {
        let transport =
            FakeTransport::new(vec![("https://a.example/x", ok(b"0123456789abcdef!!"))]);
        let mut out = Vec::new();
        let error = format!(
            "{:#}",
            download_https(&transport, "https://a.example/x", &limits(), &mut out).unwrap_err()
        );
        assert!(error.contains("exceeds"), "{error}");
    }

    #[test]
    fn relative_redirects_resolve_against_the_current_host() {
        assert_eq!(
            resolve_redirect("https://host.example/a/b", "/c").unwrap(),
            "https://host.example/c"
        );
        assert_eq!(
            resolve_redirect("https://host.example/a/b", "c").unwrap(),
            "https://host.example/a/c"
        );
        assert_eq!(
            resolve_redirect("https://host.example/a/b", "//cdn.example/d").unwrap(),
            "https://cdn.example/d"
        );
        assert_eq!(
            resolve_redirect("https://host.example", "c").unwrap(),
            "https://host.example/c"
        );
    }

    #[test]
    fn non_success_statuses_fail() {
        let transport = FakeTransport::new(vec![(
            "https://a.example/x",
            HttpResponse {
                status: 404,
                location: None,
                body: Box::new(&b""[..]),
            },
        )]);
        let mut out = Vec::new();
        let error = download_https(&transport, "https://a.example/x", &limits(), &mut out)
            .unwrap_err()
            .to_string();
        assert!(error.contains("404"), "{error}");
    }

    fn ssrf_limits() -> DownloadLimits {
        let mut l = limits();
        l.allow_ssrf = false;
        l
    }

    #[test]
    fn url_host_extracts_ipv4_ipv6_dns_and_strips_ports() {
        assert_eq!(url_host("https://example.com/x"), Some("example.com"));
        assert_eq!(url_host("https://example.com:8443/x"), Some("example.com"));
        assert_eq!(url_host("https://10.0.0.1/x"), Some("10.0.0.1"));
        assert_eq!(url_host("https://[::1]:443/x"), Some("::1"));
        assert_eq!(url_host("https://[2001:db8::1]/x"), Some("2001:db8::1"));
        assert_eq!(
            url_host("https://user:pw@host.example/x"),
            Some("host.example")
        );
        assert_eq!(url_host("https://host.example"), Some("host.example"));
        assert_eq!(url_host("https:///nohost/x"), None);
    }

    #[test]
    fn ssrf_blocks_cloud_metadata_and_private_ips() {
        let ipv4_blocked = [
            "169.254.169.254", // AWS/GCP/Azure IMDS
            "169.254.170.2",   // ECS task metadata
            "127.0.0.1",
            "0.0.0.0",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "172.31.255.255",
        ];
        let ipv6_blocked = ["::1", "fd00:ec2::254", "fe80::1", "fc00::1"];
        for host in ipv4_blocked {
            assert!(is_ssrf_dangerous(host), "expected {host} to be blocked");
            assert!(
                require_public_host(&format!("https://{host}/x")).is_err(),
                "expected URL for {host} to be rejected"
            );
        }
        for host in ipv6_blocked {
            assert!(is_ssrf_dangerous(host), "expected {host} to be blocked");
            // IPv6 literals must be bracketed in a well-formed URL.
            assert!(
                require_public_host(&format!("https://[{host}]/x")).is_err(),
                "expected bracketed URL for {host} to be rejected"
            );
        }
    }

    #[test]
    fn ssrf_blocks_internal_dns_names() {
        for host in [
            "localhost",
            "localhost.localdomain",
            "metadata",
            "metadata.google.internal",
            "service.local",
            "corp.internal",
            "nas.lan",
            "router.home",
            "gateway.home.arpa",
        ] {
            assert!(is_ssrf_dangerous(host), "expected {host} to be blocked");
        }
    }

    #[test]
    fn ssrf_allows_public_hosts_and_reserved_test_tlds() {
        for host in [
            "example.com",
            "github.com",
            "a.example",
            "sub.domain.example",
            "93.184.216.34",      // example.com's public IP
            "2606:2800:220:1::1", // a global IPv6
            "releases.example.com",
        ] {
            assert!(!is_ssrf_dangerous(host), "expected {host} to be allowed");
        }
    }

    #[test]
    fn download_refuses_ssrf_url_before_any_request() {
        let transport = FakeTransport::new(vec![]);
        let mut out = Vec::new();
        let error = download_https(
            &transport,
            "https://169.254.169.254/latest/meta-data/",
            &ssrf_limits(),
            &mut out,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("SSRF"), "{error}");
    }

    #[test]
    fn ssrf_redirect_to_internal_is_refused() {
        let transport = FakeTransport::new(vec![(
            "https://a.example/x",
            redirect("https://127.0.0.1/y"),
        )]);
        let mut out = Vec::new();
        let error = download_https(&transport, "https://a.example/x", &ssrf_limits(), &mut out)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("SSRF") || error.contains("127.0.0.1"),
            "{error}"
        );
    }

    #[test]
    fn ssrf_protection_can_be_disabled() {
        let transport = FakeTransport::new(vec![
            ("https://a.example/x", redirect("https://127.0.0.1/y")),
            ("https://127.0.0.1/y", ok(b"payload")),
        ]);
        let mut limits = ssrf_limits();
        limits.allow_ssrf = true;
        // The override applies to redirect targets as well as the initial URL.
        let mut out = Vec::new();
        let written = download_https(&transport, "https://a.example/x", &limits, &mut out).unwrap();
        assert_eq!(written, 7);
        assert_eq!(out, b"payload");
    }
}
