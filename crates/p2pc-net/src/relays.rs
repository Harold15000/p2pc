// SPDX-License-Identifier: Apache-2.0

//! The relay-map rules of H2 §10.2-§10.3, and the reachability probe `p2pc-agent doctor` runs on each relay.
//!
//! - [`check_relay_map`] validates a relay list for its [`Role`]:
//!   - **every entry** is an `https` URL with a host and nothing else (no credentials, path, query or fragment: iroh
//!     dials `/relay` on the host whatever the path says). Plain `http` is for a development relay on loopback only.
//!     An IP literal must be a public address, or loopback for a development relay;
//!   - **a node** (the agent, the desktop app's endpoint) needs at least one relay that offers QUIC address discovery,
//!     or the egress gate never opens (H1 §9, R-2): [`NO_ADDRESS_DISCOVERY`]. Only n0's public relays are *known* to
//!     offer it ([`is_n0_relay`]); a plain-HTTP PaaS relay such as ours cannot (no TLS or UDP on the relay), and a
//!     self-hosted relay offers it only with TLS and UDP, which its URL does not say. For a node, every problem is a
//!     warning (H1 configs keep working; the gate stays closed on its own), except an entry iroh cannot use as written;
//!   - **the hub**: iroh picks the home relay from the whole map by latency, and a phone reaches the hub through the
//!     hub's home relay, so **every** relay of the hub's map must be reachable from a browser (an `https` DNS name)
//!     and, when the web app build's relay list is known, allowed by its CSP (§9.5). For the hub these are errors.
//! - [`probe_relays`] measures each relay's reachability and latency through its plain HTTP probe route
//!   ([`RELAY_PROBE_PATH`]) with a [`RelayProber`]: [`HttpProber`] for real, a fake in tests.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::RelayUrl;

use crate::is_public_address;

/// The parent domain of n0's public relays (`use1-1.relay.n0.iroh.link`, …), which offer QUIC address discovery.
pub const N0_RELAY_DOMAIN: &str = "relay.n0.iroh.link";

/// What a node's map without an address-discovery relay means, in the words of H2 §10.3.
pub const NO_ADDRESS_DISCOVERY: &str = "jobs with internet access will not start: no relay offers address discovery";

/// iroh-relay's plain HTTP probe route, served by every relay (and the PaaS health check of `deploy/relay/`).
pub const RELAY_PROBE_PATH: &str = "/ping";

/// How long one relay probe may take, connection and TLS included.
pub const RELAY_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether a relay tells endpoints their public address (QUIC address discovery, which needs TLS and UDP on the relay).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressDiscovery {
    /// One of n0's public relays.
    Offered,
    /// An `https` relay that is not n0's: it offers it only if it runs with TLS and UDP, which its URL does not say.
    Unknown,
    /// A plain `http` relay: no TLS on the relay, so no QUIC address discovery.
    NotOffered,
}

/// Who uses the map.
#[derive(Debug, Clone, Copy)]
pub enum Role<'a> {
    /// The agent, or the desktop app's device endpoint: it needs address discovery (§10.3).
    Node,
    /// The hub: phones reach it through its home relay.
    Hub {
        /// The relay origins the web app build allows in `connect-src` (`https://relay.example.com`, or
        /// `https://*.example.com` for any subdomain), when the caller knows them.
        web_relays: Option<&'a [String]>,
    },
}

/// How bad a problem is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The map breaks the rules for its role.
    Error,
    /// Worth saying; nothing is refused for it.
    Warning,
}

/// One relay of the map, as understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    /// Its URL.
    pub url: RelayUrl,
    /// Whether it offers QUIC address discovery.
    pub address_discovery: AddressDiscovery,
}

/// Something wrong with a relay map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMapProblem {
    /// The entry at `index` cannot be used as written: why.
    InvalidUrl {
        /// Its position in the list.
        index: usize,
        /// Why.
        reason: String,
    },
    /// Plain `http` to a relay that is not on loopback.
    NotHttps {
        /// The relay.
        url: RelayUrl,
    },
    /// An IP literal that is neither public nor loopback.
    HostNotAllowed {
        /// The relay.
        url: RelayUrl,
    },
    /// A node's map has no relay that offers address discovery; `unknown` relays might.
    NoAddressDiscovery {
        /// How many relays may offer it without the URL saying so.
        unknown: usize,
    },
    /// The hub has no relay at all: no phone can reach it.
    NoRelay,
    /// A hub relay a browser cannot use: why.
    NotBrowserReachable {
        /// The relay.
        url: RelayUrl,
        /// Why.
        reason: &'static str,
    },
    /// A hub relay the web app build's CSP does not allow.
    NotAllowedByWebApp {
        /// The relay.
        url: RelayUrl,
    },
}

impl RelayMapProblem {
    /// A stable code, for logs and `p2pc-agent doctor`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidUrl { .. } => "relay_invalid_url",
            Self::NotHttps { .. } => "relay_not_https",
            Self::HostNotAllowed { .. } => "relay_host_not_allowed",
            Self::NoAddressDiscovery { .. } => "relay_no_address_discovery",
            Self::NoRelay => "relay_none",
            Self::NotBrowserReachable { .. } => "relay_not_browser_reachable",
            Self::NotAllowedByWebApp { .. } => "relay_not_allowed_by_web_app",
        }
    }
}

// A `RelayUrl` displays as the parsed URL: the parser percent-encodes control characters and refuses them in hosts, so
// nothing below can put one on the owner's terminal or in the log. `InvalidUrl` never echoes the entry (it may hold
// credentials, or be anything at all).
impl fmt::Display for RelayMapProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl { index, reason } => write!(f, "relay #{}: {reason}", index + 1),
            Self::NotHttps { url } => write!(
                f,
                "{url}: plain http, so the connection to the relay is not encrypted; use https (plain http is for a \
                 development relay on loopback)"
            ),
            Self::HostNotAllowed { url } => write!(
                f,
                "{url}: a private, shared, link-local or special address, which nodes and phones on other networks \
                 cannot reach; use the relay's public DNS name"
            ),
            Self::NoAddressDiscovery { unknown: 0 } => f.write_str(NO_ADDRESS_DISCOVERY),
            Self::NoAddressDiscovery { .. } => write!(
                f,
                "{NO_ADDRESS_DISCOVERY} (n0's public relays offer it; a self-hosted relay offers it only when it runs \
                 with TLS and UDP, which its URL does not say: add n0's relays, or check that the egress gate opens)"
            ),
            Self::NoRelay => f.write_str("no relay: phones reach the hub only through one"),
            Self::NotBrowserReachable { url, reason } => {
                write!(f, "{url}: a phone's browser cannot use this relay ({reason})")
            }
            Self::NotAllowedByWebApp { url } => write!(
                f,
                "{url}: the web app's CSP does not allow this relay, and iroh may pick it as the hub's home relay \
                 (every relay of the hub's map must be one the web app allows)"
            ),
        }
    }
}

/// A problem and how bad it is for the map's role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The problem.
    pub problem: RelayMapProblem,
    /// How bad.
    pub severity: Severity,
}

/// What [`check_relay_map`] found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RelayMapReport {
    /// The usable relays, in the list's order.
    pub relays: Vec<Relay>,
    /// Everything wrong, in the list's order, the map-wide problems last.
    pub findings: Vec<Finding>,
}

impl RelayMapReport {
    /// Whether at least one relay is known to offer address discovery.
    #[must_use]
    pub fn has_address_discovery(&self) -> bool {
        self.relays
            .iter()
            .any(|r| r.address_discovery == AddressDiscovery::Offered)
    }

    /// Whether any finding is an error.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Error)
    }

    /// Logs every finding, as `p2pc-agent run` does at start (§10.3): errors and warnings alike as warnings, since a
    /// node refuses nothing for its map.
    pub fn log(&self) {
        for f in &self.findings {
            tracing::warn!(code = f.problem.code(), "relay map: {}", f.problem);
        }
    }
}

/// A host name as compared: lowercase, without the trailing dot of a fully qualified name.
fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Whether `url` is one of n0's public relays (a host under [`N0_RELAY_DOMAIN`], over `https`).
#[must_use]
pub fn is_n0_relay(url: &RelayUrl) -> bool {
    let Some(url::Host::Domain(host)) = url.host() else {
        return false;
    };
    url.scheme() == "https" && is_strict_subdomain(&normalize_host(host), N0_RELAY_DOMAIN)
}

/// Whether `host` is a subdomain of `domain` (whole labels; not `domain` itself). Both normalized.
fn is_strict_subdomain(host: &str, domain: &str) -> bool {
    host.len() > domain.len() + 1 && host.ends_with(domain) && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

/// Where a relay is, as far as the rules care.
enum Host {
    /// A DNS name; `localhost` and `*.localhost` count as loopback.
    Domain { loopback: bool },
    /// An IP literal.
    Ip(IpAddr),
}

impl Host {
    fn of(url: &RelayUrl) -> Option<Self> {
        Some(match url.host()? {
            url::Host::Domain(d) => {
                let d = normalize_host(d);
                Self::Domain {
                    loopback: d == "localhost" || d.ends_with(".localhost"),
                }
            }
            url::Host::Ipv4(ip) => Self::Ip(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => Self::Ip(IpAddr::V6(ip)),
        })
    }

    fn is_loopback(&self) -> bool {
        match self {
            Self::Domain { loopback } => *loopback,
            Self::Ip(ip) => ip.to_canonical().is_loopback(),
        }
    }
}

/// Parses one config entry into a relay URL iroh uses as written, or says why not (never echoing the entry).
fn parse_entry(entry: &str) -> Result<(RelayUrl, Host), String> {
    let url: RelayUrl = entry.parse().map_err(|_| "not a URL".to_string())?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err("the scheme must be https (or http for a development relay on loopback)".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("credentials in a relay URL are not allowed".into());
    }
    let Some(host) = Host::of(&url) else {
        return Err("a relay URL needs a host".into());
    };
    if url.path() != "/" {
        return Err("a path is not allowed: iroh always dials /relay on the host".into());
    }
    if url.query().is_some() {
        return Err("a query is not allowed in a relay URL".into());
    }
    if url.fragment().is_some() {
        return Err("a fragment is not allowed in a relay URL".into());
    }
    Ok((url, host))
}

/// Whether the web app's relay origins (CSP host sources) allow `url`, whose host is a DNS name.
fn web_app_allows(url: &RelayUrl, allowed: &[String]) -> bool {
    let (Some(url::Host::Domain(host)), Some(port)) = (url.host(), url.port_or_known_default()) else {
        return false;
    };
    let host = normalize_host(host);
    allowed
        .iter()
        .any(|source| source_matches(source, url.scheme(), &host, port))
}

/// CSP host-source matching, as much of it as relay origins need: `scheme://host[:port]`, where the host may start with
/// `*.` (any subdomain, not the domain itself) and a missing port is the scheme's default.
fn source_matches(source: &str, scheme: &str, host: &str, port: u16) -> bool {
    let Some((source_scheme, rest)) = source.trim().split_once("://") else {
        return false;
    };
    if !source_scheme.eq_ignore_ascii_case(scheme) {
        return false;
    }
    let authority = rest.split('/').next().unwrap_or_default();
    let (source_host, source_port) = match authority.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(p) => (h, p),
            Err(_) => return false,
        },
        None => match scheme {
            "https" => (authority, 443),
            "http" => (authority, 80),
            _ => return false,
        },
    };
    if source_port != port {
        return false;
    }
    let source_host = normalize_host(source_host);
    match source_host.strip_prefix("*.") {
        Some(domain) => is_strict_subdomain(host, domain),
        None => source_host == host,
    }
}

/// Validates `relays` (as written in a config) for `role`. See the module docs for the rules.
#[must_use]
pub fn check_relay_map(relays: &[String], role: Role<'_>) -> RelayMapReport {
    let hub = matches!(role, Role::Hub { .. });
    // A node keeps the relays it has (H1 configs keep working): its problems are warnings.
    let severity = if hub { Severity::Error } else { Severity::Warning };
    let mut report = RelayMapReport::default();
    for (index, entry) in relays.iter().enumerate() {
        let (url, host) = match parse_entry(entry) {
            Ok(parsed) => parsed,
            Err(reason) => {
                report.findings.push(Finding {
                    problem: RelayMapProblem::InvalidUrl { index, reason },
                    severity: Severity::Error,
                });
                continue;
            }
        };
        let https = url.scheme() == "https";
        let loopback = host.is_loopback();
        let problem = match (&role, &host) {
            (Role::Hub { .. }, _) if !https => Some(RelayMapProblem::NotBrowserReachable {
                url: url.clone(),
                reason: "a browser needs https",
            }),
            (Role::Hub { .. }, _) if loopback => Some(RelayMapProblem::NotBrowserReachable {
                url: url.clone(),
                reason: "a loopback relay: a phone cannot reach it",
            }),
            (_, Host::Ip(ip)) if !loopback && !is_public_address(*ip) => {
                Some(RelayMapProblem::HostNotAllowed { url: url.clone() })
            }
            (Role::Hub { .. }, Host::Ip(_)) => Some(RelayMapProblem::NotBrowserReachable {
                url: url.clone(),
                reason: "an IP address: a browser needs the relay's DNS name, with its certificate",
            }),
            (
                Role::Hub {
                    web_relays: Some(allowed),
                },
                Host::Domain { .. },
            ) if !web_app_allows(&url, allowed) => Some(RelayMapProblem::NotAllowedByWebApp { url: url.clone() }),
            (Role::Node, _) if !https && !loopback => Some(RelayMapProblem::NotHttps { url: url.clone() }),
            _ => None,
        };
        if let Some(problem) = problem {
            report.findings.push(Finding { problem, severity });
        }
        let address_discovery = if !https {
            AddressDiscovery::NotOffered
        } else if is_n0_relay(&url) {
            AddressDiscovery::Offered
        } else {
            AddressDiscovery::Unknown
        };
        report.relays.push(Relay { url, address_discovery });
    }
    match role {
        Role::Node if !report.has_address_discovery() => {
            let unknown = report
                .relays
                .iter()
                .filter(|r| r.address_discovery == AddressDiscovery::Unknown)
                .count();
            report.findings.push(Finding {
                problem: RelayMapProblem::NoAddressDiscovery { unknown },
                severity: Severity::Warning,
            });
        }
        Role::Hub { .. } if report.relays.is_empty() => report.findings.push(Finding {
            problem: RelayMapProblem::NoRelay,
            severity: Severity::Error,
        }),
        _ => {}
    }
    report
}

/// How a relay answered its probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reachability {
    /// It answered the probe route with a success, after this long.
    Reachable(Duration),
    /// It did not: why.
    Unreachable(String),
    /// No answer within the timeout.
    TimedOut(Duration),
}

/// Probes one relay. [`HttpProber`] for real; tests use a fake.
pub trait RelayProber: Send + Sync + 'static {
    /// Probes `url` once: the latency of a success, or why it failed.
    fn probe(&self, url: &RelayUrl) -> impl Future<Output = Result<Duration, String>> + Send;
}

/// Probes every relay at once, each within `timeout`, and returns the results in `relays`' order.
pub async fn probe_relays<P: RelayProber>(
    prober: Arc<P>,
    relays: &[RelayUrl],
    timeout: Duration,
) -> Vec<(RelayUrl, Reachability)> {
    let mut probes = tokio::task::JoinSet::new();
    for (index, url) in relays.iter().cloned().enumerate() {
        let prober = Arc::clone(&prober);
        probes.spawn(async move {
            let reach = match tokio::time::timeout(timeout, prober.probe(&url)).await {
                Ok(Ok(latency)) => Reachability::Reachable(latency),
                Ok(Err(why)) => Reachability::Unreachable(why),
                Err(_) => Reachability::TimedOut(timeout),
            };
            (index, reach)
        });
    }
    let mut results: Vec<Option<Reachability>> = vec![None; relays.len()];
    while let Some(done) = probes.join_next().await {
        // A probe that panicked leaves its slot empty: it is reported as a failure below.
        if let Ok((index, reach)) = done {
            results[index] = Some(reach);
        }
    }
    relays
        .iter()
        .cloned()
        .zip(results)
        .map(|(url, reach)| {
            (
                url,
                reach.unwrap_or_else(|| Reachability::Unreachable("the probe failed".into())),
            )
        })
        .collect()
}

/// The real prober: `GET <relay>/ping` over HTTPS (or HTTP for a development relay), trusting the same web PKI roots
/// iroh trusts for relays, following no redirect and using no proxy, as iroh's own relay connection does. The latency
/// is that of a fresh connection, DNS, TCP and TLS included, up to the response's headers; the body is never read.
#[derive(Debug, Clone)]
pub struct HttpProber {
    client: reqwest::Client,
}

impl HttpProber {
    /// A prober whose every request gives up after `timeout`.
    ///
    /// # Errors
    ///
    /// When the TLS configuration or the HTTP client cannot be built.
    pub fn new(timeout: Duration) -> Result<Self, String> {
        let tls = iroh::tls::CaTlsConfig::default()
            .client_config(iroh::tls::default_provider())
            .map_err(|e| format!("cannot build the TLS configuration: {e}"))?;
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
            .map_err(|e| format!("cannot build the HTTP client: {e}"))?;
        Ok(Self { client })
    }
}

impl RelayProber for HttpProber {
    async fn probe(&self, url: &RelayUrl) -> Result<Duration, String> {
        let target = url
            .join(RELAY_PROBE_PATH)
            .map_err(|e| format!("cannot build the probe URL: {e}"))?;
        let start = Instant::now();
        let response = self.client.get(target).send().await.map_err(|e| error_chain(&e))?;
        let latency = start.elapsed();
        let status = response.status();
        if status.is_success() {
            Ok(latency)
        } else {
            Err(format!("HTTP {status}"))
        }
    }
}

/// An error and its sources, `: `-separated: reqwest's own message rarely says what failed.
fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        let text = s.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = s.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const N0: &str = "https://use1-1.relay.n0.iroh.link./";
    const N0_EU: &str = "https://euc1-1.relay.n0.iroh.link./";
    const OURS: &str = "https://relay.example.com/";

    fn list(urls: &[&str]) -> Vec<String> {
        urls.iter().map(|u| (*u).to_string()).collect()
    }

    fn url(s: &str) -> RelayUrl {
        s.parse().unwrap()
    }

    fn problems(report: &RelayMapReport) -> Vec<RelayMapProblem> {
        report.findings.iter().map(|f| f.problem.clone()).collect()
    }

    #[test]
    fn n0_relays_are_the_hosts_under_n0_s_relay_domain_over_https() {
        assert!(is_n0_relay(&url(N0)));
        assert!(is_n0_relay(&url("https://aps1-1.relay.n0.iroh.link")));
        assert!(is_n0_relay(&url("https://USW1-1.Relay.N0.Iroh.Link/")));
        // Whole labels only, and never the domain itself or a look-alike.
        for other in [
            "https://relay.n0.iroh.link/",
            "https://evilrelay.n0.iroh.link/",
            "https://use1-1.relay.n0.iroh.link.example.com/",
            "https://use1-1.staging-relay.n0.iroh.link/",
            "http://use1-1.relay.n0.iroh.link/",
            OURS,
        ] {
            assert!(!is_n0_relay(&url(other)), "{other}");
        }
        // iroh's own default map is n0's: the rule recognises every one of its relays.
        for u in iroh::RelayMode::Default.relay_map().urls::<Vec<_>>() {
            assert!(is_n0_relay(&u), "{u}");
        }
    }

    /// §10.3: the official map, n0's relays plus our HTTP relay, gives a node address discovery through n0.
    #[test]
    fn the_mixed_map_of_n0_and_our_http_relay_is_valid_for_a_node() {
        let report = check_relay_map(&list(&[N0, N0_EU, OURS]), Role::Node);
        assert_eq!(report.findings, vec![], "{report:?}");
        assert!(report.has_address_discovery());
        assert_eq!(
            report.relays.iter().map(|r| r.address_discovery).collect::<Vec<_>>(),
            [
                AddressDiscovery::Offered,
                AddressDiscovery::Offered,
                AddressDiscovery::Unknown
            ]
        );
        assert_eq!(report.relays[2].url, url(OURS));
    }

    /// §10.3: a node whose map is our HTTP relay only (the hub's map, handed down by a join token) never opens the
    /// egress gate, and says so in the spec's words.
    #[test]
    fn a_node_without_an_address_discovery_relay_is_warned() {
        let report = check_relay_map(&list(&[OURS]), Role::Node);
        assert!(!report.has_address_discovery());
        assert!(!report.has_errors(), "a warning, not an error: {report:?}");
        assert_eq!(problems(&report), [RelayMapProblem::NoAddressDiscovery { unknown: 1 }]);
        let text = report.findings[0].problem.to_string();
        assert!(text.starts_with(NO_ADDRESS_DISCOVERY), "{text}");
        assert!(text.contains("TLS and UDP"), "the hint for a self-hosted relay: {text}");
        assert_eq!(report.findings[0].problem.code(), "relay_no_address_discovery");
        assert_eq!(report.findings[0].severity, Severity::Warning);
        // No relay at all, or only development relays: no hint about self-hosted ones, just the spec's sentence.
        for map in [list(&[]), list(&["http://localhost:3340/"])] {
            let report = check_relay_map(&map, Role::Node);
            assert_eq!(
                problems(&report),
                [RelayMapProblem::NoAddressDiscovery { unknown: 0 }],
                "{map:?}"
            );
            assert_eq!(report.findings[0].problem.to_string(), NO_ADDRESS_DISCOVERY);
        }
    }

    /// Allowed schemes: `https`, and plain `http` only for a development relay on loopback.
    #[test]
    fn only_https_is_allowed_except_for_a_loopback_development_relay() {
        for dev in [
            "http://localhost:3340/",
            "http://127.0.0.1:3340/",
            "http://[::1]:3340/",
            "https://localhost/",
        ] {
            let report = check_relay_map(&list(&[N0, dev]), Role::Node);
            assert_eq!(report.findings, vec![], "{dev}: {report:?}");
            assert_eq!(report.relays.len(), 2, "{dev}");
        }
        assert_eq!(
            check_relay_map(&list(&["http://localhost:3340/"]), Role::Node).relays[0].address_discovery,
            AddressDiscovery::NotOffered
        );
        let report = check_relay_map(&list(&[N0, "http://relay.example.com/"]), Role::Node);
        assert_eq!(
            problems(&report),
            [RelayMapProblem::NotHttps {
                url: url("http://relay.example.com/")
            }]
        );
        assert_eq!(
            report.findings[0].severity,
            Severity::Warning,
            "a node keeps its H1 config"
        );
        assert_eq!(report.findings[0].problem.code(), "relay_not_https");
        // A plain `http` relay is still used: it is listed, without address discovery.
        assert_eq!(report.relays[1].address_discovery, AddressDiscovery::NotOffered);
    }

    /// What iroh cannot use as written is refused, for every role: other schemes, credentials, a path (iroh dials
    /// `/relay` whatever it says), a query, a fragment, no host, or not a URL at all.
    #[test]
    fn entries_iroh_cannot_use_as_written_are_errors() {
        for (bad, why) in [
            ("ftp://relay.example.com/", "scheme"),
            ("wss://relay.example.com/", "scheme"),
            ("https://user:pw@relay.example.com/", "credentials"), // gitleaks:allow
            ("https://relay.example.com/sub/", "path"),
            ("https://relay.example.com/?token=x", "query"),
            ("https://relay.example.com/#x", "fragment"),
            ("not a url", "URL"),
        ] {
            for role in [Role::Node, Role::Hub { web_relays: None }] {
                let report = check_relay_map(&list(&[N0, bad]), role);
                let [
                    Finding {
                        problem: RelayMapProblem::InvalidUrl { index: 1, reason },
                        severity: Severity::Error,
                    },
                ] = report.findings.as_slice()
                else {
                    panic!("{bad}: {report:?}");
                };
                assert!(reason.contains(why), "{bad}: {reason}");
                assert!(!reason.contains("pw@"), "never echo credentials: {reason}");
                assert_eq!(report.relays.len(), 1, "{bad} is not used");
                assert_eq!(report.findings[0].problem.code(), "relay_invalid_url");
            }
        }
    }

    /// Allowed hosts: a DNS name, a public IP, or loopback for a development relay. A private, CGNAT, link-local,
    /// unique-local, multicast or unspecified IP is not a relay phones or remote nodes can reach.
    #[test]
    fn ip_literals_must_be_public_or_loopback() {
        for ok in ["https://192.0.2.10/", "https://[2001:db8::10]/", "https://127.0.0.1/"] {
            let report = check_relay_map(&list(&[N0, ok]), Role::Node);
            assert_eq!(report.findings, vec![], "{ok}: {report:?}");
        }
        for bad in [
            "https://10.0.0.1/",
            "https://192.168.1.20/",
            "https://100.64.0.1/",
            "https://169.254.1.1/",
            "https://[fd00::1]/",
            "https://[fe80::1]/",
            "https://0.0.0.0/",
            "https://224.0.0.1/",
            "https://[::ffff:10.0.0.1]/",
        ] {
            let report = check_relay_map(&list(&[N0, bad]), Role::Node);
            assert_eq!(
                problems(&report),
                [RelayMapProblem::HostNotAllowed { url: url(bad) }],
                "{bad}"
            );
            assert_eq!(report.findings[0].severity, Severity::Warning);
            assert_eq!(report.findings[0].problem.code(), "relay_host_not_allowed");
        }
    }

    /// §10.3: the hub's map is our HTTP relay only in the official deployment, and n0's in the beta; both are
    /// reachable from a browser and allowed by the official web app's CSP.
    #[test]
    fn the_official_and_beta_hub_maps_are_valid() {
        let official = ["https://relay.example.com".to_string()];
        let report = check_relay_map(
            &list(&[OURS]),
            Role::Hub {
                web_relays: Some(&official),
            },
        );
        assert_eq!(report.findings, vec![], "{report:?}");
        // The hub does not need address discovery: no warning about it.
        let beta = ["https://*.relay.n0.iroh.link".to_string()];
        let report = check_relay_map(
            &list(&[N0, N0_EU]),
            Role::Hub {
                web_relays: Some(&beta),
            },
        );
        assert_eq!(report.findings, vec![], "{report:?}");
        // Without the web app's list, only what a browser needs is checked.
        let report = check_relay_map(&list(&[OURS, N0]), Role::Hub { web_relays: None });
        assert_eq!(report.findings, vec![], "{report:?}");
    }

    /// iroh picks the hub's home relay from its whole map by latency, so every relay of the map must be one a phone can
    /// use: a relay the web app's CSP does not allow is an error even next to one it allows.
    #[test]
    fn every_hub_relay_must_be_allowed_by_the_web_app() {
        let official = ["https://relay.example.com".to_string()];
        let report = check_relay_map(
            &list(&[OURS, N0]),
            Role::Hub {
                web_relays: Some(&official),
            },
        );
        assert_eq!(
            problems(&report),
            [RelayMapProblem::NotAllowedByWebApp { url: url(N0) }]
        );
        assert!(report.has_errors());
        assert_eq!(report.findings[0].problem.code(), "relay_not_allowed_by_web_app");
        assert!(report.findings[0].problem.to_string().contains("CSP"), "{report:?}");
    }

    /// CSP host-source matching: whole labels, `*.` for subdomains only (not the apex), the default port unless one is
    /// named, the trailing dot of a fully qualified name ignored, case-insensitive.
    #[test]
    fn web_app_relay_origins_match_like_csp_host_sources() {
        let check = |relay: &str, allowed: &[&str]| {
            let allowed: Vec<String> = allowed.iter().map(|s| (*s).to_string()).collect();
            !check_relay_map(
                &list(&[relay]),
                Role::Hub {
                    web_relays: Some(&allowed),
                },
            )
            .has_errors()
        };
        assert!(check("https://relay.example.com/", &["https://relay.example.com"]));
        assert!(check("https://Relay.Example.COM./", &["https://relay.example.com"]));
        assert!(check("https://relay.example.com/", &["https://relay.example.com:443"]));
        assert!(check(
            "https://relay.example.com:8443/",
            &["https://relay.example.com:8443"]
        ));
        assert!(check(N0, &["https://*.relay.n0.iroh.link"]));
        assert!(check(N0, &["https://relay.example.com", "https://*.n0.iroh.link"]));
        assert!(!check(
            "https://relay.example.com:8443/",
            &["https://relay.example.com"]
        ));
        assert!(!check("https://evilrelay.example.com/", &["https://relay.example.com"]));
        assert!(!check(
            "https://relay.example.com.evil.example/",
            &["https://relay.example.com"]
        ));
        assert!(!check("https://relay.n0.iroh.link/", &["https://*.relay.n0.iroh.link"]));
        assert!(!check("https://relay.example.com/", &["http://relay.example.com"]));
        assert!(!check("https://relay.example.com/", &[]));
    }

    /// A browser opens `wss://` to the relay's DNS name: no plain `http`, no loopback, no IP literal.
    #[test]
    fn hub_relays_must_be_reachable_from_a_browser() {
        for (bad, why) in [
            ("http://localhost:3340/", "https"),
            ("https://localhost/", "loopback"),
            ("https://127.0.0.1/", "loopback"),
            ("https://192.0.2.10/", "DNS name"),
        ] {
            let report = check_relay_map(&list(&[OURS, bad]), Role::Hub { web_relays: None });
            let [
                Finding {
                    problem: RelayMapProblem::NotBrowserReachable { url: u, reason },
                    severity: Severity::Error,
                },
            ] = report.findings.as_slice()
            else {
                panic!("{bad}: {report:?}");
            };
            assert_eq!(*u, url(bad));
            assert!(reason.contains(why), "{bad}: {reason}");
        }
        // Plain http to a remote host and non-public IPs are errors for the hub.
        for bad in ["http://relay.example.com/", "https://10.0.0.1/"] {
            let report = check_relay_map(&list(&[OURS, bad]), Role::Hub { web_relays: None });
            assert!(report.has_errors(), "{bad}: {report:?}");
            assert!(
                report.findings.iter().all(|f| f.severity == Severity::Error),
                "{bad}: {report:?}"
            );
        }
        let report = check_relay_map(&[], Role::Hub { web_relays: None });
        assert_eq!(problems(&report), [RelayMapProblem::NoRelay]);
        assert!(report.has_errors());
        assert_eq!(report.findings[0].problem.code(), "relay_none");
    }

    /// A relay URL from a config file is printed by doctor and logged: no control character of it reaches either.
    #[test]
    fn problem_texts_carry_no_control_characters() {
        let report = check_relay_map(&list(&["https://relay.example.com/\u{1b}[2J"]), Role::Node);
        for f in &report.findings {
            let text = f.problem.to_string();
            assert!(!text.chars().any(char::is_control), "{text:?}");
        }
    }

    struct FakeProber;

    impl RelayProber for FakeProber {
        async fn probe(&self, url: &RelayUrl) -> Result<Duration, String> {
            match url.host_str() {
                Some("fast.example.com") => Ok(Duration::from_millis(40)),
                Some("slow.example.com") => Ok(Duration::from_millis(81)),
                Some("hang.example.com") => std::future::pending().await,
                _ => Err("connection refused".into()),
            }
        }
    }

    /// Every relay is probed, in parallel, within the timeout; results come back in the map's order.
    #[tokio::test(start_paused = true)]
    async fn probes_report_latency_failure_and_timeout_in_order() {
        let relays = [
            url("https://slow.example.com/"),
            url("https://hang.example.com/"),
            url("https://down.example.com/"),
            url("https://fast.example.com/"),
        ];
        let out = probe_relays(Arc::new(FakeProber), &relays, RELAY_PROBE_TIMEOUT).await;
        assert_eq!(
            out,
            vec![
                (relays[0].clone(), Reachability::Reachable(Duration::from_millis(81))),
                (relays[1].clone(), Reachability::TimedOut(RELAY_PROBE_TIMEOUT)),
                (
                    relays[2].clone(),
                    Reachability::Unreachable("connection refused".into())
                ),
                (relays[3].clone(), Reachability::Reachable(Duration::from_millis(40))),
            ]
        );
        assert!(
            probe_relays(Arc::new(FakeProber), &[], RELAY_PROBE_TIMEOUT)
                .await
                .is_empty()
        );
    }

    /// The real prober builds (TLS roots and client) without touching the network.
    #[test]
    fn the_http_prober_builds() {
        HttpProber::new(RELAY_PROBE_TIMEOUT).unwrap();
    }

    /// The real prober against a local HTTP server: `GET /ping` with a success is reachable, anything else is not, a
    /// redirect is not followed. Loopback only, no relay.
    #[tokio::test]
    async fn the_http_prober_gets_the_probe_route_and_follows_no_redirect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let mut paths = Vec::new();
            for answer in [
                "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:9/ping\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            ] {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = sock.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    got.extend_from_slice(&buf[..n]);
                }
                let line = String::from_utf8_lossy(&got).lines().next().unwrap().to_string();
                paths.push(line);
                sock.write_all(answer.as_bytes()).await.unwrap();
                sock.shutdown().await.unwrap();
            }
            paths
        });
        let prober = HttpProber::new(RELAY_PROBE_TIMEOUT).unwrap();
        let relay = url(&format!("http://127.0.0.1:{port}/"));
        assert!(prober.probe(&relay).await.is_ok());
        let err = prober.probe(&relay).await.unwrap_err();
        assert!(err.contains("503"), "{err}");
        let err = prober.probe(&relay).await.unwrap_err();
        assert!(err.contains("302"), "{err}");
        let paths = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(paths, vec!["GET /ping HTTP/1.1"; 3]);
    }
}
