//! Obtains domain name expiration info via RDAP (or Ethereum for ENS names),
//! and TLS certificate expiration info.
//!
//! Used internally by the knock-knock CLI tool, not (yet) meant to be a stable public API.

use chrono::{DateTime, Utc};
use icann_rdap_client::http::Client;
use icann_rdap_client::iana::{BootstrapStore, fetch_bootstrap};
use icann_rdap_client::prelude::{
    ClientConfig, MemoryBootstrapStore, QueryType, RdapClientError, create_client, rdap_request,
};
use icann_rdap_client::rdap::ResponseData;
use icann_rdap_common::iana::IanaRegistryType;
use icann_rdap_common::response::{Domain, ObjectCommonFields, RdapResponse};
use std::error::Error;
use std::fmt;
use std::time::Duration;

pub mod ens;
pub mod keccak;
pub mod tls;
pub mod utils;
pub mod x509;

use utils::{InputParts, is_valid_ascii_domain_name, split_input};

pub const GEMINI_PORT: u16 = 1965;
pub const HTTPS_PORT: u16 = 443;
pub const MAX_ATTEMPTS: u32 = 3;
pub const TIMEOUT_SECS: u64 = 30;
pub(crate) const RETRY_DELAY: Duration = Duration::from_millis(500);

#[derive(Debug, Eq, PartialEq)]
pub enum KnockKnockError {
    /// Server responded with an unexpected HTTP status code (not in RDAP format)
    BadServerResponse(u16),
    /// IANA's list of RDAP servers could not be obtained
    BootstrapUnavailable(String),
    /// Any other problem reported by the RDAP client library
    ClientProblem(String),
    /// Server presented a certificate that could not be parsed
    CouldntParseCertificate,
    /// Server responded with data that could not be parsed
    CouldntParseData,
    /// Ethereum JSON-RPC endpoint responded with an error
    EthRpcError(String),
    /// Ethereum JSON-RPC endpoint responded with unexpected HTTP status code
    EthRpcHttpStatus(u16),
    /// Ethereum JSON-RPC endpoint could not be reached
    EthRpcUnreachable(String),
    /// Provided input doesn't look like a domain name
    InvalidDomainName,
    /// Request did not go through (no connection, timeout, DNS failure, etc)
    NetworkRequestGlitch(String),
    /// Server did not present any certificate
    NoCertificatePresented,
    /// IANA's bootstrap file has no RDAP server listed for this TLD
    NoRdapServerForTld,
    /// Server responded with an RDAP error message (other than "not found")
    RdapError(u16),
    /// TLS connection could not be established (no connection, timeout, handshake failure, etc)
    TlsConnectionFailed(String),
    /// TLS client could not be set up
    TlsSetupProblem(String),
}

impl KnockKnockError {
    /// Whether it makes sense to try sending the same request again
    pub fn is_transient(&self) -> bool {
        match self {
            KnockKnockError::BootstrapUnavailable(_)
            | KnockKnockError::EthRpcUnreachable(_)
            | KnockKnockError::NetworkRequestGlitch(_)
            | KnockKnockError::TlsConnectionFailed(_) => true,
            KnockKnockError::BadServerResponse(status)
            | KnockKnockError::EthRpcHttpStatus(status)
            | KnockKnockError::RdapError(status) => *status == 429 || *status >= 500,
            KnockKnockError::ClientProblem(_)
            | KnockKnockError::CouldntParseCertificate
            | KnockKnockError::CouldntParseData
            | KnockKnockError::EthRpcError(_)
            | KnockKnockError::InvalidDomainName
            | KnockKnockError::NoCertificatePresented
            | KnockKnockError::NoRdapServerForTld
            | KnockKnockError::TlsSetupProblem(_) => false,
        }
    }
}

impl fmt::Display for KnockKnockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KnockKnockError::BadServerResponse(status) => {
                write!(f, "RDAP server responded with HTTP status {}", status)
            }
            KnockKnockError::BootstrapUnavailable(details) => {
                write!(
                    f,
                    "Unable to obtain list of RDAP servers from IANA ({})",
                    details
                )
            }
            KnockKnockError::ClientProblem(message) => write!(f, "{}", message),
            KnockKnockError::CouldntParseCertificate => {
                write!(f, "Unable to parse certificate presented by server")
            }
            KnockKnockError::CouldntParseData => {
                write!(f, "Unable to parse data returned by RDAP server")
            }
            KnockKnockError::EthRpcError(message) => {
                write!(
                    f,
                    "Ethereum RPC endpoint responded with error ({})",
                    message
                )
            }
            KnockKnockError::EthRpcHttpStatus(status) => {
                write!(
                    f,
                    "Ethereum RPC endpoint responded with HTTP status {}",
                    status
                )
            }
            KnockKnockError::EthRpcUnreachable(details) => {
                write!(f, "Unable to reach Ethereum RPC endpoint ({})", details)
            }
            KnockKnockError::InvalidDomainName => write!(f, "Invalid domain name"),
            KnockKnockError::NetworkRequestGlitch(details) => {
                write!(f, "Unable to reach RDAP server ({})", details)
            }
            KnockKnockError::NoCertificatePresented => {
                write!(f, "Server did not present a certificate")
            }
            KnockKnockError::NoRdapServerForTld => {
                write!(f, "No RDAP server is known for this top-level domain")
            }
            KnockKnockError::RdapError(code) => {
                write!(f, "RDAP server responded with error code {}", code)
            }
            KnockKnockError::TlsConnectionFailed(details) => {
                write!(f, "Unable to establish TLS connection ({})", details)
            }
            KnockKnockError::TlsSetupProblem(details) => {
                write!(f, "Unable to set up TLS client ({})", details)
            }
        }
    }
}

impl Error for KnockKnockError {}

/// What to check, derived from user input
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    /// Lowercase ASCII host name, e.g. "www.xn--bcher-kva.de"
    pub host: String,
    /// Registrable domain name of the host, e.g. "xn--bcher-kva.de" (or "vitalik.eth" for ENS names)
    pub domain: String,
    /// Lowercase scheme, if given (e.g. "https")
    pub scheme: Option<String>,
    /// Port number, if given
    pub port: Option<u16>,
}

impl Target {
    /// Turns user input (e.g. "https://www.Bücher.de/") into a target
    pub fn parse(input: &str) -> Result<Target, KnockKnockError> {
        let InputParts { scheme, host, port } =
            split_input(input).ok_or(KnockKnockError::InvalidDomainName)?;
        let host: String =
            idna::domain_to_ascii(host).map_err(|_| KnockKnockError::InvalidDomainName)?;

        if !is_valid_ascii_domain_name(&host) {
            return Err(KnockKnockError::InvalidDomainName);
        }

        let domain: String = if ens::is_ens_name(&host) {
            ens::registrable_ens_name(&host).ok_or(KnockKnockError::InvalidDomainName)?
        } else {
            registrable_domain_name(&host)
        };

        Ok(Target {
            host,
            domain,
            scheme,
            port,
        })
    }

    /// Whether this is an ENS (.eth) name, rather than a DNS domain name
    pub fn is_ens(&self) -> bool {
        ens::is_ens_name(&self.host)
    }

    /// Whether this is a Gemini (or Titan) target, where self-signed certificates
    /// are the norm (trust on first use) rather than a problem
    pub fn is_gemini(&self) -> bool {
        matches!(self.scheme.as_deref(), Some("gemini") | Some("titan"))
    }

    /// Port to check TLS certificate on, None if it can't be checked for given scheme
    pub fn tls_port(&self) -> Option<u16> {
        // ENS names don't resolve via DNS (without a gateway), so there's no server to connect to
        if self.is_ens() {
            return None;
        }

        match self.scheme.as_deref() {
            None | Some("https") | Some("wss") => Some(self.port.unwrap_or(HTTPS_PORT)),
            // Plain HTTP port is of no use, the same host's HTTPS one is what matters
            Some("http") | Some("ws") => Some(HTTPS_PORT),
            // Gemini (and Titan, its upload companion) always use TLS
            Some("gemini") | Some("titan") => Some(self.port.unwrap_or(GEMINI_PORT)),
            Some(_) => None,
        }
    }
}

/// Finds registrable domain name for given host using the Public Suffix List,
/// e.g. "www.example.co.uk" -> "example.co.uk"
/// (only ICANN suffixes count, since registries don't know about private ones like "github.io")
pub fn registrable_domain_name(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();

    for i in 1..labels.len() {
        let tail: String = labels[i..].join(".");

        if let Some(suffix) = psl::suffix(tail.as_bytes())
            && suffix.typ() == Some(psl::Type::Icann)
            && suffix.as_bytes() == tail.as_bytes()
        {
            return labels[i - 1..].join(".");
        }
    }

    host.to_string()
}

/// Makes Punycode-encoded domain names readable, e.g. "bücher.de (xn--bcher-kva.de)"
pub fn display_domain_name(domain_name: &str) -> String {
    let (unicode, result) = idna::domain_to_unicode(domain_name);

    if result.is_ok() && unicode != domain_name {
        format!("{} ({})", unicode, domain_name)
    } else {
        domain_name.to_string()
    }
}

/// Turns error and all its sources into one line, e.g.
/// "error sending request: client error (Connect): dns error: failed to lookup address"
pub fn error_chain(error: &dyn Error) -> String {
    let mut messages: Vec<String> = vec![error.to_string()];
    let mut source: Option<&dyn Error> = error.source();

    while let Some(error) = source {
        let message: String = error.to_string();

        // Wrapper errors often repeat the message of the error they wrap
        if !messages.iter().any(|m| m.contains(&message)) {
            messages.push(message);
        }

        source = error.source();
    }

    messages.join(": ")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Registration {
    /// Domain name is registered (expiration date is missing if registry didn't provide it)
    Registered {
        expires: Option<DateTime<Utc>>,
        /// Until when (expired) name can still be renewed by its owner, if known
        grace_period_ends: Option<DateTime<Utc>>,
    },
    NotRegistered,
}

/// Finds expiration date among domain name's events
fn expiration_date(domain: &Domain) -> Option<DateTime<Utc>> {
    domain
        .events()
        .iter()
        .filter(|event| {
            event
                .event_action()
                .is_some_and(|action| action.eq_ignore_ascii_case("expiration"))
        })
        .find_map(|event| DateTime::parse_from_rfc3339(event.event_date()?).ok())
        .map(|date| date.with_timezone(&Utc))
}

/// Sorts out which responses mean "this domain name is not registered"
/// (HTTP 404, as per RFC 7480 section 5.3) and which ones are errors
fn classify_response(response: ResponseData) -> Result<Registration, KnockKnockError> {
    let status: u16 = response.http_data.status_code();

    match response.rdap {
        RdapResponse::Domain(domain) => Ok(Registration::Registered {
            expires: expiration_date(&domain),
            grace_period_ends: None,
        }),
        RdapResponse::ErrorResponse(error) => {
            let code: u16 = match error.error_code() {
                0 => status,
                code => code,
            };

            if code == 404 || status == 404 {
                Ok(Registration::NotRegistered)
            } else {
                Err(KnockKnockError::RdapError(code))
            }
        }
        // Valid RDAP, but not a domain object
        _ => match status {
            404 => Ok(Registration::NotRegistered),
            200 => Err(KnockKnockError::CouldntParseData),
            status => Err(KnockKnockError::BadServerResponse(status)),
        },
    }
}

fn classify_client_error(error: RdapClientError) -> Result<Registration, KnockKnockError> {
    match error {
        RdapClientError::Client(error) => {
            Err(KnockKnockError::NetworkRequestGlitch(error_chain(&error)))
        }
        RdapClientError::IoError(error) => {
            Err(KnockKnockError::NetworkRequestGlitch(error_chain(&error)))
        }
        // Response body is not JSON (e.g. empty, or an HTML error page)
        RdapClientError::ParsingError(info) => match info.http_data.status_code() {
            404 => Ok(Registration::NotRegistered),
            200 => Err(KnockKnockError::CouldntParseData),
            status => Err(KnockKnockError::BadServerResponse(status)),
        },
        RdapClientError::Response(_) | RdapClientError::Json(_) => {
            Err(KnockKnockError::CouldntParseData)
        }
        RdapClientError::InvalidQueryValue
        | RdapClientError::AmbiguousQueryType
        | RdapClientError::DomainNameError(_) => Err(KnockKnockError::InvalidDomainName),
        RdapClientError::BootstrapUnavailable => Err(KnockKnockError::NoRdapServerForTld),
        other => Err(KnockKnockError::ClientProblem(error_chain(&other))),
    }
}

/// Looks up domain name registration info via RDAP
pub struct RdapChecker {
    client: Client,
    store: MemoryBootstrapStore,
}

impl RdapChecker {
    /// Creates RDAP client and obtains IANA's list of RDAP servers for TLDs
    pub async fn new() -> Result<RdapChecker, KnockKnockError> {
        let config: ClientConfig = ClientConfig::builder()
            .user_agent_suffix(format!(
                "{}/{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            ))
            // A few registries only list plain HTTP RDAP servers
            .https_only(false)
            .timeout_secs(TIMEOUT_SECS)
            // Don't wait for too long when servers say "too many requests"
            .def_retry_secs(2_u32)
            .max_retry_secs(10_u32)
            .build();

        let client: Client = create_client(&config)
            .map_err(|error| KnockKnockError::ClientProblem(error_chain(&error)))?;
        let store: MemoryBootstrapStore = MemoryBootstrapStore::new();

        let mut attempt: u32 = 1;
        while let Err(error) =
            fetch_bootstrap(&IanaRegistryType::RdapBootstrapDns, &client, &store, |_| {}).await
        {
            if attempt == MAX_ATTEMPTS {
                return Err(KnockKnockError::BootstrapUnavailable(error_chain(&error)));
            }

            tokio::time::sleep(RETRY_DELAY * attempt).await;
            attempt += 1;
        }

        Ok(RdapChecker { client, store })
    }

    /// Looks up registration info for given (registrable, lowercase ASCII) domain name
    pub async fn check(&self, domain_name: &str) -> Result<Registration, KnockKnockError> {
        let query: QueryType =
            QueryType::domain(domain_name).map_err(|_| KnockKnockError::InvalidDomainName)?;

        let mut servers: Vec<String> = match self.store.get_domain_query_urls(&query) {
            Ok(Some(servers)) if !servers.is_empty() => servers,
            Ok(_) => return Err(KnockKnockError::NoRdapServerForTld),
            Err(error) => return classify_client_error(error),
        };

        // Some TLDs have more than one RDAP server listed, try HTTPS ones first
        servers.sort_by_key(|server| !server.starts_with("https://"));

        let mut last_error: KnockKnockError = KnockKnockError::NoRdapServerForTld;

        for attempt in 1..=MAX_ATTEMPTS {
            let mut worth_retrying = false;

            for server in &servers {
                let outcome = match rdap_request(server, &query, &self.client).await {
                    Ok(response) => classify_response(response),
                    Err(error) => classify_client_error(error),
                };

                match outcome {
                    Ok(registration) => return Ok(registration),
                    Err(error) => {
                        worth_retrying |= error.is_transient();
                        last_error = error;
                    }
                }
            }

            if !worth_retrying || attempt == MAX_ATTEMPTS {
                break;
            }

            tokio::time::sleep(RETRY_DELAY * attempt).await;
        }

        Err(last_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domain_names() {
        assert_eq!(registrable_domain_name("github.com"), "github.com");
        assert_eq!(
            registrable_domain_name("www.rust-lang.org"),
            "rust-lang.org"
        );
        assert_eq!(
            registrable_domain_name("a.b.example.co.uk"),
            "example.co.uk"
        );
        assert_eq!(
            registrable_domain_name("shop.example.com.au"),
            "example.com.au"
        );
        // Private suffixes are ignored, registries only know about "github.io" itself
        assert_eq!(registrable_domain_name("foo.github.io"), "github.io");
        // IDN TLD (.中国)
        assert_eq!(
            registrable_domain_name("www.example.xn--fiqs8s"),
            "example.xn--fiqs8s"
        );
        // Unknown TLDs are left as is
        assert_eq!(registrable_domain_name("x.unknowntld"), "x.unknowntld");
    }

    #[test]
    fn parse_target() {
        assert_eq!(
            Target::parse("https://www.GitHub.com/snshn/knock-knock"),
            Ok(Target {
                host: "www.github.com".to_string(),
                domain: "github.com".to_string(),
                scheme: Some("https".to_string()),
                port: None,
            })
        );
        assert_eq!(
            Target::parse("Bücher.de"),
            Ok(Target {
                host: "xn--bcher-kva.de".to_string(),
                domain: "xn--bcher-kva.de".to_string(),
                scheme: None,
                port: None,
            })
        );
    }

    #[test]
    fn tls_ports() {
        let port = |input: &str| Target::parse(input).unwrap().tls_port();

        assert_eq!(port("example.com"), Some(443));
        assert_eq!(port("https://example.com"), Some(443));
        assert_eq!(port("https://example.com:8443/"), Some(8443));
        assert_eq!(port("http://example.com:8080/"), Some(443));
        assert_eq!(port("gemini://example.com"), Some(1965));
        assert_eq!(port("gemini://example.com:1966/"), Some(1966));
        assert_eq!(port("titan://example.com/upload"), Some(1965));
        assert_eq!(port("gopher://example.com"), None);
        assert_eq!(port("vitalik.eth"), None);
    }

    #[test]
    fn parse_ens_target() {
        let target: Target = Target::parse("pay.Vitalik.eth").unwrap();

        assert_eq!(target.host, "pay.vitalik.eth");
        assert_eq!(target.domain, "vitalik.eth");
        assert!(target.is_ens());
        assert!(!Target::parse("ethereum.org").unwrap().is_ens());
    }

    #[test]
    fn parse_invalid_target() {
        assert_eq!(Target::parse(""), Err(KnockKnockError::InvalidDomainName));
        assert_eq!(
            Target::parse("exa mple.com"),
            Err(KnockKnockError::InvalidDomainName)
        );
        assert_eq!(
            Target::parse("https://"),
            Err(KnockKnockError::InvalidDomainName)
        );
    }

    #[test]
    fn display_idn_domain_names() {
        assert_eq!(display_domain_name("github.com"), "github.com");
        assert_eq!(
            display_domain_name("xn--bcher-kva.de"),
            "bücher.de (xn--bcher-kva.de)"
        );
    }
}
