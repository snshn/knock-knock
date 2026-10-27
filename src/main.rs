use chrono::{DateTime, Utc};
use clap::{Arg, Command};
use futures::stream::{self, StreamExt};
use icann_rdap_client::http::Client;
use icann_rdap_client::iana::{BootstrapStore, fetch_bootstrap};
use icann_rdap_client::prelude::{
    ClientConfig, MemoryBootstrapStore, QueryType, RdapClientError, create_client, rdap_request,
};
use icann_rdap_client::rdap::ResponseData;
use icann_rdap_common::iana::IanaRegistryType;
use icann_rdap_common::response::{Domain, ObjectCommonFields, RdapResponse};
use std::env;
use std::error::Error;
use std::io::{self, IsTerminal};
use std::process;
use std::time::Duration;

mod utils;

use utils::{
    ANSI_COLOR_GREEN, ANSI_COLOR_RED, compose_readable_duration, expiration_color, extract_host,
    highlight_text, is_valid_ascii_domain_name, should_use_colors,
};

const INDENTATION: &str = "    ";
const MAX_ATTEMPTS: u32 = 3;
const MAX_CONCURRENT_LOOKUPS: usize = 4;
const TIMEOUT_SECS: u64 = 30;
const RETRY_DELAY: Duration = Duration::from_millis(500);

#[derive(Debug, Eq, PartialEq)]
pub enum KnockKnockError {
    /// Server responded with an unexpected HTTP status code (not in RDAP format)
    BadServerResponse(u16),
    /// Any other problem reported by the RDAP client library
    ClientProblem(String),
    /// Server responded with data that could not be parsed
    CouldntParseData,
    /// Provided input doesn't look like a domain name
    InvalidDomainName,
    /// Request did not go through (no connection, timeout, DNS failure, etc)
    NetworkRequestGlitch(String),
    /// IANA's bootstrap file has no RDAP server listed for this TLD
    NoRdapServerForTld,
    /// Server responded with an RDAP error message (other than "not found")
    RdapError(u16),
}

impl KnockKnockError {
    /// Whether it makes sense to try sending the same request again
    fn is_transient(&self) -> bool {
        match self {
            KnockKnockError::NetworkRequestGlitch(_) => true,
            KnockKnockError::BadServerResponse(status) | KnockKnockError::RdapError(status) => {
                *status == 429 || *status >= 500
            }
            KnockKnockError::ClientProblem(_)
            | KnockKnockError::CouldntParseData
            | KnockKnockError::InvalidDomainName
            | KnockKnockError::NoRdapServerForTld => false,
        }
    }

    fn describe(&self) -> String {
        match self {
            KnockKnockError::BadServerResponse(status) => {
                format!("RDAP server responded with HTTP status {}", status)
            }
            KnockKnockError::ClientProblem(message) => message.clone(),
            KnockKnockError::CouldntParseData => {
                "Unable to parse data returned by RDAP server".to_string()
            }
            KnockKnockError::InvalidDomainName => "Invalid domain name".to_string(),
            KnockKnockError::NetworkRequestGlitch(details) => {
                format!("Unable to reach RDAP server ({})", details)
            }
            KnockKnockError::NoRdapServerForTld => {
                "No RDAP server is known for this top-level domain".to_string()
            }
            KnockKnockError::RdapError(code) => {
                format!("RDAP server responded with error code {}", code)
            }
        }
    }
}

pub enum LookupResult {
    Registered(Box<Domain>),
    NotRegistered,
}

/// Turns user input (e.g. "https://Bücher.de/") into a lowercase ASCII domain name
/// suitable for RDAP queries (e.g. "xn--bcher-kva.de")
fn normalize_domain_name(input: &str) -> Option<String> {
    let host: &str = extract_host(input)?;
    let domain_name: String = idna::domain_to_ascii(host).ok()?;

    if is_valid_ascii_domain_name(&domain_name) {
        Some(domain_name)
    } else {
        None
    }
}

/// Makes Punycode-encoded domain names readable, e.g. "bücher.de (xn--bcher-kva.de)"
fn display_domain_name(domain_name: &str) -> String {
    let (unicode, result) = idna::domain_to_unicode(domain_name);

    if result.is_ok() && unicode != domain_name {
        format!("{} ({})", unicode, domain_name)
    } else {
        domain_name.to_string()
    }
}

/// Turns error and all its sources into one line, e.g.
/// "error sending request: client error (Connect): dns error: failed to lookup address"
fn error_chain(error: &dyn Error) -> String {
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

/// Sorts out which responses mean "this domain name is not registered"
/// (HTTP 404, as per RFC 7480 section 5.3) and which ones are errors
fn classify_response(response: ResponseData) -> Result<LookupResult, KnockKnockError> {
    let status: u16 = response.http_data.status_code();

    match response.rdap {
        RdapResponse::Domain(domain) => Ok(LookupResult::Registered(domain)),
        RdapResponse::ErrorResponse(error) => {
            let code: u16 = match error.error_code() {
                0 => status,
                code => code,
            };

            if code == 404 || status == 404 {
                Ok(LookupResult::NotRegistered)
            } else {
                Err(KnockKnockError::RdapError(code))
            }
        }
        // Valid RDAP, but not a domain object
        _ => match status {
            404 => Ok(LookupResult::NotRegistered),
            200 => Err(KnockKnockError::CouldntParseData),
            status => Err(KnockKnockError::BadServerResponse(status)),
        },
    }
}

fn classify_client_error(error: RdapClientError) -> Result<LookupResult, KnockKnockError> {
    match error {
        RdapClientError::Client(error) => {
            Err(KnockKnockError::NetworkRequestGlitch(error_chain(&error)))
        }
        RdapClientError::IoError(error) => {
            Err(KnockKnockError::NetworkRequestGlitch(error_chain(&error)))
        }
        // Response body is not JSON (e.g. empty, or an HTML error page)
        RdapClientError::ParsingError(info) => match info.http_data.status_code() {
            404 => Ok(LookupResult::NotRegistered),
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

async fn check_domain(
    client: &Client,
    store: &MemoryBootstrapStore,
    domain_name: &str,
) -> Result<LookupResult, KnockKnockError> {
    let query: QueryType =
        QueryType::domain(domain_name).map_err(|_| KnockKnockError::InvalidDomainName)?;

    let mut servers: Vec<String> = match store.get_domain_query_urls(&query) {
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
            let outcome = match rdap_request(server, &query, client).await {
                Ok(response) => classify_response(response),
                Err(error) => classify_client_error(error),
            };

            match outcome {
                Ok(result) => return Ok(result),
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

/// Returns message, its color, and whether it is an error
fn describe_result(
    result: &Result<LookupResult, KnockKnockError>,
    show_full_time: bool,
) -> (String, &'static str, bool) {
    match result {
        Ok(LookupResult::Registered(domain)) => match expiration_date(domain) {
            Some(date) => {
                let seconds_left: i64 = (date - Utc::now()).num_seconds();
                let readable_duration = compose_readable_duration(seconds_left, show_full_time);
                let message = if seconds_left >= 0 {
                    format!("Domain name will expire in {}", readable_duration)
                } else {
                    format!("Domain name has expired {} ago", readable_duration)
                };

                (message, expiration_color(seconds_left), false)
            }
            None => (
                "ERROR: Unable to obtain domain name expiration date".to_string(),
                ANSI_COLOR_RED,
                true,
            ),
        },
        Ok(LookupResult::NotRegistered) => (
            "Domain name not registered".to_string(),
            ANSI_COLOR_GREEN,
            false,
        ),
        Err(error) => (format!("ERROR: {}", error.describe()), ANSI_COLOR_RED, true),
    }
}

#[tokio::main]
async fn main() {
    let matches = Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::new("certificates")
                .short('c')
                .long("check-certificates"),
        )
        .arg(
            Arg::new("fulltime")
                .short('f')
                .long("full-time")
                .help("Shows full time left until expiration (days, hours, minutes, seconds)"),
        )
        .arg(
            Arg::new("DOMAINS")
                .help("Provides domain(s) to look up information for")
                .required(true)
                .multiple_occurrences(true)
                .index(1),
        )
        .get_matches();

    let show_full_time: bool = matches.is_present("fulltime");
    let use_colors: bool = should_use_colors(
        io::stdout().is_terminal(),
        env::var_os("NO_COLOR").as_deref(),
    );
    let use_colors_stderr: bool = should_use_colors(
        io::stderr().is_terminal(),
        env::var_os("NO_COLOR").as_deref(),
    );

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

    let client: Client = match create_client(&config) {
        Ok(client) => client,
        Err(error) => {
            eprintln!(
                "{}",
                highlight_text(
                    &format!("ERROR: Unable to create RDAP client: {}", error),
                    ANSI_COLOR_RED,
                    use_colors_stderr,
                ),
            );
            process::exit(1);
        }
    };

    // Obtain IANA's list of RDAP servers for TLDs once, before running lookups
    let store: MemoryBootstrapStore = MemoryBootstrapStore::new();
    let mut attempt: u32 = 1;
    while let Err(error) =
        fetch_bootstrap(&IanaRegistryType::RdapBootstrapDns, &client, &store, |_| {}).await
    {
        if attempt == MAX_ATTEMPTS {
            eprintln!(
                "{}",
                highlight_text(
                    &format!(
                        "ERROR: Unable to obtain list of RDAP servers from IANA ({})",
                        error_chain(&error)
                    ),
                    ANSI_COLOR_RED,
                    use_colors_stderr,
                ),
            );
            process::exit(1);
        }

        tokio::time::sleep(RETRY_DELAY * attempt).await;
        attempt += 1;
    }

    let client: &Client = &client;
    let store: &MemoryBootstrapStore = &store;

    // Run up to MAX_CONCURRENT_LOOKUPS lookups at once, but print results in order
    let mut lookups = stream::iter(matches.values_of("DOMAINS").unwrap())
        .map(|input| async move {
            match normalize_domain_name(input) {
                Some(domain_name) => (
                    display_domain_name(&domain_name),
                    check_domain(client, store, &domain_name).await,
                ),
                None => (input.to_string(), Err(KnockKnockError::InvalidDomainName)),
            }
        })
        .buffered(MAX_CONCURRENT_LOOKUPS);

    let mut had_errors = false;

    while let Some((title, result)) = lookups.next().await {
        let (message, color, is_error) = describe_result(&result, show_full_time);

        had_errors |= is_error;

        println!("{}:", title);
        println!(
            "{}",
            highlight_text(&format!("{}{}", INDENTATION, message), color, use_colors)
        );
    }

    if had_errors {
        process::exit(1);
    }
}
