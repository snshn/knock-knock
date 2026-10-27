use chrono::{DateTime, SecondsFormat, Utc};
use clap::{Arg, Command};
use futures::stream::{self, StreamExt};
use serde_json::{Value, json};
use std::env;
use std::io::{self, IsTerminal};
use std::process;

use knock_knock::ens::{DEFAULT_ETH_RPC_URL, EnsChecker};
use knock_knock::tls::{Certificate, TlsChecker, VerificationError};
use knock_knock::utils::{
    ANSI_COLOR_GREEN, ANSI_COLOR_RED, ANSI_COLOR_YELLOW, compose_readable_duration,
    expiration_color, highlight_text, should_use_colors,
};
use knock_knock::{
    GEMINI_PORT, HTTPS_PORT, KnockKnockError, RdapChecker, Registration, Target,
    display_domain_name,
};

const INDENTATION: &str = "    ";
const MAX_CONCURRENT_LOOKUPS: usize = 4;

/// Returns lines (message and color), and whether there was an error
fn describe_registration(
    result: &Result<Registration, KnockKnockError>,
    target: Option<&Target>,
    show_full_time: bool,
) -> (Vec<(String, &'static str)>, bool) {
    let kind: &str = match target {
        Some(target) if target.is_ens() => "ENS name",
        _ => "Domain name",
    };
    // Mention which name was checked if it's different from what was given
    let subject: String = match target {
        Some(target) if target.domain != target.host => {
            format!("{} {}", kind, display_domain_name(&target.domain))
        }
        _ => kind.to_string(),
    };
    let now: DateTime<Utc> = Utc::now();

    match result {
        Ok(Registration::Registered {
            expires: Some(expires),
            grace_period_ends,
        }) => {
            let seconds_left: i64 = (*expires - now).num_seconds();
            let readable_duration = compose_readable_duration(seconds_left, show_full_time);
            let mut lines = vec![(
                if seconds_left >= 0 {
                    format!("{} will expire in {}", subject, readable_duration)
                } else {
                    format!("{} has expired {} ago", subject, readable_duration)
                },
                expiration_color(seconds_left),
            )];

            if let Some(grace_period_ends) = grace_period_ends
                && seconds_left < 0
            {
                let grace_seconds_left: i64 = (*grace_period_ends - now).num_seconds();

                lines.push((
                    format!(
                        "Owner can still renew it within {} (grace period), then anyone can register it",
                        compose_readable_duration(grace_seconds_left, show_full_time)
                    ),
                    ANSI_COLOR_RED,
                ));
            }

            (lines, false)
        }
        Ok(Registration::Registered { expires: None, .. }) => (
            vec![(
                format!(
                    "ERROR: Unable to obtain {} expiration date",
                    kind.to_lowercase()
                ),
                ANSI_COLOR_RED,
            )],
            true,
        ),
        Ok(Registration::NotRegistered) => (
            vec![(format!("{} not registered", subject), ANSI_COLOR_GREEN)],
            false,
        ),
        Err(error) => (vec![(format!("ERROR: {}", error), ANSI_COLOR_RED)], true),
    }
}

/// Outcome of certificate check
enum CertificateCheck {
    /// Check was not requested
    NotRequested,
    /// Certificates can't be checked for given target (e.g. "gopher://" or ENS names)
    NotApplicable(String),
    Done {
        result: Result<Certificate, KnockKnockError>,
        /// Gemini uses trust on first use, self-signed certificates are expected
        gemini: bool,
    },
}

/// Returns lines (message and color), and whether there was an error
fn describe_certificate(
    check: &CertificateCheck,
    show_full_time: bool,
) -> (Vec<(String, &'static str)>, bool) {
    match check {
        CertificateCheck::NotRequested => (vec![], false),
        CertificateCheck::NotApplicable(reason) => {
            (vec![(reason.clone(), ANSI_COLOR_YELLOW)], false)
        }
        CertificateCheck::Done {
            result: Ok(certificate),
            gemini,
        } => {
            let seconds_left: i64 = (certificate.not_after - Utc::now()).num_seconds();
            let readable_duration = compose_readable_duration(seconds_left, show_full_time);
            let subject: String = match (*gemini, certificate.port) {
                (false, HTTPS_PORT) => "TLS certificate".to_string(),
                (false, port) => format!("TLS certificate (port {})", port),
                (true, GEMINI_PORT) => "TLS certificate (Gemini)".to_string(),
                (true, port) => format!("TLS certificate (Gemini, port {})", port),
            };
            let mut lines = vec![(
                if seconds_left >= 0 {
                    format!("{} will expire in {}", subject, readable_duration)
                } else {
                    format!("{} has expired {} ago", subject, readable_duration)
                },
                expiration_color(seconds_left),
            )];

            // Expiration is already reported above, and Gemini capsules commonly
            // use self-signed certificates (which is fine, as long as they match the host)
            if let Some(verification_error) = &certificate.verification_error
                && *verification_error != VerificationError::Expired
                && !(*gemini && *verification_error == VerificationError::UnknownIssuer)
            {
                lines.push((
                    format!("{} is not trusted: {}", subject, verification_error),
                    ANSI_COLOR_RED,
                ));
            }

            (lines, false)
        }
        CertificateCheck::Done {
            result: Err(error), ..
        } => (
            vec![(
                format!("ERROR: Unable to check TLS certificate: {}", error),
                ANSI_COLOR_RED,
            )],
            true,
        ),
    }
}

fn format_timestamp(timestamp: &DateTime<Utc>) -> String {
    timestamp.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Returns JSON representation of registration info, and whether it is an error
fn registration_to_json(
    result: &Result<Registration, KnockKnockError>,
    now: &DateTime<Utc>,
) -> (Value, bool) {
    match result {
        Ok(Registration::Registered {
            expires: Some(expires),
            grace_period_ends,
        }) => {
            let mut registration: Value = json!({
                "status": "registered",
                "expires": format_timestamp(expires),
                "seconds_left": (*expires - *now).num_seconds(),
            });
            if let Some(grace_period_ends) = grace_period_ends {
                registration["grace_period_ends"] = json!(format_timestamp(grace_period_ends));
            }

            (registration, false)
        }
        Ok(Registration::Registered { expires: None, .. }) => (
            json!({
                "status": "registered",
                "expires": null,
                "seconds_left": null,
                "error": "Unable to obtain domain name expiration date",
            }),
            true,
        ),
        Ok(Registration::NotRegistered) => (json!({ "status": "not_registered" }), false),
        Err(error) => (
            json!({
                "status": "error",
                "error": error.to_string(),
            }),
            true,
        ),
    }
}

/// Returns JSON representation of certificate info (null if not requested), and whether it is an error
fn certificate_to_json(check: &CertificateCheck, now: &DateTime<Utc>) -> (Value, bool) {
    match check {
        CertificateCheck::NotRequested => (Value::Null, false),
        CertificateCheck::NotApplicable(reason) => (
            json!({
                "status": "not_applicable",
                "reason": reason,
            }),
            false,
        ),
        CertificateCheck::Done {
            result: Ok(certificate),
            ..
        } => (
            json!({
                "status": "checked",
                "host": certificate.host,
                "port": certificate.port,
                "not_before": format_timestamp(&certificate.not_before),
                "expires": format_timestamp(&certificate.not_after),
                "seconds_left": (certificate.not_after - *now).num_seconds(),
                "self_signed": certificate.self_signed,
                "trusted": certificate.verification_error.is_none(),
                "verification_error": certificate
                    .verification_error
                    .as_ref()
                    .map(|verification_error| verification_error.to_string()),
            }),
            false,
        ),
        CertificateCheck::Done {
            result: Err(error), ..
        } => (
            json!({
                "status": "error",
                "error": error.to_string(),
            }),
            true,
        ),
    }
}

fn exit_with_error(error: &KnockKnockError, use_colors: bool) -> ! {
    eprintln!(
        "{}",
        highlight_text(&format!("ERROR: {}", error), ANSI_COLOR_RED, use_colors),
    );
    process::exit(1);
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
                .long("check-certificates")
                .help("Also checks when TLS certificates expire"),
        )
        .arg(
            Arg::new("eth-rpc-url")
                .long("eth-rpc-url")
                .takes_value(true)
                .value_name("URL")
                .env("ETH_RPC_URL")
                .help(
                    "Ethereum JSON-RPC endpoint used for looking up ENS (.eth) names \
                     [default: https://ethereum-rpc.publicnode.com]",
                ),
        )
        .arg(
            Arg::new("fulltime")
                .short('f')
                .long("full-time")
                .help("Shows full time left until expiration (days, hours, minutes, seconds)"),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .help("Outputs results in JSON format"),
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
    let output_json: bool = matches.is_present("json");
    let use_colors: bool = !output_json
        && should_use_colors(
            io::stdout().is_terminal(),
            env::var_os("NO_COLOR").as_deref(),
        );
    let use_colors_stderr: bool = should_use_colors(
        io::stderr().is_terminal(),
        env::var_os("NO_COLOR").as_deref(),
    );

    let inputs: Vec<&str> = matches.values_of("DOMAINS").unwrap().collect();
    let targets: Vec<Target> = inputs
        .iter()
        .filter_map(|input| Target::parse(input).ok())
        .collect();

    // Only set up what's needed for given names
    let rdap_checker: Option<RdapChecker> = if targets.iter().any(|target| !target.is_ens()) {
        match RdapChecker::new().await {
            Ok(rdap_checker) => Some(rdap_checker),
            Err(error) => exit_with_error(&error, use_colors_stderr),
        }
    } else {
        None
    };
    let rdap_checker: Option<&RdapChecker> = rdap_checker.as_ref();

    let ens_checker: Option<EnsChecker> = if targets.iter().any(Target::is_ens) {
        let rpc_url: &str = matches
            .value_of("eth-rpc-url")
            .unwrap_or(DEFAULT_ETH_RPC_URL);

        match EnsChecker::new(rpc_url) {
            Ok(ens_checker) => Some(ens_checker),
            Err(error) => exit_with_error(&error, use_colors_stderr),
        }
    } else {
        None
    };
    let ens_checker: Option<&EnsChecker> = ens_checker.as_ref();

    let tls_checker: Option<TlsChecker> = if matches.is_present("certificates") {
        match TlsChecker::new() {
            Ok(tls_checker) => Some(tls_checker),
            Err(error) => exit_with_error(&error, use_colors_stderr),
        }
    } else {
        None
    };
    let tls_checker: Option<&TlsChecker> = tls_checker.as_ref();

    // Run up to MAX_CONCURRENT_LOOKUPS lookups at once, but print results in order
    let mut lookups = stream::iter(inputs)
        .map(|input| async move {
            match Target::parse(input) {
                Ok(target) => {
                    let certificate_check = async {
                        match (tls_checker, target.tls_port()) {
                            (None, _) => CertificateCheck::NotRequested,
                            (Some(tls_checker), Some(port)) => CertificateCheck::Done {
                                result: tls_checker.check(&target.host, port).await,
                                gemini: target.is_gemini(),
                            },
                            (Some(_), None) if target.is_ens() => CertificateCheck::NotApplicable(
                                "No TLS certificate to check for ENS names".to_string(),
                            ),
                            (Some(_), None) => CertificateCheck::NotApplicable(format!(
                                "No TLS certificate to check for {}://",
                                target.scheme.clone().unwrap_or_default()
                            )),
                        }
                    };
                    let registration_check = async {
                        match (target.is_ens(), ens_checker, rdap_checker) {
                            (true, Some(ens_checker), _) => ens_checker.check(&target.domain).await,
                            (false, _, Some(rdap_checker)) => {
                                rdap_checker.check(&target.domain).await
                            }
                            // Checkers are set up for all parsed targets above
                            _ => Err(KnockKnockError::ClientProblem(
                                "No checker available".to_string(),
                            )),
                        }
                    };
                    let (registration, certificate) =
                        tokio::join!(registration_check, certificate_check);

                    (input, Some(target), registration, certificate)
                }
                Err(error) => (input, None, Err(error), CertificateCheck::NotRequested),
            }
        })
        .buffered(MAX_CONCURRENT_LOOKUPS);

    let mut had_errors = false;
    let mut json_results: Vec<Value> = Vec::new();

    while let Some((input, target, registration, certificate)) = lookups.next().await {
        if output_json {
            let now: DateTime<Utc> = Utc::now();
            let (registration_json, registration_is_error) =
                registration_to_json(&registration, &now);
            let (certificate_json, certificate_is_error) = certificate_to_json(&certificate, &now);

            had_errors |= registration_is_error || certificate_is_error;

            let mut result: Value = json!({
                "input": input,
                "host": target.as_ref().map(|target| target.host.clone()),
                "domain": target.as_ref().map(|target| target.domain.clone()),
                "scheme": target.as_ref().and_then(|target| target.scheme.clone()),
                "naming_system": target
                    .as_ref()
                    .map(|target| if target.is_ens() { "ens" } else { "dns" }),
                "registration": registration_json,
            });
            if !certificate_json.is_null() {
                result["certificate"] = certificate_json;
            }
            json_results.push(result);

            continue;
        }

        let title: String = match &target {
            Some(target) => display_domain_name(&target.host),
            None => input.to_string(),
        };
        let (registration_lines, registration_is_error) =
            describe_registration(&registration, target.as_ref(), show_full_time);

        had_errors |= registration_is_error;

        let (certificate_lines, certificate_is_error) =
            describe_certificate(&certificate, show_full_time);

        had_errors |= certificate_is_error;

        println!("{}:", title);
        for (message, color) in registration_lines.into_iter().chain(certificate_lines) {
            println!(
                "{}",
                highlight_text(&format!("{}{}", INDENTATION, message), color, use_colors)
            );
        }
    }

    if output_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json_results).expect("unable to serialize results")
        );
    }

    if had_errors {
        process::exit(1);
    }
}
