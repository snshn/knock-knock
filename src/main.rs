use chrono::{DateTime, SecondsFormat, Utc};
use clap::{Arg, Command};
use futures::stream::{self, StreamExt};
use serde_json::{Value, json};
use std::env;
use std::io::{self, IsTerminal};
use std::process;

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

/// Returns message, its color, and whether it is an error
fn describe_registration(
    result: &Result<Registration, KnockKnockError>,
    target: Option<&Target>,
    show_full_time: bool,
) -> (String, &'static str, bool) {
    // Mention which domain name was checked if it's different from what was given
    let subject: String = match target {
        Some(target) if target.domain != target.host => {
            format!("Domain name {}", display_domain_name(&target.domain))
        }
        _ => "Domain name".to_string(),
    };

    match result {
        Ok(Registration::Registered {
            expires: Some(expires),
        }) => {
            let seconds_left: i64 = (*expires - Utc::now()).num_seconds();
            let readable_duration = compose_readable_duration(seconds_left, show_full_time);
            let message = if seconds_left >= 0 {
                format!("{} will expire in {}", subject, readable_duration)
            } else {
                format!("{} has expired {} ago", subject, readable_duration)
            };

            (message, expiration_color(seconds_left), false)
        }
        Ok(Registration::Registered { expires: None }) => (
            "ERROR: Unable to obtain domain name expiration date".to_string(),
            ANSI_COLOR_RED,
            true,
        ),
        Ok(Registration::NotRegistered) => (
            format!("{} not registered", subject),
            ANSI_COLOR_GREEN,
            false,
        ),
        Err(error) => (format!("ERROR: {}", error), ANSI_COLOR_RED, true),
    }
}

/// Outcome of certificate check
enum CertificateCheck {
    /// Check was not requested
    NotRequested,
    /// Certificates can't be checked for given scheme (e.g. "gopher://")
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
        CertificateCheck::NotApplicable(scheme) => (
            vec![(
                format!("No TLS certificate to check for {}://", scheme),
                ANSI_COLOR_YELLOW,
            )],
            false,
        ),
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
        }) => (
            json!({
                "status": "registered",
                "expires": format_timestamp(expires),
                "seconds_left": (*expires - *now).num_seconds(),
            }),
            false,
        ),
        Ok(Registration::Registered { expires: None }) => (
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
        CertificateCheck::NotApplicable(scheme) => (
            json!({
                "status": "not_applicable",
                "reason": format!("No TLS certificate to check for {}://", scheme),
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

    let checker: RdapChecker = match RdapChecker::new().await {
        Ok(checker) => checker,
        Err(error) => {
            eprintln!(
                "{}",
                highlight_text(
                    &format!("ERROR: {}", error),
                    ANSI_COLOR_RED,
                    use_colors_stderr
                ),
            );
            process::exit(1);
        }
    };
    let checker: &RdapChecker = &checker;

    let tls_checker: Option<TlsChecker> = if matches.is_present("certificates") {
        match TlsChecker::new() {
            Ok(tls_checker) => Some(tls_checker),
            Err(error) => {
                eprintln!(
                    "{}",
                    highlight_text(
                        &format!("ERROR: {}", error),
                        ANSI_COLOR_RED,
                        use_colors_stderr
                    ),
                );
                process::exit(1);
            }
        }
    } else {
        None
    };
    let tls_checker: Option<&TlsChecker> = tls_checker.as_ref();

    // Run up to MAX_CONCURRENT_LOOKUPS lookups at once, but print results in order
    let mut lookups = stream::iter(matches.values_of("DOMAINS").unwrap())
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
                            (Some(_), None) => CertificateCheck::NotApplicable(
                                target.scheme.clone().unwrap_or_default(),
                            ),
                        }
                    };
                    let (registration, certificate) =
                        tokio::join!(checker.check(&target.domain), certificate_check);

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
        let (message, color, is_error) =
            describe_registration(&registration, target.as_ref(), show_full_time);

        had_errors |= is_error;

        let (certificate_lines, certificate_is_error) =
            describe_certificate(&certificate, show_full_time);

        had_errors |= certificate_is_error;

        println!("{}:", title);
        for (message, color) in [(message, color)].into_iter().chain(certificate_lines) {
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
