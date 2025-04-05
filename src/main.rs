use chrono::{DateTime, Duration, Utc};
use clap::{Arg, Command};
use rdap_client::bootstrap::Bootstrap;
use rdap_client::parser::{Domain, EventAction};
use rdap_client::{Client, ClientError};
use std::env;

#[derive(Debug, Eq, PartialEq)]
pub enum KnockKnockError {
    CouldntParseData,
    DomainNotFound,
    NetworkRequestGlitch,
    NoServersFound,
    RdapProblem,
    BadServer,
    UnableToRetrieveListOfServers,
}

const ANSI_COLOR_RED: &str = "\x1b[31m";
const ANSI_COLOR_GREEN: &str = "\x1b[32m";
const ANSI_COLOR_YELLOW: &str = "\x1b[33m";
const ANSI_COLOR_RESET: &str = "\x1b[0m";
const EXPIRATION_WARNING: i64 = 2419200; // Amount of seconds in 4 weeks
const EXPIRATION_CRITICAL: i64 = 604800; // Amount of seconds in 1 week
const INDENTATION: &str = "    ";

async fn check_domain(
    client: &Client,
    bootstrap: &Bootstrap,
    domain_name: &str,
) -> Result<Domain, KnockKnockError> {
    if let Some(servers) = bootstrap.dns.find(domain_name) {
        if !servers.is_empty() {
            match client.query_domain(&servers[0], domain_name).await {
                Ok(response) => Ok(response),
                Err(error) => match error {
                    ClientError::Reqwest(_) => {
                        Err::<Domain, KnockKnockError>(KnockKnockError::NetworkRequestGlitch)
                    }
                    ClientError::Server(response) => {
                        if response.status() == 404 {
                            return Err::<Domain, KnockKnockError>(KnockKnockError::DomainNotFound);
                        }

                        Err::<Domain, KnockKnockError>(KnockKnockError::BadServer)
                    }
                    ClientError::JsonDecode(_, _) => {
                        Err::<Domain, KnockKnockError>(KnockKnockError::CouldntParseData)
                    }
                    ClientError::Rdap(_, _) => {
                        Err::<Domain, KnockKnockError>(KnockKnockError::RdapProblem)
                    }
                },
            }
        } else {
            Err::<Domain, KnockKnockError>(KnockKnockError::NoServersFound)
        }
    } else {
        Err::<Domain, KnockKnockError>(KnockKnockError::UnableToRetrieveListOfServers)
    }
}

fn compose_readable_duration(mut duration: Duration, show_full_time: bool) -> String {
    let is_neg: bool = duration.num_milliseconds() < 0;
    if is_neg {
        duration = duration * -1;
    }

    let mut vec: Vec<String> = Vec::new();

    let days_left = duration.num_days();
    if days_left > 0 {
        let days_str: String = format!("{} {}", days_left, pluralize("day", days_left));

        if !show_full_time {
            return days_str;
        }

        vec.push(days_str);
        duration -= Duration::days(days_left);
    }

    let hours_left = duration.num_hours();
    if hours_left > 0 {
        let hours_str: String = format!("{} {}", hours_left, pluralize("hour", hours_left));

        if !show_full_time {
            return hours_str;
        }

        vec.push(hours_str);
        duration -= Duration::hours(hours_left);
    }

    let minutes_left = duration.num_minutes();
    if minutes_left > 0 {
        let minutes_str: String = format!("{} {}", minutes_left, pluralize("minute", minutes_left));

        if !show_full_time {
            return minutes_str;
        }

        vec.push(minutes_str);
        duration -= Duration::minutes(minutes_left);
    }

    let seconds_left = duration.num_seconds();
    if seconds_left > 0 {
        let seconds_str: String = format!("{} {}", seconds_left, pluralize("second", seconds_left));

        if !show_full_time {
            return seconds_str;
        }

        vec.push(seconds_str);
    }

    vec.join(", ")
}

pub fn highlight_text(text: &str, color: &str) -> String {
    format!("{}{}{}", color, text, ANSI_COLOR_RESET)
}

pub fn pluralize(item_name: &str, quantity: i64) -> String {
    let mut result = String::from(item_name);

    if quantity != 1 {
        result += "s";
    }

    result
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
        .arg(Arg::new("fulltime").short('f').long("full-time"))
        .arg(
            Arg::new("DOMAINS")
                .help("Provides domain(s) to look up information for")
                .required(true)
                .multiple_occurrences(true)
                .index(1),
        )
        .get_matches();

    let client: Client = Client::new();

    match client.fetch_bootstrap().await {
        Ok(bootstrap) => {
            let iterator = matches.values_of("DOMAINS");

            let domain_names: Vec<&str> = iterator.unwrap().collect();
            let mut i = 0;
            let mut prev_i = 0;
            let mut retry_count = 0;

            while i < domain_names.len() {
                let domain_name = domain_names[i];

                if i == prev_i {
                    retry_count = 0;
                    println!("{}:", domain_name);
                } else {
                    retry_count += 1;
                }

                i += 1;
                prev_i = i;

                if retry_count >= 3 {
                    // println!(
                    //     "{}",
                    //     &highlight_text(
                    //         &format!("{}ERROR: Unable to retrieve domain name info", INDENTATION),
                    //         ANSI_COLOR_RED
                    //     ),
                    // );
                    println!(
                        "{}",
                        &highlight_text(
                            &format!("{}Domain name not registered", INDENTATION),
                            ANSI_COLOR_GREEN
                        ),
                    );

                    continue;
                }

                let result = check_domain(&client, &bootstrap, domain_name).await;
                match result {
                    Ok(response) => {
                        let mut found_expiration_date_info = false;
                        let mut expiration_date: DateTime<Utc> = Utc::now();
                        for event in response.events.into_iter() {
                            // println!("{:?}", event);
                            if event.event_action == EventAction::Expiration {
                                expiration_date = event.event_date.with_timezone(&Utc);
                                found_expiration_date_info = true;
                                break;
                            }
                        }

                        if found_expiration_date_info {
                            let now: DateTime<Utc> = Utc::now();
                            let time_diff: Duration = expiration_date - now;

                            let has_already_expired: bool = time_diff.num_milliseconds() < 1;
                            let seconds: i64 = time_diff.num_seconds();
                            let is_warning: bool = seconds <= EXPIRATION_WARNING;
                            let is_critical: bool = seconds <= EXPIRATION_CRITICAL;
                            let color = if has_already_expired {
                                ANSI_COLOR_RED
                            } else if is_warning {
                                ANSI_COLOR_YELLOW
                            } else if is_critical {
                                ANSI_COLOR_RED
                            } else {
                                ANSI_COLOR_GREEN
                            };

                            if expiration_date >= now {
                                println!(
                                    "{}",
                                    &highlight_text(
                                        &format!(
                                            "{}Domain name will expire in {}",
                                            INDENTATION,
                                            compose_readable_duration(
                                                time_diff,
                                                matches.is_present("fulltime")
                                            )
                                        ),
                                        color
                                    ),
                                );
                            } else {
                                println!(
                                    "{}",
                                    &highlight_text(
                                        &format!(
                                            "{}Domain name has expired {} ago",
                                            INDENTATION,
                                            compose_readable_duration(
                                                time_diff,
                                                matches.is_present("fulltime")
                                            )
                                        ),
                                        color
                                    ),
                                );
                            }
                        } else {
                            println!(
                                "{}",
                                &highlight_text(
                                    &format!(
                                        "{}ERROR: Unable to obtain domain name expiration date",
                                        INDENTATION
                                    ),
                                    ANSI_COLOR_RED
                                ),
                            );
                        }
                    }
                    Err(error) => match error {
                        KnockKnockError::DomainNotFound => {
                            println!(
                                "{}",
                                &highlight_text(
                                    &format!("{}Domain name not registered", INDENTATION),
                                    ANSI_COLOR_GREEN
                                ),
                            );
                        }
                        _ => {
                            i -= 1;
                        }
                    },
                }
            }
        }
        Err(_) => {
            println!(
                "{}",
                &highlight_text(
                    &format!("{}ERROR: Unable to establish connection", INDENTATION),
                    ANSI_COLOR_RED
                ),
            );
            std::process::exit(1);
        }
    }
}
