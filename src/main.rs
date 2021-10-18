#[macro_use]
extern crate clap;

use chrono::{DateTime, Duration, Utc};
use clap::{App, Arg};
use std::env;
use whois_rust::{WhoIs, WhoIsLookupOptions};
use whoisthere::{parse_info, DomainProps};

const ANSI_COLOR_RED: &'static str = "\x1b[31m";
const ANSI_COLOR_GREEN: &'static str = "\x1b[32m";
const ANSI_COLOR_YELLOW: &'static str = "\x1b[33m";
const ANSI_COLOR_RESET: &'static str = "\x1b[0m";
const EXPIRATION_WARNING: i64 = 2419200; // Number of seconds in 4 weeks
const EXPIRATION_CRITICAL: i64 = 604800; // Number of seconds in 1 week
const INDENTATION: &'static str = "    ";

fn pluralize(item_name: &str, quantity: i64) -> String {
    let mut result = String::from(item_name);
    if quantity != 1 {
        result += "s";
    }
    result
}

fn compose_readable_duration(mut duration: Duration) -> String {
    let is_neg: bool = duration.num_milliseconds() < 0;
    if is_neg {
        duration = duration * -1;
    }

    let mut vec: Vec<String> = Vec::new();

    let days = duration.num_days();
    if days > 0 {
        let days_str: String = format!("{} {}", days, pluralize("day", days));
        vec.push(days_str);
        duration = duration - Duration::days(days);
    }

    let hours_left = duration.num_hours();
    if hours_left > 0 {
        let hours_str: String = format!("{} {}", hours_left, pluralize("hour", hours_left));
        vec.push(hours_str);
        duration = duration - Duration::hours(hours_left);
    }

    let minutes_left = duration.num_minutes();
    if minutes_left > 0 {
        let minutes_str: String = format!("{} {}", minutes_left, pluralize("minute", minutes_left));
        vec.push(minutes_str);
        duration = duration - Duration::minutes(minutes_left);
    }

    let seconds_left = duration.num_seconds();
    if seconds_left > 0 {
        vec.push(format!(
            "{} {}",
            seconds_left,
            pluralize("second", seconds_left)
        ));
    }

    vec.join(", ")
}

pub fn get_domain_info(domain_name: &str) -> Result<DomainProps, std::fmt::Error> {
    static JSON: &str = include_str!("servers.json");
    let whois: WhoIs = WhoIs::from_string(JSON).unwrap();

    match whois.lookup(WhoIsLookupOptions::from_string(domain_name).unwrap()) {
        Ok(result) => Ok(parse_info(&domain_name, &result)),
        Err(_e) => Err(std::fmt::Error),
    }
}

fn main() {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(crate_version!())
        .author(format!("\n{}", crate_authors!("\n")).as_str())
        .about(crate_description!())
        .arg(
            Arg::with_name("certificates")
                .short("c")
                .long("check-certificates"),
        )
        .arg(
            Arg::with_name("DOMAINS")
                .help("Provides domain(s) to look up information for")
                .required(true)
                .multiple(true)
                .index(1),
        )
        .get_matches();

    let iterator = matches.values_of("DOMAINS");
    for domain_name in iterator.unwrap() {
        println!("{}:", domain_name);
        match get_domain_info(domain_name) {
            Ok(domain_whois_info) => {
                if domain_whois_info.is_registered {
                    match domain_whois_info.expiration_date.parse::<DateTime<Utc>>() {
                        Ok(expiration_date) => {
                            let now: DateTime<Utc> =
                                DateTime::<Utc>::from_utc(Utc::now().naive_utc(), Utc);
                            let time_diff: Duration = expiration_date - now;

                            let is_neg: bool = time_diff.num_milliseconds() < 0;
                            let seconds: i64 = time_diff.num_seconds();
                            let is_warning: bool = seconds <= EXPIRATION_WARNING;
                            let is_critical: bool = seconds <= EXPIRATION_CRITICAL;
                            let color;

                            if is_neg {
                                color = ANSI_COLOR_RED;
                            } else {
                                if is_warning {
                                    color = ANSI_COLOR_YELLOW;
                                } else if is_critical {
                                    color = ANSI_COLOR_RED;
                                } else {
                                    color = ANSI_COLOR_GREEN;
                                }
                            }
                            if expiration_date >= now {
                                println!(
                                    "{}Domain name will expire in {}{}{}",
                                    INDENTATION,
                                    color,
                                    compose_readable_duration(time_diff),
                                    ANSI_COLOR_RESET,
                                );
                            } else {
                                println!(
                                    "{}Domain name has expired {}{}{} ago",
                                    INDENTATION,
                                    color,
                                    compose_readable_duration(time_diff),
                                    ANSI_COLOR_RESET,
                                );
                            }
                        }
                        Err(_e) => {
                            println!(
                                "{}{}Unable to obtain domain name expiration date{}",
                                INDENTATION, ANSI_COLOR_RED, ANSI_COLOR_RESET,
                            );
                        }
                    }
                } else {
                    println!(
                        "{}{}Domain name not registered{}",
                        INDENTATION, ANSI_COLOR_GREEN, ANSI_COLOR_RESET,
                    );
                }
            }
            Err(_e) => {
                println!(
                    "{}{}Unable to retrieve domain whois information{}",
                    INDENTATION, ANSI_COLOR_RED, ANSI_COLOR_RESET,
                );
            }
        }
    }
}
