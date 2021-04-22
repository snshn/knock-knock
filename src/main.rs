#[macro_use]
extern crate clap;
extern crate whois_rust;
// extern crate whoisthere;

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

fn format_expires_in_message(mut duration: Duration) -> String {
    let is_warning = duration.num_seconds() <= EXPIRATION_WARNING;
    let is_critical = duration.num_seconds() <= EXPIRATION_CRITICAL;
    let mut result = String::new();

    if is_warning {
        result += ANSI_COLOR_YELLOW;
    } else if is_critical {
        result += ANSI_COLOR_RED;
    } else {
        result += ANSI_COLOR_GREEN;
    }

    let mut vec: Vec<String> = Vec::new();

    if duration.num_days() > 0 {
        let days: String = format!(
            "{} {}",
            duration.num_days(),
            pluralize("day", duration.num_days()),
        );
        vec.push(days);
        duration = duration - Duration::days(duration.num_days());
    }

    if duration.num_hours() > 0 {
        let hours: String = format!(
            "{} {}",
            duration.num_hours(),
            pluralize("hour", duration.num_hours()),
        );
        vec.push(hours);
        duration = duration - Duration::hours(duration.num_hours());
    }

    if duration.num_minutes() > 0 {
        let minutes: String = format!(
            "{} {}",
            duration.num_minutes(),
            pluralize("minute", duration.num_minutes()),
        );
        vec.push(minutes);
        duration = duration - Duration::minutes(duration.num_minutes());
    }

    if duration.num_seconds() > 0 {
        vec.push(format!(
            "{} {}",
            duration.num_seconds(),
            pluralize("second", duration.num_seconds()),
        ));
    }

    result += &vec.join(", ");

    result += ANSI_COLOR_RESET;

    result
}

pub fn get_domain_info(domain_name: &str) -> DomainProps {
    let whois: WhoIs = WhoIs::from_path("./servers.json").unwrap();
    let result: String = whois
        .lookup(WhoIsLookupOptions::from_string(domain_name).unwrap())
        .unwrap();

    return parse_info(&domain_name, &result);
}

fn main() {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(crate_version!())
        .author(format!("\n{}", crate_authors!("\n")).as_str())
        .about(crate_description!())
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("check-certificates"),
        )
        .arg(
            Arg::with_name("INPUT")
                .help("Sets the input file to use")
                .required(true)
                .multiple(true)
                .index(1),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .get_matches();

    let iterator = matches.values_of("INPUT");
    for domain_name in iterator.unwrap() {
        let now: DateTime<Utc> = DateTime::<Utc>::from_utc(Utc::now().naive_utc(), Utc);
        println!("{}:", domain_name);
        let domain_whois_info: DomainProps = get_domain_info(domain_name);
        if domain_whois_info.is_registered {
            let expires_in = domain_whois_info
                .expiration_date
                .parse::<DateTime<Utc>>()
                .unwrap()
                - now;
            println!(
                "{}Expires in: {}",
                INDENTATION,
                format_expires_in_message(expires_in)
            );
        } else {
            println!(
                "{}{}Domain not registered.{}",
                INDENTATION, ANSI_COLOR_GREEN, ANSI_COLOR_RESET
            );
        }
    }
}
