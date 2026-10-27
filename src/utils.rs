use std::ffi::OsStr;

pub const ANSI_COLOR_RED: &str = "\x1b[31m";
pub const ANSI_COLOR_GREEN: &str = "\x1b[32m";
pub const ANSI_COLOR_YELLOW: &str = "\x1b[33m";
pub const ANSI_COLOR_RESET: &str = "\x1b[0m";

pub const EXPIRATION_WARNING: i64 = 60 * 60 * 24 * 7 * 4; // Amount of seconds in 4 weeks
pub const EXPIRATION_CRITICAL: i64 = 60 * 60 * 24 * 7; // Amount of seconds in 1 week

const TIME_UNITS: [(&str, u64); 4] = [
    ("day", 60 * 60 * 24),
    ("hour", 60 * 60),
    ("minute", 60),
    ("second", 1),
];

/// Turns an amount of seconds (positive or negative) into a human-readable string,
/// e.g. "3 days" or, if `show_full_time` is set, "3 days, 2 hours, 1 second"
pub fn compose_readable_duration(seconds: i64, show_full_time: bool) -> String {
    let mut remaining: u64 = seconds.unsigned_abs();
    let mut parts: Vec<String> = Vec::new();

    for (unit_name, unit_size) in TIME_UNITS {
        let amount: u64 = remaining / unit_size;

        if amount > 0 {
            parts.push(format!("{} {}", amount, pluralize(unit_name, amount)));

            if !show_full_time {
                break;
            }

            remaining %= unit_size;
        }
    }

    if parts.is_empty() {
        return format!("0 {}", pluralize("second", 0));
    }

    parts.join(", ")
}

/// Picks the color to be used for expiration info,
/// based on how many seconds are left until the domain name expires
pub fn expiration_color(seconds_left: i64) -> &'static str {
    if seconds_left <= EXPIRATION_CRITICAL {
        // Already expired or about to expire within a week
        ANSI_COLOR_RED
    } else if seconds_left <= EXPIRATION_WARNING {
        ANSI_COLOR_YELLOW
    } else {
        ANSI_COLOR_GREEN
    }
}

pub fn highlight_text(text: &str, color: &str, use_colors: bool) -> String {
    if use_colors {
        format!("{}{}{}", color, text, ANSI_COLOR_RESET)
    } else {
        text.to_string()
    }
}

/// Colors are only used when printing to a terminal,
/// unless disabled via NO_COLOR environment variable (https://no-color.org)
pub fn should_use_colors(is_terminal: bool, no_color: Option<&OsStr>) -> bool {
    is_terminal && no_color.is_none_or(|value| value.is_empty())
}

pub fn pluralize(item_name: &str, quantity: u64) -> String {
    let mut result = String::from(item_name);

    if quantity != 1 {
        result += "s";
    }

    result
}

/// Parts of user input relevant for checks
#[derive(Debug, Eq, PartialEq)]
pub struct InputParts<'a> {
    /// Scheme in lowercase, e.g. "https" or "gemini"
    pub scheme: Option<String>,
    pub host: &'a str,
    pub port: Option<u16>,
}

/// Splits whatever the user has provided into scheme, host and port,
/// e.g. "HTTPS://user@Example.com:8080/path?q#f" -> ("https", "Example.com", 8080)
pub fn split_input(input: &str) -> Option<InputParts<'_>> {
    let mut host: &str = input.trim();
    let mut scheme: Option<String> = None;
    let mut port: Option<u16> = None;

    // Scheme (e.g. "https://")
    if let Some((scheme_part, rest)) = host.split_once("://") {
        scheme = Some(scheme_part.to_ascii_lowercase());
        host = rest;
    }

    // Drop path, query and fragment
    if let Some(end) = host.find(['/', '?', '#']) {
        host = &host[..end];
    }

    // Drop user info (e.g. "user:password@")
    if let Some((_, rest)) = host.rsplit_once('@') {
        host = rest;
    }

    // Port number (e.g. ":8080")
    if let Some((rest, port_part)) = host
        .rsplit_once(':')
        .filter(|(_, port_part)| port_part.chars().all(|c| c.is_ascii_digit()))
    {
        host = rest;
        port = port_part.parse().ok().filter(|&port: &u16| port != 0);
    }

    // Drop trailing dot(s) of fully qualified domain names (e.g. "example.com.")
    host = host.trim_end_matches('.');

    if host.is_empty() {
        None
    } else {
        Some(InputParts { scheme, host, port })
    }
}

/// Extracts host part out of whatever the user has provided,
/// e.g. "https://user@Example.com:8080/path?q#f" -> "Example.com"
pub fn extract_host(input: &str) -> Option<&str> {
    split_input(input).map(|parts| parts.host)
}

/// Checks if given (already lowercased and Punycode-encoded) domain name is valid
pub fn is_valid_ascii_domain_name(domain_name: &str) -> bool {
    !domain_name.is_empty()
        && domain_name.len() <= 253
        && domain_name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: i64 = 60;
    const HOUR: i64 = 60 * MINUTE;
    const DAY: i64 = 24 * HOUR;

    #[test]
    fn pluralize_singular_and_plural() {
        assert_eq!(pluralize("day", 0), "days");
        assert_eq!(pluralize("day", 1), "day");
        assert_eq!(pluralize("day", 2), "days");
    }

    #[test]
    fn duration_short_shows_largest_unit_only() {
        assert_eq!(
            compose_readable_duration(189 * DAY + 5 * HOUR, false),
            "189 days"
        );
        assert_eq!(compose_readable_duration(DAY, false), "1 day");
        assert_eq!(compose_readable_duration(5 * HOUR + 3, false), "5 hours");
        assert_eq!(compose_readable_duration(MINUTE, false), "1 minute");
        assert_eq!(compose_readable_duration(42, false), "42 seconds");
    }

    #[test]
    fn duration_full_shows_all_non_zero_units() {
        assert_eq!(
            compose_readable_duration(294 * DAY + 8 * HOUR + 57 * MINUTE + 11, true),
            "294 days, 8 hours, 57 minutes, 11 seconds"
        );
        assert_eq!(compose_readable_duration(DAY + 1, true), "1 day, 1 second");
        assert_eq!(compose_readable_duration(2 * HOUR, true), "2 hours");
    }

    #[test]
    fn duration_negative_is_same_as_positive() {
        assert_eq!(compose_readable_duration(-3 * DAY, false), "3 days");
        assert_eq!(
            compose_readable_duration(-(3 * DAY + HOUR), true),
            "3 days, 1 hour"
        );
    }

    #[test]
    fn duration_zero_is_not_empty() {
        assert_eq!(compose_readable_duration(0, false), "0 seconds");
        assert_eq!(compose_readable_duration(0, true), "0 seconds");
    }

    #[test]
    fn duration_extreme_values_do_not_panic() {
        compose_readable_duration(i64::MIN, true);
        compose_readable_duration(i64::MAX, true);
    }

    #[test]
    fn color_thresholds() {
        assert_eq!(expiration_color(-DAY), ANSI_COLOR_RED);
        assert_eq!(expiration_color(0), ANSI_COLOR_RED);
        assert_eq!(expiration_color(3 * DAY), ANSI_COLOR_RED);
        assert_eq!(expiration_color(EXPIRATION_CRITICAL), ANSI_COLOR_RED);
        assert_eq!(expiration_color(EXPIRATION_CRITICAL + 1), ANSI_COLOR_YELLOW);
        assert_eq!(expiration_color(20 * DAY), ANSI_COLOR_YELLOW);
        assert_eq!(expiration_color(EXPIRATION_WARNING), ANSI_COLOR_YELLOW);
        assert_eq!(expiration_color(EXPIRATION_WARNING + 1), ANSI_COLOR_GREEN);
        assert_eq!(expiration_color(365 * DAY), ANSI_COLOR_GREEN);
    }

    #[test]
    fn highlight_text_with_and_without_colors() {
        assert_eq!(
            highlight_text("hi", ANSI_COLOR_RED, true),
            "\x1b[31mhi\x1b[0m"
        );
        assert_eq!(highlight_text("hi", ANSI_COLOR_RED, false), "hi");
    }

    #[test]
    fn colors_only_for_terminals_without_no_color() {
        assert!(should_use_colors(true, None));
        assert!(should_use_colors(true, Some(OsStr::new(""))));
        assert!(!should_use_colors(true, Some(OsStr::new("1"))));
        assert!(!should_use_colors(false, None));
        assert!(!should_use_colors(false, Some(OsStr::new("1"))));
    }

    #[test]
    fn split_input_scheme_and_port() {
        assert_eq!(
            split_input("HTTPS://user@Example.com:8443/path"),
            Some(InputParts {
                scheme: Some("https".to_string()),
                host: "Example.com",
                port: Some(8443),
            })
        );
        assert_eq!(
            split_input("gemini://geminiprotocol.net/"),
            Some(InputParts {
                scheme: Some("gemini".to_string()),
                host: "geminiprotocol.net",
                port: None,
            })
        );
        assert_eq!(
            split_input("example.com"),
            Some(InputParts {
                scheme: None,
                host: "example.com",
                port: None,
            })
        );
    }

    #[test]
    fn split_input_invalid_port() {
        // Empty, zero, or out of range port numbers are ignored
        assert_eq!(split_input("example.com:").unwrap().port, None);
        assert_eq!(split_input("example.com:0").unwrap().port, None);
        assert_eq!(split_input("example.com:99999").unwrap().port, None);
        assert_eq!(
            split_input("example.com:99999").unwrap().host,
            "example.com"
        );
    }

    #[test]
    fn extract_host_plain() {
        assert_eq!(extract_host("example.com"), Some("example.com"));
        assert_eq!(extract_host("  Example.COM \n"), Some("Example.COM"));
    }

    #[test]
    fn extract_host_from_url() {
        assert_eq!(extract_host("https://example.com"), Some("example.com"));
        assert_eq!(extract_host("https://example.com/"), Some("example.com"));
        assert_eq!(
            extract_host("http://user:pass@www.example.com:8080/a/b?c=d#e"),
            Some("www.example.com")
        );
        assert_eq!(extract_host("example.com?x"), Some("example.com"));
        assert_eq!(extract_host("example.com#x"), Some("example.com"));
        assert_eq!(extract_host("example.com:443"), Some("example.com"));
    }

    #[test]
    fn extract_host_trailing_dot() {
        assert_eq!(extract_host("example.com."), Some("example.com"));
        assert_eq!(extract_host("example.com.."), Some("example.com"));
    }

    #[test]
    fn extract_host_empty() {
        assert_eq!(extract_host(""), None);
        assert_eq!(extract_host("   "), None);
        assert_eq!(extract_host("."), None);
        assert_eq!(extract_host("https://"), None);
        assert_eq!(extract_host("https:///path"), None);
    }

    #[test]
    fn valid_domain_names() {
        assert!(is_valid_ascii_domain_name("example.com"));
        assert!(is_valid_ascii_domain_name("sub-domain.example.co.uk"));
        assert!(is_valid_ascii_domain_name("xn--bcher-kva.de"));
        assert!(is_valid_ascii_domain_name("123.com"));
        assert!(is_valid_ascii_domain_name(&format!(
            "{}.com",
            "a".repeat(63)
        )));
    }

    #[test]
    fn invalid_domain_names() {
        assert!(!is_valid_ascii_domain_name(""));
        assert!(!is_valid_ascii_domain_name("Example.com"));
        assert!(!is_valid_ascii_domain_name("exa mple.com"));
        assert!(!is_valid_ascii_domain_name("exa_mple.com"));
        assert!(!is_valid_ascii_domain_name("example..com"));
        assert!(!is_valid_ascii_domain_name(".example.com"));
        assert!(!is_valid_ascii_domain_name("-example.com"));
        assert!(!is_valid_ascii_domain_name("example-.com"));
        assert!(!is_valid_ascii_domain_name(&format!(
            "{}.com",
            "a".repeat(64)
        )));
        assert!(!is_valid_ascii_domain_name(&"a.".repeat(127)));
    }
}
