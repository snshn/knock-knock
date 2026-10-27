//! Minimal X.509 (DER) parsing, just enough to read certificate validity period
//! and tell whether it's self-signed, without pulling in a full ASN.1 parser.

const TAG_SEQUENCE: u8 = 0x30;
const TAG_INTEGER: u8 = 0x02;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_EXPLICIT_VERSION: u8 = 0xA0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateValidity {
    /// Unix timestamp the certificate is valid from
    pub not_before: i64,
    /// Unix timestamp the certificate is valid until
    pub not_after: i64,
    /// Whether issuer and subject are identical
    pub self_signed: bool,
}

/// Splits DER-encoded data into tag, contents and remaining data
fn read_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, data) = data.split_first()?;
    let (&first_length_byte, data) = data.split_first()?;

    let (length, data): (usize, &[u8]) = if first_length_byte < 0x80 {
        (first_length_byte as usize, data)
    } else {
        let length_bytes_count: usize = (first_length_byte & 0x7F) as usize;

        if length_bytes_count == 0 || length_bytes_count > 4 || data.len() < length_bytes_count {
            return None;
        }

        let (length_bytes, data) = data.split_at(length_bytes_count);
        let length: usize = length_bytes
            .iter()
            .fold(0, |length, &byte| (length << 8) | byte as usize);

        (length, data)
    };

    if data.len() < length {
        return None;
    }

    let (contents, rest) = data.split_at(length);

    Some((tag, contents, rest))
}

/// Same as read_tlv(), but expects specific tag
fn expect_tlv(data: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    match read_tlv(data)? {
        (tag, contents, rest) if tag == expected_tag => Some((contents, rest)),
        _ => None,
    }
}

/// Number of days since 1970-01-01 for given date (proleptic Gregorian calendar)
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year: i64 = if month <= 2 { year - 1 } else { year };
    let era: i64 = year.div_euclid(400);
    let year_of_era: i64 = year - era * 400;
    let month_index: i64 = (month + 9) % 12; // March = 0
    let day_of_year: i64 = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era: i64 = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    era * 146097 + day_of_era - 719468
}

fn parse_digits(digits: &[u8]) -> Option<i64> {
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }

    Some(
        digits
            .iter()
            .fold(0, |number, &digit| number * 10 + (digit - b'0') as i64),
    )
}

/// Parses UTCTime ("YYMMDDHHMMSSZ") or GeneralizedTime ("YYYYMMDDHHMMSSZ")
/// as mandated by RFC 5280 section 4.1.2.5, returns Unix timestamp
fn parse_time(tag: u8, value: &[u8]) -> Option<i64> {
    let (year, rest): (i64, &[u8]) = match (tag, value.len()) {
        (TAG_UTC_TIME, 13) => {
            let year: i64 = parse_digits(&value[..2])?;
            // RFC 5280: YY >= 50 means 19YY, YY < 50 means 20YY
            (
                if year >= 50 { 1900 + year } else { 2000 + year },
                &value[2..],
            )
        }
        (TAG_GENERALIZED_TIME, 15) => (parse_digits(&value[..4])?, &value[4..]),
        _ => return None,
    };

    if rest[10] != b'Z' {
        return None;
    }

    let month: i64 = parse_digits(&rest[0..2])?;
    let day: i64 = parse_digits(&rest[2..4])?;
    let hour: i64 = parse_digits(&rest[4..6])?;
    let minute: i64 = parse_digits(&rest[6..8])?;
    let second: i64 = parse_digits(&rest[8..10])?;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }

    Some(days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second)
}

fn read_time(data: &[u8]) -> Option<(i64, &[u8])> {
    let (tag, contents, rest) = read_tlv(data)?;

    Some((parse_time(tag, contents)?, rest))
}

/// Reads validity period of DER-encoded X.509 certificate (RFC 5280 section 4.1)
pub fn certificate_validity(der: &[u8]) -> Option<CertificateValidity> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (certificate, _) = expect_tlv(der, TAG_SEQUENCE)?;
    let (tbs_certificate, _) = expect_tlv(certificate, TAG_SEQUENCE)?;

    // version [0] EXPLICIT (optional)
    let mut data: &[u8] = tbs_certificate;
    if let Some((TAG_EXPLICIT_VERSION, _, rest)) = read_tlv(data) {
        data = rest;
    }

    // serialNumber, signature (algorithm), issuer
    let (_, data) = expect_tlv(data, TAG_INTEGER)?;
    let (_, data) = expect_tlv(data, TAG_SEQUENCE)?;
    let (issuer, data) = expect_tlv(data, TAG_SEQUENCE)?;

    // validity ::= SEQUENCE { notBefore Time, notAfter Time }
    let (validity, data) = expect_tlv(data, TAG_SEQUENCE)?;
    let (not_before, validity) = read_time(validity)?;
    let (not_after, _) = read_time(validity)?;

    // subject
    let (subject, _) = expect_tlv(data, TAG_SEQUENCE)?;

    Some(CertificateValidity {
        not_before,
        not_after,
        self_signed: issuer == subject,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes base64 contents of PEM file (test helper)
    fn pem_to_der(pem: &str) -> Vec<u8> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut der: Vec<u8> = Vec::new();
        let mut buffer: u32 = 0;
        let mut bits: u32 = 0;

        for line in pem.lines().filter(|line| !line.starts_with("-----")) {
            for byte in line.trim().bytes().filter(|&byte| byte != b'=') {
                let value = ALPHABET.iter().position(|&c| c == byte).unwrap() as u32;
                buffer = (buffer << 6) | value;
                bits += 6;

                if bits >= 8 {
                    bits -= 8;
                    der.push((buffer >> bits) as u8);
                    buffer &= (1 << bits) - 1;
                }
            }
        }

        der
    }

    #[test]
    fn days_since_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
        assert_eq!(days_from_civil(2024, 2, 29), 19782);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }

    #[test]
    fn utc_time() {
        assert_eq!(parse_time(TAG_UTC_TIME, b"700101000000Z"), Some(0));
        assert_eq!(parse_time(TAG_UTC_TIME, b"491231235959Z"), Some(2524607999));
        assert_eq!(parse_time(TAG_UTC_TIME, b"500101000000Z"), Some(-631152000));
    }

    #[test]
    fn generalized_time() {
        assert_eq!(
            parse_time(TAG_GENERALIZED_TIME, b"20500101000000Z"),
            Some(2524608000)
        );
        assert_eq!(
            parse_time(TAG_GENERALIZED_TIME, b"99991231235959Z"),
            Some(253402300799)
        );
    }

    #[test]
    fn malformed_time() {
        assert_eq!(parse_time(TAG_UTC_TIME, b"7001010000Z"), None);
        assert_eq!(parse_time(TAG_UTC_TIME, b"700101000000+"), None);
        assert_eq!(parse_time(TAG_UTC_TIME, b"701301000000Z"), None);
        assert_eq!(parse_time(TAG_UTC_TIME, b"7001010000a0Z"), None);
        assert_eq!(parse_time(TAG_GENERALIZED_TIME, b"700101000000Z"), None);
        assert_eq!(parse_time(TAG_SEQUENCE, b"700101000000Z"), None);
    }

    #[test]
    fn self_signed_certificate() {
        let der = pem_to_der(include_str!("../tests/data/self-signed.pem"));

        assert_eq!(
            certificate_validity(&der),
            Some(CertificateValidity {
                // 2026-01-01T00:00:00Z
                not_before: 1767225600,
                // 2026-04-01T12:30:45Z
                not_after: 1775046645,
                self_signed: true,
            })
        );
    }

    #[test]
    fn ca_signed_certificate() {
        let der = pem_to_der(include_str!("../tests/data/ca-signed.pem"));

        assert_eq!(
            certificate_validity(&der),
            Some(CertificateValidity {
                // 2025-06-15T08:00:00Z
                not_before: 1749974400,
                // 2026-06-15T08:00:00Z
                not_after: 1781510400,
                self_signed: false,
            })
        );
    }

    #[test]
    fn certificate_with_generalized_time() {
        let der = pem_to_der(include_str!("../tests/data/far-future.pem"));

        assert_eq!(
            certificate_validity(&der),
            Some(CertificateValidity {
                // 2026-01-01T00:00:00Z (UTCTime)
                not_before: 1767225600,
                // 2077-07-07T07:07:07Z (GeneralizedTime)
                not_after: 3392867227,
                self_signed: true,
            })
        );
    }

    #[test]
    fn garbage_is_not_a_certificate() {
        assert_eq!(certificate_validity(&[]), None);
        assert_eq!(certificate_validity(&[0x30]), None);
        assert_eq!(certificate_validity(&[0x30, 0x82, 0xFF, 0xFF, 0x00]), None);
        assert_eq!(certificate_validity(b"hello, world"), None);

        let der = pem_to_der(include_str!("../tests/data/self-signed.pem"));
        for length in 0..der.len() {
            assert_eq!(certificate_validity(&der[..length]), None);
        }
    }
}
