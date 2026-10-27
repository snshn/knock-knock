//! Obtains ENS (.eth) name expiration info from Ethereum, via JSON-RPC.

use chrono::{DateTime, Utc};
use reqwest::header::CONTENT_TYPE;
use serde_json::{Value, json};
use std::time::Duration;

use crate::keccak::{keccak256, to_hex};
use crate::{KnockKnockError, MAX_ATTEMPTS, RETRY_DELAY, Registration, TIMEOUT_SECS, error_chain};

/// Used unless specified otherwise (note that it gets to see which names are being checked)
pub const DEFAULT_ETH_RPC_URL: &str = "https://ethereum-rpc.publicnode.com";

/// ENS BaseRegistrarImplementation contract on Ethereum mainnet, owner of the .eth TLD
const BASE_REGISTRAR_ADDRESS: &str = "0x57f1887a8bf19b14fc0df6fd9b2acc9af147ea85";

/// After expiration, only the owner can renew the name during this period
pub const GRACE_PERIOD_SECS: i64 = 90 * 24 * 60 * 60;

/// Whether given (lowercase ASCII) host name is an ENS name
pub fn is_ens_name(host: &str) -> bool {
    host.ends_with(".eth")
}

/// Finds .eth name that controls given host, e.g. "pay.vitalik.eth" -> "vitalik.eth"
pub fn registrable_ens_name(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.split('.').collect();

    if labels.len() < 2 || labels[labels.len() - 1] != "eth" {
        return None;
    }

    Some(labels[labels.len() - 2..].join("."))
}

/// Label that gets hashed into the token ID of given .eth name, e.g. "vitalik.eth" -> "vitalik".
/// ENS hashes labels in their (normalized) Unicode form, not Punycode.
pub fn ens_label(ens_name: &str) -> Option<String> {
    let label: &str = ens_name.strip_suffix(".eth")?;

    if label.is_empty() || label.contains('.') {
        return None;
    }

    let (unicode_label, result) = idna::domain_to_unicode(label);
    result.ok()?;

    Some(unicode_label)
}

/// Encodes call of nameExpires(uint256 id), where id = keccak256(label)
pub fn name_expires_call_data(label: &str) -> String {
    // First 4 bytes of keccak256("nameExpires(uint256)")
    const NAME_EXPIRES_SELECTOR: &str = "d6e4fa86";

    format!(
        "0x{}{}",
        NAME_EXPIRES_SELECTOR,
        to_hex(&keccak256(label.as_bytes()))
    )
}

/// Decodes uint256 returned by a contract call (as hex string), if it fits into i64
pub fn decode_uint256(result: &str) -> Option<i64> {
    let digits: &str = result.strip_prefix("0x")?;

    if digits.len() != 64 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    // Anything beyond last 16 hex digits must be zero
    let (high, low) = digits.split_at(48);
    if !high.chars().all(|c| c == '0') {
        return None;
    }

    i64::try_from(u64::from_str_radix(low, 16).ok()?).ok()
}

/// Turns expiration timestamp from the registrar into registration info
pub fn registration_from_expiry(expires: i64, now: &DateTime<Utc>) -> Registration {
    // Zero means the name has never been registered
    let expires: DateTime<Utc> = match DateTime::from_timestamp(expires, 0) {
        Some(expires) if expires.timestamp() > 0 => expires,
        _ => return Registration::NotRegistered,
    };
    let grace_period_ends: DateTime<Utc> = expires + chrono::Duration::seconds(GRACE_PERIOD_SECS);

    // Once grace period is over, the name is available for anyone to register
    if grace_period_ends <= *now {
        return Registration::NotRegistered;
    }

    Registration::Registered {
        expires: Some(expires),
        grace_period_ends: Some(grace_period_ends),
    }
}

/// Looks up .eth name registration info via an Ethereum JSON-RPC endpoint
pub struct EnsChecker {
    client: reqwest::Client,
    rpc_url: String,
}

impl EnsChecker {
    pub fn new(rpc_url: &str) -> Result<EnsChecker, KnockKnockError> {
        let client: reqwest::Client = reqwest::Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .user_agent(format!(
                "{}/{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(|error| KnockKnockError::ClientProblem(error_chain(&error)))?;

        Ok(EnsChecker {
            client,
            rpc_url: rpc_url.to_string(),
        })
    }

    /// Performs read-only contract call (eth_call), returns raw result
    async fn eth_call(&self, to: &str, data: &str) -> Result<String, KnockKnockError> {
        let request: Value = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{ "to": to, "data": data }, "latest"],
        });

        let response = self
            .client
            .post(&self.rpc_url)
            .header(CONTENT_TYPE, "application/json")
            .body(request.to_string())
            .send()
            .await
            .map_err(|error| KnockKnockError::EthRpcUnreachable(error_chain(&error)))?;

        let status: u16 = response.status().as_u16();
        let body: String = response
            .text()
            .await
            .map_err(|error| KnockKnockError::EthRpcUnreachable(error_chain(&error)))?;

        if status != 200 {
            return Err(KnockKnockError::EthRpcHttpStatus(status));
        }

        let response: Value =
            serde_json::from_str(&body).map_err(|_| KnockKnockError::CouldntParseData)?;

        if let Some(error) = response.get("error") {
            let message: String = error
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| error.to_string());

            return Err(KnockKnockError::EthRpcError(message));
        }

        response
            .get("result")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or(KnockKnockError::CouldntParseData)
    }

    /// Looks up registration info for given .eth name (e.g. "vitalik.eth")
    pub async fn check(&self, ens_name: &str) -> Result<Registration, KnockKnockError> {
        let label: String = ens_label(ens_name).ok_or(KnockKnockError::InvalidDomainName)?;
        let call_data: String = name_expires_call_data(&label);

        let mut attempt: u32 = 1;
        let result: String = loop {
            match self.eth_call(BASE_REGISTRAR_ADDRESS, &call_data).await {
                Ok(result) => break result,
                Err(error) if error.is_transient() && attempt < MAX_ATTEMPTS => {
                    tokio::time::sleep(RETRY_DELAY * attempt).await;
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        };

        let expires: i64 = decode_uint256(&result).ok_or(KnockKnockError::CouldntParseData)?;

        Ok(registration_from_expiry(expires, &Utc::now()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ens_names() {
        assert!(is_ens_name("vitalik.eth"));
        assert!(is_ens_name("pay.vitalik.eth"));
        assert!(!is_ens_name("eth"));
        assert!(!is_ens_name("ethereum.org"));
        assert!(!is_ens_name("vitalik.eth.limo"));
    }

    #[test]
    fn registrable_ens_names() {
        assert_eq!(
            registrable_ens_name("vitalik.eth"),
            Some("vitalik.eth".to_string())
        );
        assert_eq!(
            registrable_ens_name("pay.vitalik.eth"),
            Some("vitalik.eth".to_string())
        );
        assert_eq!(registrable_ens_name("eth"), None);
        assert_eq!(registrable_ens_name("example.com"), None);
    }

    #[test]
    fn call_data() {
        assert_eq!(
            name_expires_call_data("vitalik"),
            "0xd6e4fa86af2caa1c2ca1d027f1ac823b529d0a67cd144264b2789fa2ea4d63a67c7103cc"
        );
    }

    #[test]
    fn decode_uint256_values() {
        assert_eq!(decode_uint256(&format!("0x{}", "0".repeat(64))), Some(0));
        assert_eq!(
            decode_uint256("0x000000000000000000000000000000000000000000000000000000007a8d3d80"),
            Some(2056076672)
        );
        // Too large for a timestamp
        assert_eq!(decode_uint256(&format!("0x1{}", "0".repeat(63))), None);
        // Malformed
        assert_eq!(decode_uint256("0x"), None);
        assert_eq!(decode_uint256("1234"), None);
        assert_eq!(decode_uint256(&format!("0x{}", "g".repeat(64))), None);
    }

    #[test]
    fn registration_states() {
        let now: DateTime<Utc> = DateTime::from_timestamp(2_000_000_000, 0).unwrap();
        let at = |timestamp: i64| DateTime::from_timestamp(timestamp, 0).unwrap();

        // Never registered
        assert_eq!(
            registration_from_expiry(0, &now),
            Registration::NotRegistered
        );

        // Registered
        assert_eq!(
            registration_from_expiry(2_100_000_000, &now),
            Registration::Registered {
                expires: Some(at(2_100_000_000)),
                grace_period_ends: Some(at(2_100_000_000 + GRACE_PERIOD_SECS)),
            }
        );

        // Expired, but still in grace period
        let expired: i64 = 2_000_000_000 - 10 * 24 * 60 * 60;
        assert_eq!(
            registration_from_expiry(expired, &now),
            Registration::Registered {
                expires: Some(at(expired)),
                grace_period_ends: Some(at(expired + GRACE_PERIOD_SECS)),
            }
        );

        // Grace period is over, available to anyone
        assert_eq!(
            registration_from_expiry(2_000_000_000 - GRACE_PERIOD_SECS, &now),
            Registration::NotRegistered
        );
    }
}
