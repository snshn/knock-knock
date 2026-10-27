//! Obtains ENS (.eth) name expiration info from Ethereum, via JSON-RPC.

use chrono::{DateTime, Utc};
use reqwest::header::CONTENT_TYPE;
use serde_json::{Value, json};
use std::time::Duration;

use crate::keccak::{keccak256, to_hex};
use crate::{
    KnockKnockError, MAX_ATTEMPTS, RETRY_DELAY, Registration, RegistrationDetails, TIMEOUT_SECS,
    error_chain,
};

/// Used unless specified otherwise (note that it gets to see which names are being checked)
pub const DEFAULT_ETH_RPC_URL: &str = "https://ethereum-rpc.publicnode.com";

/// ENS BaseRegistrarImplementation contract on Ethereum mainnet, owner of the .eth TLD
const BASE_REGISTRAR_ADDRESS: &str = "0x57f1887a8bf19b14fc0df6fd9b2acc9af147ea85";

/// ENS NameWrapper contract on Ethereum mainnet, which owns wrapped names on behalf of their owners
const NAME_WRAPPER_ADDRESS: &str = "0xd4416b13d2b3a9abae7acd5d6c2bbdbe25686401";

/// ENS registry contract on Ethereum mainnet
const REGISTRY_ADDRESS: &str = "0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e";

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

/// Computes ENS namehash (EIP-137) of given name, e.g. "vitalik.eth"
pub fn namehash(name: &str) -> [u8; 32] {
    let mut node = [0u8; 32];

    for label in name.rsplit('.').filter(|label| !label.is_empty()) {
        let (unicode_label, _) = idna::domain_to_unicode(label);
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&node);
        data[32..].copy_from_slice(&keccak256(unicode_label.as_bytes()));
        node = keccak256(&data);
    }

    node
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

/// Encodes call of a function taking a single 32-byte argument
fn call_data(selector: &str, argument: &[u8; 32]) -> String {
    format!("0x{}{}", selector, to_hex(argument))
}

/// Applies EIP-55 mixed-case checksum to given lowercase hex address (without "0x")
pub fn checksum_address(address: &str) -> String {
    let hash: String = to_hex(&keccak256(address.as_bytes()));

    let checksummed: String = address
        .chars()
        .zip(hash.chars())
        .map(|(character, hash_character)| {
            if character.is_ascii_alphabetic() && hash_character.to_digit(16).unwrap_or(0) >= 8 {
                character.to_ascii_uppercase()
            } else {
                character
            }
        })
        .collect();

    format!("0x{}", checksummed)
}

/// Decodes address returned by a contract call (None for zero address)
pub fn decode_address(result: &str) -> Option<String> {
    let digits: &str = result.strip_prefix("0x")?;

    if digits.len() != 64 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    // Address is the last 20 bytes, the rest is padding
    let (padding, address) = digits.split_at(24);
    if !padding.chars().all(|c| c == '0') || address.chars().all(|c| c == '0') {
        return None;
    }

    Some(checksum_address(&address.to_ascii_lowercase()))
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
        details: Box::default(),
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

    /// Same as eth_call(), but retries on transient errors
    async fn eth_call_with_retries(&self, to: &str, data: &str) -> Result<String, KnockKnockError> {
        let mut attempt: u32 = 1;

        loop {
            match self.eth_call(to, data).await {
                Err(error) if error.is_transient() && attempt < MAX_ATTEMPTS => {
                    tokio::time::sleep(RETRY_DELAY * attempt).await;
                    attempt += 1;
                }
                result => return result,
            }
        }
    }

    /// Finds the actual owner of given .eth name, looking through NameWrapper for wrapped names
    async fn find_owner(&self, label_hash: &[u8; 32], node: &[u8; 32]) -> Option<String> {
        // First 4 bytes of keccak256("ownerOf(uint256)"), same for both contracts
        const OWNER_OF_SELECTOR: &str = "6352211e";

        // Reverts for expired names (even within grace period)
        let registrant: String = decode_address(
            &self
                .eth_call_with_retries(
                    BASE_REGISTRAR_ADDRESS,
                    &call_data(OWNER_OF_SELECTOR, label_hash),
                )
                .await
                .ok()?,
        )?;

        if !registrant.eq_ignore_ascii_case(NAME_WRAPPER_ADDRESS) {
            return Some(registrant);
        }

        // Wrapped names are owned by NameWrapper, which keeps track of their actual owners
        decode_address(
            &self
                .eth_call_with_retries(NAME_WRAPPER_ADDRESS, &call_data(OWNER_OF_SELECTOR, node))
                .await
                .ok()?,
        )
    }

    /// Finds resolver contract set for given name in ENS registry
    async fn find_resolver(&self, node: &[u8; 32]) -> Option<String> {
        // First 4 bytes of keccak256("resolver(bytes32)")
        const RESOLVER_SELECTOR: &str = "0178b8bf";

        decode_address(
            &self
                .eth_call_with_retries(REGISTRY_ADDRESS, &call_data(RESOLVER_SELECTOR, node))
                .await
                .ok()?,
        )
    }

    /// Looks up registration info for given .eth name (e.g. "vitalik.eth")
    pub async fn check(&self, ens_name: &str) -> Result<Registration, KnockKnockError> {
        let label: String = ens_label(ens_name).ok_or(KnockKnockError::InvalidDomainName)?;

        let result: String = self
            .eth_call_with_retries(BASE_REGISTRAR_ADDRESS, &name_expires_call_data(&label))
            .await?;
        let expires: i64 = decode_uint256(&result).ok_or(KnockKnockError::CouldntParseData)?;

        let mut registration: Registration = registration_from_expiry(expires, &Utc::now());

        // Owner and resolver are nice to have, failing to obtain them isn't an error
        if let Registration::Registered { details, .. } = &mut registration {
            let label_hash: [u8; 32] = keccak256(label.as_bytes());
            let node: [u8; 32] = namehash(ens_name);
            let (owner, resolver) = tokio::join!(
                self.find_owner(&label_hash, &node),
                self.find_resolver(&node)
            );

            **details = RegistrationDetails {
                owner,
                resolver,
                ..RegistrationDetails::default()
            };
        }

        Ok(registration)
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
    fn namehashes() {
        // EIP-137
        assert_eq!(to_hex(&namehash("")), "0".repeat(64));
        assert_eq!(
            to_hex(&namehash("eth")),
            "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
        );
        assert_eq!(
            to_hex(&namehash("foo.eth")),
            "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f"
        );
    }

    #[test]
    fn checksum_addresses() {
        // EIP-55
        for address in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            assert_eq!(
                checksum_address(&address[2..].to_ascii_lowercase()),
                address
            );
        }
    }

    #[test]
    fn decode_addresses() {
        assert_eq!(
            decode_address("0x000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045"),
            Some("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".to_string())
        );
        // Zero address means none
        assert_eq!(decode_address(&format!("0x{}", "0".repeat(64))), None);
        // Not an address
        assert_eq!(decode_address(&format!("0x1{}", "0".repeat(63))), None);
        assert_eq!(decode_address("0x"), None);
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
                details: Box::default(),
            }
        );

        // Expired, but still in grace period
        let expired: i64 = 2_000_000_000 - 10 * 24 * 60 * 60;
        assert_eq!(
            registration_from_expiry(expired, &now),
            Registration::Registered {
                expires: Some(at(expired)),
                grace_period_ends: Some(at(expired + GRACE_PERIOD_SECS)),
                details: Box::default(),
            }
        );

        // Grace period is over, available to anyone
        assert_eq!(
            registration_from_expiry(2_000_000_000 - GRACE_PERIOD_SECS, &now),
            Registration::NotRegistered
        );
    }
}
