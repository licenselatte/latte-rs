//! Minimal EdDSA/Ed25519 JWT compact-serialization handling.
//!
//! This is intentionally narrow: the certificate chain uses exactly one JWA
//! algorithm (`"EdDSA"`, RFC 8037, pure Ed25519, never prehashed
//! HashEdDSA), one serialization (compact, not JWS-JSON), and a fixed set
//! of claims per JWT "kind". There is no reason to depend on a general JWT
//! library for four call sites; the only cryptographic primitive used is
//! `ed25519_dalek`'s signature verification (audited, not hand-rolled).

use crate::error::VerifyError;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use std::time::SystemTime;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub struct ParsedJwt {
    pub claims: Map<String, Value>,
}

/// Parses and Ed25519-verifies a compact JWT against `pub_key`, then
/// validates `iss` and, with **zero leeway**, `iat`/`exp`/`nbf` if present.
///
/// This zero-leeway behavior applies to the submaster/project/daily
/// certs, which get no clock-skew tolerance at all. The activation token
/// itself is parsed by a separate function
/// (`parse_and_verify_with_infinite_leeway`), which applies an
/// effectively-infinite leeway there instead.
pub fn parse_and_verify(
    token: &str,
    pub_key: &VerifyingKey,
    expected_issuer: &str,
    now: SystemTime,
) -> Result<ParsedJwt, VerifyError> {
    parse_and_verify_inner(token, pub_key, expected_issuer, now, 0)
}

/// Same as `parse_and_verify`, but `iat`/`exp`/`nbf` checks are skipped
/// entirely (`leeway_secs` effectively infinite). Used for the
/// activation-JWT parse specifically so the hand-rolled grace-period math
/// (see `validate.rs`) is the sole authority on expiry for that JWT.
pub fn parse_and_verify_with_infinite_leeway(
    token: &str,
    pub_key: &VerifyingKey,
    expected_issuer: &str,
) -> Result<ParsedJwt, VerifyError> {
    parse_and_verify_inner(
        token,
        pub_key,
        expected_issuer,
        SystemTime::UNIX_EPOCH,
        u64::MAX,
    )
}

fn parse_and_verify_inner(
    token: &str,
    pub_key: &VerifyingKey,
    expected_issuer: &str,
    now: SystemTime,
    leeway_secs: u64,
) -> Result<ParsedJwt, VerifyError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(VerifyError::Malformed(format!(
            "expected 3 dot-separated parts, got {}",
            parts.len()
        )));
    }
    let [header_b64, payload_b64, sig_b64] = [parts[0], parts[1], parts[2]];

    let header_bytes = B64
        .decode(header_b64)
        .map_err(|e| VerifyError::Malformed(format!("header base64: {e}")))?;
    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| VerifyError::Malformed(format!("header json: {e}")))?;
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
    if alg != "EdDSA" {
        return Err(VerifyError::Malformed(format!("unexpected alg: {alg}")));
    }

    let payload_bytes = B64
        .decode(payload_b64)
        .map_err(|e| VerifyError::Malformed(format!("payload base64: {e}")))?;
    let claims: Map<String, Value> = serde_json::from_slice::<Value>(&payload_bytes)
        .map_err(|e| VerifyError::Malformed(format!("payload json: {e}")))?
        .as_object()
        .cloned()
        .ok_or_else(|| VerifyError::Malformed("payload is not a JSON object".into()))?;

    let sig_bytes = B64
        .decode(sig_b64)
        .map_err(|e| VerifyError::Malformed(format!("signature base64: {e}")))?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| VerifyError::Malformed("signature is not 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_bytes);

    let signing_input = format!("{header_b64}.{payload_b64}");
    pub_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| VerifyError::InvalidSignature)?;

    let iss = claims.get("iss").and_then(Value::as_str).unwrap_or("");
    if iss != expected_issuer {
        return Err(VerifyError::WrongIssuer);
    }

    if leeway_secs != u64::MAX {
        check_time_claims(&claims, now, leeway_secs)?;
    }

    Ok(ParsedJwt { claims })
}

fn check_time_claims(
    claims: &Map<String, Value>,
    now: SystemTime,
    leeway_secs: u64,
) -> Result<(), VerifyError> {
    let now_unix = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let leeway = leeway_secs as i64;

    if let Some(iat) = claim_as_i64(claims, "iat") {
        if iat > now_unix + leeway {
            return Err(VerifyError::NotYetValid);
        }
    }
    if let Some(nbf) = claim_as_i64(claims, "nbf") {
        if nbf > now_unix + leeway {
            return Err(VerifyError::NotYetValid);
        }
    }
    if let Some(exp) = claim_as_i64(claims, "exp") {
        if exp < now_unix - leeway {
            return Err(VerifyError::Expired);
        }
    }
    Ok(())
}

fn claim_as_i64(claims: &Map<String, Value>, key: &str) -> Option<i64> {
    claims.get(key).and_then(Value::as_f64).map(|f| f as i64)
}

pub fn claim_str<'a>(claims: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    claims.get(key).and_then(Value::as_str)
}

pub fn claim_i64(claims: &Map<String, Value>, key: &str) -> Option<i64> {
    claim_as_i64(claims, key)
}
