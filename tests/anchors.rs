//! Trusting several master keys: a chain is accepted when any one of them
//! signed its submaster cert, and rejected when none did.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use latte_rs::domain::CertChain;
use latte_rs::verify::{
    master_public_keys, verify_activation_any_at, verify_activation_at, MASTER_PUBLIC_KEYS_HEX,
};
use serde_json::{json, Value};
use std::time::{Duration, SystemTime};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sign(signer: &SigningKey, mut claims: Value) -> String {
    claims["iss"] = json!("licenselatte");
    let input = format!(
        "{}.{}",
        B64.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#),
        B64.encode(claims.to_string())
    );
    let sig = signer.sign(input.as_bytes());
    format!("{input}.{}", B64.encode(sig.to_bytes()))
}

fn hex_pub(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().to_bytes())
}

const NOW: u64 = 1_791_400_000;

/// A chain whose submaster cert is signed by `master`, verified at `NOW`.
fn chain_signed_by(master: &SigningKey) -> (String, CertChain) {
    let (submaster, project, daily) = (key(10), key(11), key(12));
    let cert = |signer: &SigningKey, claims: Value| {
        let mut claims = claims;
        claims["iat"] = json!(NOW - 3600);
        claims["exp"] = json!(NOW + 3600);
        sign(signer, claims)
    };
    let chain = CertChain {
        submaster: cert(
            master,
            json!({"sub": "submaster", "spk": hex_pub(&submaster)}),
        ),
        project: cert(
            &submaster,
            json!({"sub": "project", "pid": "p", "ppk": hex_pub(&project)}),
        ),
        daily: cert(
            &project,
            json!({"sub": "daily", "pid": "p", "dpk": hex_pub(&daily)}),
        ),
    };
    let token = sign(
        &daily,
        json!({"sub": "KEY", "aid": "a", "pid": "p", "mid": "m", "ltype": "perpetual",
               "iat": NOW - 60, "exp": NOW + 86_400, "grc": 86_400}),
    );
    (token, chain)
}

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(NOW)
}

#[test]
fn a_chain_signed_by_any_trusted_master_verifies() {
    let masters = [key(1), key(2), key(3)];
    let trusted: Vec<VerifyingKey> = masters.iter().map(SigningKey::verifying_key).collect();
    for master in &masters {
        let (token, chain) = chain_signed_by(master);
        let lic = verify_activation_any_at(&trusted, &token, &chain, now())
            .unwrap_or_else(|e| panic!("chain signed by a trusted master was rejected: {e}"));
        assert_eq!(lic.key, "KEY");
    }
}

#[test]
fn a_chain_signed_by_an_untrusted_master_is_rejected() {
    let trusted: Vec<VerifyingKey> = [key(1), key(2), key(3)]
        .iter()
        .map(SigningKey::verifying_key)
        .collect();
    let (token, chain) = chain_signed_by(&key(9));
    assert!(verify_activation_any_at(&trusted, &token, &chain, now()).is_err());
    assert!(verify_activation_any_at(&[], &token, &chain, now()).is_err());
}

#[test]
fn the_single_key_form_still_verifies() {
    let master = key(1);
    let (token, chain) = chain_signed_by(&master);
    assert!(verify_activation_at(&master.verifying_key(), &token, &chain, now()).is_ok());
    assert!(verify_activation_at(&key(2).verifying_key(), &token, &chain, now()).is_err());
}

#[test]
fn every_embedded_master_key_is_a_valid_ed25519_key() {
    let keys = master_public_keys();
    assert_eq!(keys.len(), MASTER_PUBLIC_KEYS_HEX.len());
    for (hex_key, k) in MASTER_PUBLIC_KEYS_HEX.iter().zip(&keys) {
        assert_eq!(hex::encode(k.to_bytes()), *hex_key);
    }
}
