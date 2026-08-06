//! Certificate chain verification: Master -> Submaster -> Project -> Daily
//! -> activation token, including the cross-checks between links. One of
//! those cross-checks has a known quirk (see the comment at that check
//! below); read it before "fixing" it.

use crate::domain::{CertChain, License, LicenseType};
use crate::error::VerifyError;
use crate::jwt::{claim_i64, claim_str, parse_and_verify, parse_and_verify_with_infinite_leeway};
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

const ISSUER: &str = "licenselatte";
const MAX_GRACE_PERIOD: Duration = Duration::from_secs(90 * 24 * 60 * 60);

fn pub_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, VerifyError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| VerifyError::InvalidClaim("pubkey", "must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| VerifyError::InvalidClaim("pubkey", e.to_string()))
}

fn pub_key_from_cert(
    claims: &serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<VerifyingKey, VerifyError> {
    let hex_str = claim_str(claims, field).ok_or(VerifyError::MissingClaim(field))?;
    let bytes = hex::decode(hex_str)
        .map_err(|e| VerifyError::InvalidClaim(field, format!("not valid hex: {e}")))?;
    pub_key_from_bytes(&bytes)
}

fn unix_to_system_time(secs: i64) -> SystemTime {
    if secs >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs as u64)
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_secs((-secs) as u64)
    }
}

/// Verifies the full chain and the activation token, evaluating time-based
/// claims as of `now`. Production callers should pass `SystemTime::now()`;
/// tests pass a fixture's pinned `now` so results are reproducible (see
/// `latte-testvectors/README.md`).
pub fn verify_activation_at(
    master_pub: &VerifyingKey,
    token: &str,
    chain: &CertChain,
    now: SystemTime,
) -> Result<License, VerifyError> {
    // Step 1: submaster cert, signed by master.
    let sub = parse_and_verify(&chain.submaster, master_pub, ISSUER, now)?;
    let submaster_pub = pub_key_from_cert(&sub.claims, "spk")?;

    // Step 2: project cert, signed by submaster.
    let proj = parse_and_verify(&chain.project, &submaster_pub, ISSUER, now)?;
    let project_pub = pub_key_from_cert(&proj.claims, "ppk")?;

    // Step 3: daily cert, signed by project key.
    let daily = parse_and_verify(&chain.daily, &project_pub, ISSUER, now)?;
    let daily_pub = pub_key_from_cert(&daily.claims, "dpk")?;

    // Step 4: activation JWT, signed by the daily key. Verification applies
    // effectively-infinite leeway here; the activation's own iat/exp/nbf are
    // not authoritative, the grace-period math in validate.rs is.
    let activation = parse_and_verify_with_infinite_leeway(token, &daily_pub, ISSUER)?;
    let claims = &activation.claims;

    let key = claim_str(claims, "sub").unwrap_or("").to_string();
    let activation_id = claim_str(claims, "aid").unwrap_or("").to_string();
    let project_id = claim_str(claims, "pid").unwrap_or("").to_string();
    let machine_id = claim_str(claims, "mid").unwrap_or("").to_string();
    let license_type = LicenseType::from_claim(claim_str(claims, "ltype").unwrap_or(""));

    let grc = claim_i64(claims, "grc").unwrap_or(0);
    let grace_period = Duration::from_secs(grc.max(0) as u64);
    let iat = claim_i64(claims, "iat")
        .map(unix_to_system_time)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let exp = claim_i64(claims, "exp")
        .map(unix_to_system_time)
        .unwrap_or(SystemTime::UNIX_EPOCH);

    let mut metadata = HashMap::new();
    if let Some(pmd) = claims.get("pmd").and_then(|v| v.as_object()) {
        for (k, v) in pmd {
            if let Some(s) = v.as_str() {
                metadata.insert(k.clone(), s.to_string());
            }
        }
    }

    // Cross-check: project cert's own pid (if present) must agree with the
    // activation JWT's pid.
    if let Some(pid_in_cert) = claim_str(&proj.claims, "pid") {
        if !pid_in_cert.is_empty() && pid_in_cert != project_id {
            return Err(VerifyError::ChainInconsistent(format!(
                "project_id mismatch between activation JWT ({project_id}) and project cert ({pid_in_cert})"
            )));
        }
    }

    // Daily cert's iat/exp are required (not just optional claims).
    let daily_iat = claim_i64(&daily.claims, "iat")
        .map(unix_to_system_time)
        .ok_or(VerifyError::MissingClaim("iat"))?;
    let daily_exp = claim_i64(&daily.claims, "exp")
        .map(unix_to_system_time)
        .ok_or(VerifyError::MissingClaim("exp"))?;

    // Cross-check: activation iat must not precede the daily cert's own iat
    // (an activation can't have been issued before its signer existed).
    if iat < daily_iat {
        return Err(VerifyError::ChainInconsistent(
            "activation JWT iat is before daily cert iat".into(),
        ));
    }

    // Cross-check intended to ensure the activation doesn't outlive the
    // daily cert that signed it. This compares the activation's iat against
    // the daily cert's exp, not the activation's own exp as the error
    // message below might suggest. That's deliberate: do not change this to
    // compare `exp` without explicit sign-off, since it changes accept/reject
    // outcomes for existing licenses.
    if iat > daily_exp {
        return Err(VerifyError::ChainInconsistent(
            "activation JWT iat is after daily cert exp".into(),
        ));
    }

    // Grace period ceiling: no lower bound is enforced anywhere.
    if grace_period > MAX_GRACE_PERIOD {
        return Err(VerifyError::ChainInconsistent(format!(
            "grace period too long: {grace_period:?}"
        )));
    }

    Ok(License {
        key,
        activation_id,
        project_id,
        machine_id,
        issued_at: iat,
        expires_at: exp,
        grace_period,
        license_type,
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn sign_jwt(key: &SigningKey, claims: serde_json::Value) -> String {
        let header = B64.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = B64.encode(claims.to_string());
        let signing_input = format!("{header}.{payload}");
        let sig = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", B64.encode(sig.to_bytes()))
    }

    struct TestChain {
        master: SigningKey,
        project: SigningKey,
        daily: SigningKey,
        chain: CertChain,
    }

    fn build_chain(now: i64) -> TestChain {
        let master = random_signing_key();
        let submaster = random_signing_key();
        let project = random_signing_key();
        let daily = random_signing_key();

        let submaster_cert = sign_jwt(
            &master,
            json!({"iss": ISSUER, "iat": now - 1_000_000, "exp": now + 1_000_000, "spk": hex::encode(submaster.verifying_key().to_bytes())}),
        );
        let project_cert = sign_jwt(
            &submaster,
            json!({"iss": ISSUER, "iat": now - 500_000, "exp": now + 500_000, "ppk": hex::encode(project.verifying_key().to_bytes()), "pid": "proj_1"}),
        );
        let daily_cert = sign_jwt(
            &project,
            json!({"iss": ISSUER, "iat": now - 86_400, "exp": now + 86_400, "dpk": hex::encode(daily.verifying_key().to_bytes())}),
        );

        TestChain {
            master,
            project,
            daily,
            chain: CertChain {
                submaster: submaster_cert,
                project: project_cert,
                daily: daily_cert,
            },
        }
    }

    // Test-only key generation: pull 32 random bytes from the OS CSPRNG via
    // `getrandom` (already a transitive dependency of ed25519-dalek) rather
    // than depending on the `rand` crate just for this.
    fn random_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("OS RNG");
        SigningKey::from_bytes(&seed)
    }

    fn activation_claims(now: i64) -> serde_json::Value {
        json!({
            "iss": ISSUER, "sub": "KEY", "aid": "ACT1", "pid": "proj_1", "mid": "machine-1",
            "ltype": "expiring", "iat": now, "exp": now + 1_000_000, "grc": 7 * 86_400,
        })
    }

    #[test]
    fn valid_chain_and_signature_is_accepted() {
        let now = 10_000_000;
        let tc = build_chain(now);
        let token = sign_jwt(&tc.daily, activation_claims(now));
        let now_t = SystemTime::UNIX_EPOCH + Duration::from_secs(now as u64);
        let lic = verify_activation_at(&tc.master.verifying_key(), &token, &tc.chain, now_t)
            .expect("valid chain should verify");
        assert_eq!(lic.key, "KEY");
        assert_eq!(lic.project_id, "proj_1");
    }

    #[test]
    fn tampered_activation_signature_is_rejected() {
        let now = 10_000_000;
        let tc = build_chain(now);
        let mut token = sign_jwt(&tc.daily, activation_claims(now));
        token.push('x'); // corrupt the trailing signature bytes
        let now_t = SystemTime::UNIX_EPOCH + Duration::from_secs(now as u64);
        let err =
            verify_activation_at(&tc.master.verifying_key(), &token, &tc.chain, now_t).unwrap_err();
        assert!(matches!(
            err,
            VerifyError::Malformed(_) | VerifyError::InvalidSignature
        ));
    }

    #[test]
    fn wrong_master_key_is_rejected() {
        let now = 10_000_000;
        let tc = build_chain(now);
        let token = sign_jwt(&tc.daily, activation_claims(now));
        let wrong_master = random_signing_key();
        let now_t = SystemTime::UNIX_EPOCH + Duration::from_secs(now as u64);
        let err = verify_activation_at(&wrong_master.verifying_key(), &token, &tc.chain, now_t)
            .unwrap_err();
        assert!(matches!(err, VerifyError::InvalidSignature));
    }

    #[test]
    fn broken_intermediate_link_is_rejected() {
        let now = 10_000_000;
        let mut tc = build_chain(now);
        // Re-sign the project cert with a rogue key instead of the real submaster.
        let rogue = random_signing_key();
        tc.chain.project = sign_jwt(
            &rogue,
            json!({"iss": ISSUER, "iat": now - 500_000, "exp": now + 500_000, "ppk": hex::encode(tc.project.verifying_key().to_bytes()), "pid": "proj_1"}),
        );
        let token = sign_jwt(&tc.daily, activation_claims(now));
        let now_t = SystemTime::UNIX_EPOCH + Duration::from_secs(now as u64);
        let err =
            verify_activation_at(&tc.master.verifying_key(), &token, &tc.chain, now_t).unwrap_err();
        assert!(matches!(err, VerifyError::InvalidSignature));
    }

    #[test]
    fn project_id_cross_check_is_enforced() {
        let now = 10_000_000;
        let tc = build_chain(now);
        let mut claims = activation_claims(now);
        claims["pid"] = json!("some-other-project");
        let token = sign_jwt(&tc.daily, claims);
        let now_t = SystemTime::UNIX_EPOCH + Duration::from_secs(now as u64);
        let err =
            verify_activation_at(&tc.master.verifying_key(), &token, &tc.chain, now_t).unwrap_err();
        assert!(matches!(err, VerifyError::ChainInconsistent(_)));
    }

    #[test]
    fn daily_cert_missing_exp_is_rejected() {
        let now = 10_000_000;
        let mut tc = build_chain(now);
        tc.chain.daily = sign_jwt(
            &tc.project,
            json!({"iss": ISSUER, "iat": now - 86_400, "dpk": hex::encode(tc.daily.verifying_key().to_bytes())}),
        );
        let token = sign_jwt(&tc.daily, activation_claims(now));
        let now_t = SystemTime::UNIX_EPOCH + Duration::from_secs(now as u64);
        let err =
            verify_activation_at(&tc.master.verifying_key(), &token, &tc.chain, now_t).unwrap_err();
        assert!(matches!(err, VerifyError::MissingClaim("exp")));
    }

    #[test]
    fn cert_iat_in_future_is_rejected_with_zero_leeway() {
        let now = 10_000_000;
        let tc = build_chain(now);
        let token = sign_jwt(&tc.daily, activation_claims(now));
        // Verifier's clock is set before the daily cert's own iat (now - 86_400).
        let skewed_now = SystemTime::UNIX_EPOCH + Duration::from_secs((now - 86_400 - 10) as u64);
        let err = verify_activation_at(&tc.master.verifying_key(), &token, &tc.chain, skewed_now)
            .unwrap_err();
        assert!(matches!(err, VerifyError::NotYetValid));
    }

    #[test]
    fn activation_future_iat_is_tolerated_by_infinite_leeway() {
        let now = 10_000_000;
        let tc = build_chain(now);
        let mut claims = activation_claims(now);
        claims["iat"] = json!(now + 3600); // 1h in the future relative to `now_t` below
        let token = sign_jwt(&tc.daily, claims);
        let now_t = SystemTime::UNIX_EPOCH + Duration::from_secs(now as u64);
        // Chain (cert) validity windows comfortably cover `now_t`; only the
        // activation JWT's own iat is "in the future", which is tolerated
        // via an effectively infinite leeway.
        assert!(verify_activation_at(&tc.master.verifying_key(), &token, &tc.chain, now_t).is_ok());
    }

    #[test]
    fn grace_period_exceeding_90_day_ceiling_is_rejected() {
        let now = 10_000_000;
        let tc = build_chain(now);
        let mut claims = activation_claims(now);
        claims["grc"] = json!(91 * 86_400);
        let token = sign_jwt(&tc.daily, claims);
        let now_t = SystemTime::UNIX_EPOCH + Duration::from_secs(now as u64);
        let err =
            verify_activation_at(&tc.master.verifying_key(), &token, &tc.chain, now_t).unwrap_err();
        assert!(matches!(err, VerifyError::ChainInconsistent(_)));
    }

    #[test]
    fn malformed_token_is_rejected() {
        let now = 10_000_000;
        let tc = build_chain(now);
        let now_t = SystemTime::UNIX_EPOCH + Duration::from_secs(now as u64);
        let err = verify_activation_at(&tc.master.verifying_key(), "not-a-jwt", &tc.chain, now_t)
            .unwrap_err();
        assert!(matches!(err, VerifyError::Malformed(_)));
    }
}
