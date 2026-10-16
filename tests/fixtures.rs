//! Runs every shared fixture in `testdata/` against this crate's
//! verify/validate pipeline. See `latte-testvectors/README.md` for the
//! fixture schema and the `expect_reason` taxonomy this test asserts
//! against.

use ed25519_dalek::VerifyingKey;
use latte_rs::domain::CertChain;
use latte_rs::error::ValidateError;
use latte_rs::storage;
use latte_rs::validate::{in_grace_period, validate_at};
use latte_rs::verify::{verify_activation_any_at, verify_activation_at};
use latte_rs::{check_license_at, PublicLicense, UNLIMITED};
use serde::Deserialize;
use std::fs;
use std::time::{Duration, SystemTime};

#[derive(Deserialize)]
struct ChainJson {
    submaster: String,
    project: String,
    daily: String,
}

#[derive(Deserialize)]
struct Fixture {
    name: String,
    now: String,
    master_public_key_hex: String,
    machine_id: String,
    token: String,
    chain: ChainJson,
    expect: String,
    expect_stage: String,
    expect_reason: String,
    expect_in_grace_period: bool,
    expect_has_entitlements: bool,
    expect_entitlements: serde_json::Map<String, serde_json::Value>,
}

fn parse_rfc3339(s: &str) -> SystemTime {
    // Fixtures are always "YYYY-MM-DDTHH:MM:SSZ" (generator emits UTC, zero
    // sub-second precision), so a tiny hand-rolled parser is enough and
    // keeps this test crate dependency-free beyond serde/serde_json.
    let b = s.as_bytes();
    assert_eq!(b[19], b'Z', "fixture 'now' must be UTC ('Z' suffix): {s}");
    let year: i64 = s[0..4].parse().unwrap();
    let month: i64 = s[5..7].parse().unwrap();
    let day: i64 = s[8..10].parse().unwrap();
    let hour: i64 = s[11..13].parse().unwrap();
    let min: i64 = s[14..16].parse().unwrap();
    let sec: i64 = s[17..19].parse().unwrap();

    // Days since epoch via the civil_from_days algorithm (Howard Hinnant).
    let days = days_from_civil(year, month, day);
    let total_secs = days * 86400 + hour * 3600 + min * 60 + sec;
    if total_secs >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_secs(total_secs as u64)
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_secs((-total_secs) as u64)
    }
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn reason_for(err: &ValidateError) -> &'static str {
    match err {
        ValidateError::HardExpired => "hard_expired",
        ValidateError::GraceExpired => "grace_expired",
        ValidateError::LicenseTooOld => "license_too_old",
        ValidateError::MachineIdMismatch => "machine_id_mismatch",
        ValidateError::InvalidFields(_) => "other",
    }
}

#[test]
fn fixtures() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/vectors");
    let mut ran = 0;
    let mut failures = Vec::new();

    for entry in fs::read_dir(dir).expect("read testdata dir") {
        let path = entry.unwrap().path();
        if path.file_name().unwrap() == "manifest.json" {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let data = fs::read_to_string(&path).unwrap();
        let f: Fixture = serde_json::from_str(&data).unwrap();
        ran += 1;

        if let Err(msg) = run_one(&f) {
            failures.push(format!("{}: {}", f.name, msg));
        }
    }

    assert!(
        ran > 15,
        "expected the full shared fixture set, only found {ran}"
    );
    assert!(
        failures.is_empty(),
        "fixture failures:\n{}",
        failures.join("\n")
    );
}

fn run_one(f: &Fixture) -> Result<(), String> {
    let now = parse_rfc3339(&f.now);
    let master_bytes = hex::decode(&f.master_public_key_hex).map_err(|e| e.to_string())?;
    let master_arr: [u8; 32] = master_bytes.try_into().map_err(|_| "bad master key len")?;
    let master_pub =
        VerifyingKey::from_bytes(&master_arr).map_err(|e| format!("bad master key: {e}"))?;

    let chain = CertChain {
        submaster: f.chain.submaster.clone(),
        project: f.chain.project.clone(),
        daily: f.chain.daily.clone(),
    };

    let license = match verify_activation_at(&master_pub, &f.token, &chain, now) {
        Err(_e) => {
            return if f.expect == "reject" && f.expect_stage == "verify" {
                Ok(())
            } else {
                Err(format!(
                    "unexpected verify-stage rejection (want expect={} stage={})",
                    f.expect, f.expect_stage
                ))
            };
        }
        Ok(l) => l,
    };
    if f.expect == "reject" && f.expect_stage == "verify" {
        return Err("expected verify-stage rejection but chain verification succeeded".into());
    }

    if let Err(e) = validate_at(&license, &f.machine_id, now) {
        if f.expect != "reject" || f.expect_stage != "validate" {
            return Err(format!(
                "unexpected validate-stage rejection: {e} (want expect={} stage={})",
                f.expect, f.expect_stage
            ));
        }
        let got = reason_for(&e);
        if got != f.expect_reason {
            return Err(format!(
                "reason mismatch: got {got}, want {} (err: {e})",
                f.expect_reason
            ));
        }
        return Ok(());
    }

    if f.expect != "accept" {
        return Err(format!(
            "expected rejection (stage={} reason={}) but verify+validate both succeeded",
            f.expect_stage, f.expect_reason
        ));
    }

    let in_grace = in_grace_period(&license, now);
    if in_grace != f.expect_in_grace_period {
        return Err(format!(
            "in_grace_period mismatch: got {in_grace}, want {}",
            f.expect_in_grace_period
        ));
    }

    // Through the public check_license_at rather than the decoder, so this
    // covers the wiring an application actually gets back, not just the
    // parsing. It re-runs verify+validate, which for an accepted fixture is
    // cheap and cannot fail.
    let public = check_license_at(&master_pub, &f.token, &chain, &f.machine_id, now)
        .map_err(|e| format!("check_license_at failed on an accepted fixture: {e}"))?;
    assert_entitlements(&public, f)?;

    Ok(())
}

/// Checks the shared entitlement contract from `latte-testvectors/README.md`
/// against one fixture.
///
/// It asserts the *accessors*, not just the map, because the map is the
/// easy half: the rules that actually split implementations are the ones
/// about input an SDK does not like — a malformed value that must be
/// dropped rather than errored on, and the two coercions (a falsy 0, a
/// boolean read as 1) that must miss rather than convert.
fn assert_entitlements(lic: &PublicLicense, f: &Fixture) -> Result<(), String> {
    if lic.has_entitlements() != f.expect_has_entitlements {
        return Err(format!(
            "has_entitlements mismatch: got {}, want {}",
            lic.has_entitlements(),
            f.expect_has_entitlements
        ));
    }

    let got_len = lic.entitlements.as_ref().map_or(0, |e| e.len());
    if got_len != f.expect_entitlements.len() {
        return Err(format!(
            "entitlements mismatch: got {:?}, want {:?}",
            lic.entitlements, f.expect_entitlements
        ));
    }

    for (key, want) in &f.expect_entitlements {
        match want {
            serde_json::Value::Bool(want) => {
                if lic.can(key) != *want {
                    return Err(format!("can({key:?}) = {}, want {want}", lic.can(key)));
                }
                // No coercion: a boolean is not 1 or 0.
                if let Some(got) = lic.limit(key) {
                    return Err(format!(
                        "limit({key:?}) = {got} on a boolean entitlement, want a miss"
                    ));
                }
            }
            serde_json::Value::Number(want) => {
                let want = want.as_i64().ok_or("non-integer in expect_entitlements")?;
                match lic.limit(key) {
                    None => return Err(format!("limit({key:?}) missed, want {want}")),
                    Some(got) if got != want => {
                        return Err(format!("limit({key:?}) = {got}, want {want}"))
                    }
                    Some(got) if want == UNLIMITED && got != UNLIMITED => {
                        return Err(format!(
                            "limit({key:?}) = {got}, want the UNLIMITED sentinel {UNLIMITED}"
                        ))
                    }
                    Some(_) => {}
                }
                // No coercion: an integer is not truthy, not even a non-zero one.
                if lic.can(key) {
                    return Err(format!(
                        "can({key:?}) = true on an integer entitlement, want false"
                    ));
                }
            }
            other => {
                return Err(format!(
                    "expect_entitlements[{key:?}] is {other}, but the format admits only bool and integer"
                ))
            }
        }
    }

    // Absence denies, whether or not the claim was there at all.
    if lic.can("no_such_entitlement_key") {
        return Err("can() on an unset key returned true; absence must deny".into());
    }
    if lic.limit("no_such_entitlement_key").is_some() {
        return Err("limit() on an unset key reported present; absence must deny".into());
    }

    Ok(())
}

fn parse_keys(hexes: &[String]) -> Vec<VerifyingKey> {
    hexes
        .iter()
        .map(|h| {
            let arr: [u8; 32] = hex::decode(h).unwrap().try_into().unwrap();
            VerifyingKey::from_bytes(&arr).unwrap()
        })
        .collect()
}

#[derive(Deserialize)]
struct AnchorCase {
    name: String,
    now: String,
    master_public_keys_hex: Vec<String>,
    machine_id: String,
    token: String,
    chain: ChainJson,
    expect: String,
    expect_stage: String,
}

#[derive(Deserialize)]
struct Anchors {
    cases: Vec<AnchorCase>,
}

/// testdata/anchors.json: a submaster cert signed by any one trusted root
/// verifies, one signed by a root outside the list does not.
#[test]
fn anchors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/anchors.json");
    let a: Anchors = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert!(!a.cases.is_empty());

    let mut failures = Vec::new();
    for c in &a.cases {
        let now = parse_rfc3339(&c.now);
        let chain = CertChain {
            submaster: c.chain.submaster.clone(),
            project: c.chain.project.clone(),
            daily: c.chain.daily.clone(),
        };
        let got = match verify_activation_any_at(
            &parse_keys(&c.master_public_keys_hex),
            &c.token,
            &chain,
            now,
        ) {
            Err(_) => ("reject", "verify"),
            Ok(lic) => match validate_at(&lic, &c.machine_id, now) {
                Err(_) => ("reject", "validate"),
                Ok(()) => ("accept", "none"),
            },
        };
        if got != (c.expect.as_str(), c.expect_stage.as_str()) {
            failures.push(format!(
                "{}: got {}/{}, want {}/{}",
                c.name, got.0, got.1, c.expect, c.expect_stage
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "anchor failures:\n{}",
        failures.join("\n")
    );
}

#[derive(Deserialize)]
struct CacheCase {
    name: String,
    contents: String,
}

#[derive(Deserialize)]
struct CacheFiles {
    now: String,
    master_public_keys_hex: Vec<String>,
    cases: Vec<CacheCase>,
}

/// testdata/cache_files.json: a cached token file this SDK cannot use must
/// come out as not activated, never as a panic.
#[test]
fn cache_files() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/cache_files.json");
    let cf: CacheFiles = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert!(!cf.cases.is_empty());
    let now = parse_rfc3339(&cf.now);
    let keys = parse_keys(&cf.master_public_keys_hex);
    let dir = tempfile::tempdir().unwrap();

    let mut failures = Vec::new();
    for c in &cf.cases {
        let file = dir.path().join(format!("{}.json", c.name));
        fs::write(&file, &c.contents).unwrap();
        let outcome = std::panic::catch_unwind(|| match storage::load(&file) {
            None => true,
            Some((token, chain)) => verify_activation_any_at(&keys, &token, &chain, now).is_err(),
        });
        match outcome {
            Ok(true) => {}
            Ok(false) => failures.push(format!(
                "{}: verified a cache file with no usable chain",
                c.name
            )),
            Err(_) => failures.push(format!("{}: panicked", c.name)),
        }
    }
    assert!(
        failures.is_empty(),
        "cache file failures:\n{}",
        failures.join("\n")
    );
}
