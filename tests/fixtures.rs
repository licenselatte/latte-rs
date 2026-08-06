//! Runs every shared fixture in `testdata/` against this crate's
//! verify/validate pipeline. See `latte-testvectors/README.md` for the
//! fixture schema and the `expect_reason` taxonomy this test asserts
//! against.

use ed25519_dalek::VerifyingKey;
use latte::domain::CertChain;
use latte::error::ValidateError;
use latte::validate::{in_grace_period, validate_at};
use latte::verify::verify_activation_at;
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

    Ok(())
}
