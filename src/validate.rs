//! Grace-period / offline validation, including boundary semantics (`>`,
//! never `>=`) and the independent 365-day `LicenseTooOld` ceiling that has
//! nothing to do with `grace_period`.

use crate::domain::License;
use crate::error::ValidateError;
use std::time::{Duration, SystemTime};

const MAX_AGE: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// Validates `license` against `machine_id`, evaluating grace-period and
/// expiry math as of `now`. Production callers should pass
/// `SystemTime::now()`; tests pass a fixture's pinned `now`.
pub fn validate_at(
    license: &License,
    machine_id: &str,
    now: SystemTime,
) -> Result<(), ValidateError> {
    if license.issued_at == SystemTime::UNIX_EPOCH {
        return Err(ValidateError::InvalidFields("issued_at is zero".into()));
    }
    if license.expires_at == SystemTime::UNIX_EPOCH {
        return Err(ValidateError::InvalidFields("expires_at is zero".into()));
    }
    if license.grace_period.is_zero() {
        return Err(ValidateError::InvalidFields(
            "grace_period is zero or negative".into(),
        ));
    }
    if license.machine_id != machine_id {
        return Err(ValidateError::MachineIdMismatch);
    }
    if license.expires_at < license.issued_at {
        return Err(ValidateError::InvalidFields(
            "expires_at is before issued_at".into(),
        ));
    }

    // perpetual_fixed tokens never expire and have no grace-period check,
    // but the four preconditions above still apply unconditionally,
    // including grace_period > 0, even though it's otherwise unused for
    // this type: the checks run before the branch on LicenseType.
    if license.license_type.is_perpetual_fixed() {
        return if now > license.expires_at {
            Err(ValidateError::HardExpired)
        } else {
            Ok(())
        };
    }

    let offline_deadline = license.issued_at + license.grace_period;

    if now > license.expires_at {
        return Err(ValidateError::HardExpired);
    }
    if now > offline_deadline {
        return Err(ValidateError::GraceExpired);
    }
    if now
        .duration_since(license.issued_at)
        .unwrap_or(Duration::ZERO)
        > MAX_AGE
    {
        return Err(ValidateError::LicenseTooOld);
    }

    Ok(())
}

/// `in_grace_period`: true once more than 60 minutes have passed since
/// `issued_at` without a renewal, while still inside the grace window
/// measured from that same `issued_at`. This is **not** "is the license in
/// its grace period"; despite the name, it's a softer, earlier warning
/// signal, distinct from the hard grace-deadline check in `validate_at`.
pub fn in_grace_period(license: &License, now: SystemTime) -> bool {
    const MAX_RENEWAL_TIME: Duration = Duration::from_secs(60 * 60);
    let since_activation = match now.duration_since(license.issued_at) {
        Ok(d) => d,
        Err(_) => return false, // now is before issued_at
    };
    since_activation > MAX_RENEWAL_TIME && since_activation < license.grace_period
}

/// `is_valid`: `now - issued_at <= grace_period`, inclusive at the
/// boundary. A third, distinct freshness check from `validate_at`'s
/// grace-deadline branch and from `in_grace_period` above; each answers a
/// different question, so they're kept as separate functions rather than
/// collapsed into one.
pub fn is_valid(license: &License, now: SystemTime) -> bool {
    match now.duration_since(license.issued_at) {
        Ok(d) => d <= license.grace_period,
        Err(_) => true, // now is before issued_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::LicenseType;
    use std::collections::HashMap;

    fn base_license(now: SystemTime) -> License {
        License {
            key: "K".into(),
            activation_id: "A".into(),
            project_id: "P".into(),
            machine_id: "M".into(),
            issued_at: now - Duration::from_secs(7 * 24 * 60 * 60),
            expires_at: now + Duration::from_secs(365 * 24 * 60 * 60),
            grace_period: Duration::from_secs(7 * 24 * 60 * 60),
            license_type: LicenseType::Expiring,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn grace_boundary_exact_deadline_is_still_valid() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        let lic = base_license(now);
        let deadline = lic.issued_at + lic.grace_period;
        assert!(validate_at(&lic, "M", deadline).is_ok());
    }

    #[test]
    fn grace_boundary_one_second_before_is_valid() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        let lic = base_license(now);
        let deadline = lic.issued_at + lic.grace_period - Duration::from_secs(1);
        assert!(validate_at(&lic, "M", deadline).is_ok());
    }

    #[test]
    fn grace_boundary_one_second_after_is_grace_expired() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        let lic = base_license(now);
        let deadline = lic.issued_at + lic.grace_period + Duration::from_secs(1);
        assert_eq!(
            validate_at(&lic, "M", deadline),
            Err(ValidateError::GraceExpired)
        );
    }

    #[test]
    fn hard_expiry_wins_even_within_nominal_grace_window() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        let mut lic = base_license(now);
        lic.expires_at = lic.issued_at + Duration::from_secs(3600); // expires long before grace deadline
        let check_at = lic.expires_at + Duration::from_secs(1);
        assert_eq!(
            validate_at(&lic, "M", check_at),
            Err(ValidateError::HardExpired)
        );
    }

    #[test]
    fn license_too_old_fires_independent_of_grace_and_expiry() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        let mut lic = base_license(now);
        lic.grace_period = Duration::from_secs(1000 * 24 * 60 * 60); // huge, won't trip first
        lic.expires_at = lic.issued_at + Duration::from_secs(2000 * 24 * 60 * 60); // far future
        let check_at = lic.issued_at + Duration::from_secs(366 * 24 * 60 * 60);
        assert_eq!(
            validate_at(&lic, "M", check_at),
            Err(ValidateError::LicenseTooOld)
        );
    }

    #[test]
    fn machine_id_mismatch_is_reported_before_time_based_checks() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        let lic = base_license(now);
        assert_eq!(
            validate_at(&lic, "someone-else", now),
            Err(ValidateError::MachineIdMismatch)
        );
    }

    #[test]
    fn perpetual_fixed_still_requires_positive_grace_period() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        let mut lic = base_license(now);
        lic.license_type = LicenseType::PerpetualFixed;
        lic.grace_period = Duration::ZERO;
        assert!(matches!(
            validate_at(&lic, "M", now),
            Err(ValidateError::InvalidFields(_))
        ));
    }

    #[test]
    fn perpetual_fixed_skips_grace_deadline_but_not_hard_expiry() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        let mut lic = base_license(now);
        lic.license_type = LicenseType::PerpetualFixed;
        // now is already past issued_at+grace_period, which would normally
        // be GraceExpired, but perpetual_fixed doesn't check that at all.
        let check_at = lic.issued_at + lic.grace_period + Duration::from_secs(1);
        assert!(validate_at(&lic, "M", check_at).is_ok());
    }

    #[test]
    fn in_grace_period_is_false_before_the_60_minute_marker() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        let mut lic = base_license(now);
        lic.issued_at = now - Duration::from_secs(30 * 60);
        assert!(!in_grace_period(&lic, now));
    }

    #[test]
    fn in_grace_period_is_true_between_60_minutes_and_the_grace_deadline() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        let mut lic = base_license(now);
        lic.issued_at = now - Duration::from_secs(2 * 60 * 60);
        assert!(in_grace_period(&lic, now));
    }

    #[test]
    fn is_valid_matches_validate_at_boundary() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        let lic = base_license(now);
        let deadline = lic.issued_at + lic.grace_period;
        assert!(is_valid(&lic, deadline));
        assert!(!is_valid(&lic, deadline + Duration::from_secs(1)));
    }

    #[test]
    fn perpetual_fixed_still_hard_expires() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        let mut lic = base_license(now);
        lic.license_type = LicenseType::PerpetualFixed;
        lic.expires_at = now - Duration::from_secs(1);
        assert_eq!(validate_at(&lic, "M", now), Err(ValidateError::HardExpired));
    }

    #[test]
    fn invalid_fields_rejected() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);

        let mut lic = base_license(now);
        lic.issued_at = SystemTime::UNIX_EPOCH;
        assert!(matches!(
            validate_at(&lic, "M", now),
            Err(ValidateError::InvalidFields(_))
        ));

        let mut lic = base_license(now);
        lic.expires_at = SystemTime::UNIX_EPOCH;
        assert!(matches!(
            validate_at(&lic, "M", now),
            Err(ValidateError::InvalidFields(_))
        ));

        let mut lic = base_license(now);
        lic.grace_period = Duration::ZERO;
        assert!(matches!(
            validate_at(&lic, "M", now),
            Err(ValidateError::InvalidFields(_))
        ));
    }

    #[test]
    fn expires_before_issued_is_rejected() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        let mut lic = base_license(now);
        lic.expires_at = lic.issued_at - Duration::from_secs(1);
        assert!(matches!(
            validate_at(&lic, "M", now),
            Err(ValidateError::InvalidFields(_))
        ));
    }
}
