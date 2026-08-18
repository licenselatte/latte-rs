use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// The policy type of a verified license, from the token's `ltype` claim.
/// Unrecognized strings round-trip through `Other` rather than erroring,
/// since validation treats any non-`perpetual_fixed` value identically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseType {
    PerpetualFixed,
    Perpetual,
    Expiring,
    Other(String),
}

impl LicenseType {
    pub fn from_claim(s: &str) -> Self {
        match s {
            "perpetual_fixed" => LicenseType::PerpetualFixed,
            "perpetual" => LicenseType::Perpetual,
            "expiring" => LicenseType::Expiring,
            other => LicenseType::Other(other.to_string()),
        }
    }

    pub fn is_perpetual_fixed(&self) -> bool {
        matches!(self, LicenseType::PerpetualFixed)
    }
}

/// A chain-verified, not-yet-grace-validated license. Produced by
/// `verify::verify_activation_at`, consumed by `validate::validate_at`.
#[derive(Debug, Clone)]
pub struct License {
    pub key: String,
    /// The legacy-system key string this license was resolved from, when
    /// it was minted via a legacy-key migration alias rather than
    /// activated by its own native key. Empty for a natively-keyed
    /// license. Internal only — used to recognize a cached token on a
    /// later `activate` call passing the same legacy key, since `key`
    /// above will be the newly minted native key instead. See the JWT's
    /// "alias" claim.
    pub alias: String,
    pub activation_id: String,
    pub project_id: String,
    pub machine_id: String,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub grace_period: Duration,
    pub license_type: LicenseType,
    pub metadata: HashMap<String, String>,
}

/// The three-JWT certificate chain: Master (implicit, the caller-supplied
/// verifying key) -> Submaster -> Project -> Daily. `Deserialize`
/// derives directly from those field names (no renames needed) so the
/// `http` feature's wire-response decoding can use this type as-is.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CertChain {
    pub submaster: String,
    pub project: String,
    pub daily: String,
}
