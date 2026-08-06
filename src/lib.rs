//! Rust SDK for LicenseLatte license activation and offline verification.
//!
//! `Sdk` (behind the default-on `http` feature) activates and renews
//! licenses over the network, with an optional on-disk cache (the
//! default-on `cache` feature) so a valid activation survives across
//! restarts without a network call. See `src/http.rs` for the full
//! behavior.
//!
//! Everything below `Sdk`, chain verification (`verify`), grace-period
//! validation (`validate`), and license-key/AppID normalization (`key`,
//! `appid`), has no dependencies beyond `serde`/`ed25519-dalek` and works
//! the same with both features disabled; machine-ID fingerprinting is left
//! to the integrator (an OS fingerprint is out of this crate's scope,
//! only the requirement that it's an opaque string is).
//!
//! No `unsafe` appears anywhere in this crate.

pub mod appid;
pub mod domain;
pub mod error;
#[cfg(feature = "http")]
pub mod http;
mod jwt;
pub mod key;
#[cfg(feature = "cache")]
pub mod storage;
pub mod validate;
pub mod verify;

#[cfg(feature = "http")]
pub use http::{Config, Sdk};

use domain::{CertChain, License};
use error::{ValidateError, VerifyError};
use std::fmt;
use std::time::SystemTime;

/// Everything that can go wrong verifying a cached activation, folding
/// `VerifyError` and `ValidateError` into one type for callers who just
/// want a single `Result`.
#[derive(Debug)]
pub enum CheckError {
    Verify(VerifyError),
    Validate(ValidateError),
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckError::Verify(e) => write!(f, "{e}"),
            CheckError::Validate(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CheckError {}

/// The verified, validated, "safe to use" view of a license.
#[derive(Debug, Clone)]
pub struct PublicLicense {
    pub key: String,
    pub activation_id: String,
    pub project_id: String,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub grace_period: std::time::Duration,
    pub in_grace_period: bool,
    pub license_type: domain::LicenseType,
    pub metadata: std::collections::HashMap<String, String>,
}

/// Runs the full pipeline on a cached or freshly-received token: chain
/// verification, then grace-period validation, then the `InGracePeriod`
/// computation. This is the primary entry point plugin developers embed;
/// see the module-level docs for what it does and why, and `README.md` for
/// usage.
pub fn check_license_at(
    master_pub: &ed25519_dalek::VerifyingKey,
    token: &str,
    chain: &CertChain,
    machine_id: &str,
    now: SystemTime,
) -> Result<PublicLicense, CheckError> {
    let license: License =
        verify::verify_activation_at(master_pub, token, chain, now).map_err(CheckError::Verify)?;
    validate::validate_at(&license, machine_id, now).map_err(CheckError::Validate)?;

    let in_grace = validate::in_grace_period(&license, now);

    Ok(PublicLicense {
        key: license.key,
        activation_id: license.activation_id,
        project_id: license.project_id,
        issued_at: license.issued_at,
        expires_at: license.expires_at,
        grace_period: license.grace_period,
        in_grace_period: in_grace,
        license_type: license.license_type,
        metadata: license.metadata,
    })
}
