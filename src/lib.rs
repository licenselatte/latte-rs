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
//! `appid`), has no dependencies beyond `serde`/`ed25519-dalek`/`sha2` and
//! works the same with both features disabled. Those functions take the
//! derived machine ID (`Sdk::machine_id`, or [`machine_id::derive`] without
//! `Sdk`), never a raw one.
//!
//! No `unsafe` appears anywhere in this crate.

pub mod appid;
pub mod domain;
pub mod entitlements;
pub mod error;
#[cfg(feature = "http")]
pub mod http;
mod jwt;
pub mod key;
pub mod machine_id;
#[cfg(feature = "cache")]
pub mod storage;
pub mod validate;
pub mod verify;

pub use entitlements::{EntitlementValue, UNLIMITED};
#[cfg(feature = "http")]
pub use http::{Config, Sdk};

use domain::{CertChain, License};
use error::{ValidateError, VerifyError};
use std::collections::HashMap;
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
///
/// `#[non_exhaustive]` so that a future claim can be surfaced here without
/// a breaking release: construct one only through [`check_license_at`],
/// which is how you get one anyway.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PublicLicense {
    pub key: String,
    pub activation_id: String,
    pub project_id: String,
    pub issued_at: SystemTime,
    /// The licence's end date; 2099-01-01T00:00:00Z for a licence that
    /// never ends.
    pub expires_at: SystemTime,
    pub grace_period: std::time::Duration,
    pub in_grace_period: bool,
    pub license_type: domain::LicenseType,
    pub metadata: HashMap<String, String>,

    /// The typed feature map the seller signed into this licence, or
    /// `None` when the token carried no `ent` claim at all.
    ///
    /// `None` and `Some(empty)` deny identically; they differ only in
    /// [`PublicLicense::has_entitlements`], which is the probe an
    /// application branches on while its installed base renews. Read
    /// individual keys with [`PublicLicense::can`] and
    /// [`PublicLicense::limit`] rather than indexing this directly, unless
    /// you want to enumerate what was granted. See the [`entitlements`]
    /// module for the full contract.
    pub entitlements: Option<HashMap<String, EntitlementValue>>,
}

impl PublicLicense {
    /// Whether the boolean entitlement named by `key` is present and true.
    ///
    /// A key that is absent, or that holds an integer rather than a
    /// boolean, answers `false`. There is no coercion across kinds: `can`
    /// on an integer entitlement is false even when that integer is
    /// non-zero, because a rule that read "nonzero is true" is one five
    /// SDKs would eventually disagree about.
    pub fn can(&self, key: &str) -> bool {
        self.entitlements
            .as_ref()
            .and_then(|e| e.get(key))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// The integer entitlement named by `key`, or `None` when it is absent.
    ///
    /// The unlimited sentinel is returned as-is: compare the result against
    /// [`UNLIMITED`] rather than testing for a negative number. A key that
    /// holds a boolean rather than an integer misses — `limit` on a boolean
    /// is `None`, not 1 or 0.
    pub fn limit(&self, key: &str) -> Option<i64> {
        self.entitlements
            .as_ref()
            .and_then(|e| e.get(key))
            .and_then(|v| v.as_int())
    }

    /// Whether the activation token carried an `ent` claim at all —
    /// including an empty one, which is why this is not a length check.
    ///
    /// It exists for one job: letting an application fall back to its
    /// pre-entitlements behaviour for the one release it takes an
    /// installed base to renew. Absence denies, so without this probe,
    /// shipping `can()` before setting values in the dashboard switches the
    /// feature off for every customer holding an older cached token.
    pub fn has_entitlements(&self) -> bool {
        self.entitlements.is_some()
    }
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
    check_license_any_at(
        std::slice::from_ref(master_pub),
        token,
        chain,
        machine_id,
        now,
    )
}

/// [`check_license_at`], trusting any one of `master_pubs`. Pass
/// [`verify::master_public_keys`] to trust the same roots `Sdk` does.
pub fn check_license_any_at(
    master_pubs: &[ed25519_dalek::VerifyingKey],
    token: &str,
    chain: &CertChain,
    machine_id: &str,
    now: SystemTime,
) -> Result<PublicLicense, CheckError> {
    let license: License = verify::verify_activation_any_at(master_pubs, token, chain, now)
        .map_err(CheckError::Verify)?;
    validate::validate_at(&license, machine_id, now).map_err(CheckError::Validate)?;

    let in_grace = validate::in_grace_period(&license, now);

    Ok(to_public_license(license, in_grace))
}

/// Projects a chain-verified [`License`] onto its public shape.
///
/// Shared with the cached-token path in `http.rs` rather than inlined at
/// each call site: the two used to be duplicate struct literals, and a
/// field added to one and not the other is a difference nothing would
/// catch. `#[non_exhaustive]` now makes this the only way to build one
/// from outside the crate anyway.
pub(crate) fn to_public_license(license: License, in_grace: bool) -> PublicLicense {
    PublicLicense {
        key: license.key,
        activation_id: license.activation_id,
        project_id: license.project_id,
        issued_at: license.issued_at,
        expires_at: license.expires_at,
        grace_period: license.grace_period,
        in_grace_period: in_grace,
        license_type: license.license_type,
        metadata: license.metadata,
        entitlements: license.entitlements,
    }
}
