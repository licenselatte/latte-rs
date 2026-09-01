//! Typed entitlements: the answers a seller signed into a licence about
//! what their customer bought.
//!
//! An entitlement answers one of exactly two questions about the software
//! you shipped: *may this customer do X* (a boolean, read with
//! [`PublicLicense::can`]) and *how many Y do they get* (an integer, read
//! with [`PublicLicense::limit`]). The values are set on a policy and
//! overridden per licence in the LicenseLatte dashboard, resolved
//! server-side, and signed into the activation token as the `ent` claim —
//! so `can` and `limit` answer fully offline, with no network call and no
//! second source of truth.
//!
//! They are deliberately not the same thing as `metadata` (the `pmd`
//! claim): metadata is arbitrary display data, filtered per field, and
//! untyped. Entitlements are booleans and integers, unfiltered, and exist
//! precisely to be read on the customer's machine. The two never merge,
//! and the same key may appear in both meaning different things.
//!
//! # Absence denies, and that has a rollout consequence
//!
//! A key that is not in the claim answers `false` / `None`. There is no
//! "unknown means allow": the token is a bearer artefact sitting in a file
//! on the machine of the person it constrains, so if absence granted,
//! stripping the claim would unlock everything, and replaying a token
//! minted before the seller adopted entitlements would do the same with no
//! tampering at all.
//!
//! The cost of that default lands on you, not on the server. Shipping
//!
//! ```ignore
//! if !lic.can("export_pdf") { hide(); }
//! ```
//!
//! before your installed base has renewed disables PDF export for every
//! customer whose cached token predates the claim. Use
//! [`PublicLicense::has_entitlements`] to bridge one release:
//!
//! ```ignore
//! let enabled = if lic.has_entitlements() { lic.can("export_pdf") } else { legacy() };
//! ```
//!
//! Drop the fallback once the base has renewed — one grace window, which
//! the dashboard shows per policy.
//!
//! # Tamper resistance
//!
//! Entitlements are a distribution mechanism for a signed answer, not a
//! tamper-proofing one. A determined user can patch this check out of your
//! binary exactly as they could any other. If real revenue depends on a
//! feature, re-validate it server-side.
//!
//! [`PublicLicense::can`]: crate::PublicLicense::can
//! [`PublicLicense::limit`]: crate::PublicLicense::limit
//! [`PublicLicense::has_entitlements`]: crate::PublicLicense::has_entitlements

use std::collections::HashMap;

/// The sentinel an integer entitlement carries to mean "no ceiling".
///
/// [`limit`] returns it as-is; compare against this constant rather than
/// testing for a negative number.
///
/// ```ignore
/// if let Some(n) = lic.limit("max_projects") {
///     if n != latte::UNLIMITED && used >= n { return Err(TooMany); }
/// }
/// ```
///
/// [`limit`]: crate::PublicLicense::limit
pub const UNLIMITED: i64 = -1;

/// One entitlement's value: a boolean, or a 64-bit signed integer.
///
/// Two variants and no more. Strings would be the untyped bag with extra
/// steps, enums are N booleans with a schema the client has to know, and
/// floats round-trip through five JSON parsers with five opinions about
/// `1.0` versus `1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntitlementValue {
    Bool(bool),
    Int(i64),
}

impl EntitlementValue {
    /// The boolean value, or `None` if this is an integer entitlement.
    ///
    /// There is no coercion: a non-zero integer is not `Some(true)`.
    pub fn as_bool(self) -> Option<bool> {
        match self {
            EntitlementValue::Bool(b) => Some(b),
            EntitlementValue::Int(_) => None,
        }
    }

    /// The integer value, or `None` if this is a boolean entitlement.
    ///
    /// [`UNLIMITED`] is returned as-is; callers compare against the
    /// constant.
    pub fn as_int(self) -> Option<i64> {
        match self {
            EntitlementValue::Int(i) => Some(i),
            EntitlementValue::Bool(_) => None,
        }
    }

    /// Whether this is the unlimited sentinel.
    pub fn is_unlimited(self) -> bool {
        matches!(self, EntitlementValue::Int(UNLIMITED))
    }
}

/// Narrows a raw `ent` claim to the two types the format admits, dropping
/// everything else.
///
/// Dropping rather than erroring is the contract, not laxity: rejecting a
/// token because a seller managed to get a string into one value would
/// take a working product offline for a data-entry mistake, on a machine
/// that cannot be reached to fix it. Refusing bad values is the server's
/// job at write time, where there is a human and an error message.
///
/// `serde_json` can tell an integer from a float, but two of the five SDKs
/// cannot: Go's and JavaScript's JSON parsers hand back one numeric type
/// for both. So the rule is the one all five can implement — a whole-valued
/// number is an integer (`25.0` is 25), a fractional one is dropped.
///
/// Returns `None` when the claim is absent, which is a different thing from
/// an empty map — `has_entitlements` reads exactly that distinction.
pub(crate) fn decode_entitlements(
    claims: &serde_json::Map<String, serde_json::Value>,
) -> Option<HashMap<String, EntitlementValue>> {
    let raw = claims.get("ent")?.as_object()?;

    let mut out = HashMap::with_capacity(raw.len());
    for (key, value) in raw {
        let decoded = match value {
            serde_json::Value::Bool(b) => EntitlementValue::Bool(*b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    EntitlementValue::Int(i)
                } else if let Some(f) = n.as_f64().filter(|f| f.is_finite() && f.fract() == 0.0) {
                    // Whole-valued float: representable, and the shape a
                    // Go- or JavaScript-signed token cannot be told apart
                    // from a plain integer anyway.
                    match i64::try_from(f as i128) {
                        Ok(i) => EntitlementValue::Int(i),
                        Err(_) => continue,
                    }
                } else {
                    continue;
                }
            }
            _ => continue,
        };
        out.insert(key.clone(), decoded);
    }
    Some(out)
}
