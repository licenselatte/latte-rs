use std::fmt;

/// Errors surfaced while verifying a certificate chain JWT (submaster,
/// project, or daily cert) or the activation token's own signature.
#[derive(Debug)]
pub enum VerifyError {
    /// The JWT was not well-formed (wrong number of `.`-separated parts,
    /// invalid base64url, or the payload wasn't valid JSON).
    Malformed(String),
    /// The Ed25519 signature did not verify against the expected public key.
    InvalidSignature,
    /// A required claim was missing or had the wrong type.
    MissingClaim(&'static str),
    /// A claim was present but structurally invalid (e.g. a pubkey field
    /// that isn't valid hex, or isn't 32 bytes once decoded).
    InvalidClaim(&'static str, String),
    /// `iss` didn't match the expected issuer.
    WrongIssuer,
    /// The JWT's `iat` is after the verifier's current time (zero leeway
    /// for cert-chain links).
    NotYetValid,
    /// The JWT's `exp` is before the verifier's current time (zero leeway).
    Expired,
    /// Cross-check between two certs in the chain failed (project_id
    /// mismatch, activation iat before daily cert iat, the
    /// activation-iat-vs-daily-exp check, or the grace period exceeding
    /// the 90-day ceiling).
    ChainInconsistent(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Malformed(s) => write!(f, "malformed token: {s}"),
            VerifyError::InvalidSignature => write!(f, "invalid signature"),
            VerifyError::MissingClaim(c) => write!(f, "missing claim: {c}"),
            VerifyError::InvalidClaim(c, why) => write!(f, "invalid claim {c}: {why}"),
            VerifyError::WrongIssuer => write!(f, "unexpected issuer"),
            VerifyError::NotYetValid => write!(f, "token used before issued"),
            VerifyError::Expired => write!(f, "token is expired"),
            VerifyError::ChainInconsistent(s) => write!(f, "chain inconsistent: {s}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Errors surfaced by grace-period / offline validation, once the chain and
/// signature have already verified.
#[derive(Debug, PartialEq, Eq)]
pub enum ValidateError {
    /// `now > expires_at`.
    HardExpired,
    /// `now > issued_at + grace_period`, but not yet past `expires_at`.
    GraceExpired,
    /// `now - issued_at > 365 days`, independent of `expires_at`/`grace_period`.
    LicenseTooOld,
    /// The caller-supplied machine ID doesn't match the license's `mid`
    /// claim.
    MachineIdMismatch,
    /// One of `issued_at`/`expires_at`/`grace_period` is missing or
    /// inconsistent (zero timestamps, non-positive grace period, or
    /// `expires_at` before `issued_at`).
    InvalidFields(String),
}

impl fmt::Display for ValidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidateError::HardExpired => write!(f, "license expired"),
            ValidateError::GraceExpired => write!(f, "grace period expired"),
            ValidateError::LicenseTooOld => write!(f, "license too old"),
            ValidateError::MachineIdMismatch => write!(f, "machine ID does not match"),
            ValidateError::InvalidFields(s) => write!(f, "invalid license: {s}"),
        }
    }
}

impl std::error::Error for ValidateError {}

/// Errors from parsing/validating an `AppId` (`pk_{env}_{32-char key}`).
#[derive(Debug, PartialEq, Eq)]
pub enum AppIdError {
    InvalidFormat,
    UnknownEnvironment(String),
    InvalidKeySegment,
    InvalidChecksum,
}

impl fmt::Display for AppIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppIdError::InvalidFormat => write!(f, "invalid AppID"),
            AppIdError::UnknownEnvironment(e) => write!(f, "unknown environment: {e}"),
            AppIdError::InvalidKeySegment => write!(f, "invalid app id key segment"),
            AppIdError::InvalidChecksum => write!(f, "invalid app id checksum"),
        }
    }
}

impl std::error::Error for AppIdError {}

/// Top-level error returned by `Sdk` (`activate`, `renew`, and, with the
/// `cache` feature, `check`).
#[derive(Debug, thiserror::Error)]
pub enum LatteError {
    /// The license key's format or checksum is invalid, or its short_id
    /// doesn't belong to this project. Never reaches the network.
    #[error("invalid license key")]
    InvalidKey,
    /// The license is past its hard expiry, from a 403 response
    /// (`activate`/`renew`) or a cached token (`check`).
    #[error("license expired")]
    LicenseExpired,
    /// No usable license is currently active on this machine: nothing is
    /// cached, the cache is unreadable/tampered, or it's valid but
    /// rejected for a reason other than hard expiry (out of grace, too
    /// old, wrong machine). Only produced by `check`.
    #[error("not activated on this machine")]
    NotActivated,
    #[error("activation seat limit reached")]
    SeatLimit,
    #[error("license not found")]
    LicenseNotFound,
    #[error("invalid project key")]
    InvalidProjectKey,
    #[error(transparent)]
    InvalidAppId(#[from] AppIdError),
    /// Reserved for a future explicit cache-management API; nothing
    /// currently returns this, cache I/O failures are handled by falling
    /// back to the network (or, for `check`, to `NotActivated`) rather
    /// than surfacing an error.
    #[error("storage error: {0}")]
    Storage(String),
    /// Transport-level failure (DNS, TCP, timeout), the request never got
    /// a response.
    #[error("network error: {0}")]
    Network(String),
    /// A non-2xx response with no more specific variant above, a
    /// malformed/empty response body, or a server-issued token that failed
    /// local verification, that last case isn't `InvalidKey`/etc. on
    /// purpose: those variants describe *this SDK's* judgment of a request
    /// or a cached token, not the server's own response failing a check it
    /// should have passed.
    #[error("{0}")]
    Server(String),
}
