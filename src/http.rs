//! `Sdk`: activates and renews licenses over the network, with an optional
//! on-disk cache so repeat launches don't need a network call.
//!
//! Two independent Cargo features control what's compiled in:
//!
//! - `http` (default-on), the network client itself (`reqwest`). Without
//!   it there's no `Sdk` at all; call `verify::verify_activation_at` /
//!   `validate::validate_at` directly against your own HTTP client instead.
//! - `cache` (default-on), the on-disk token cache (`crate::storage`).
//!   With `http` but without `cache`, `Sdk` still works, just without the
//!   fast path in `activate`/`renew` and without `check` (there'd be
//!   nothing for it to check). Turn this off for embedded/sandboxed
//!   targets with no writable filesystem.
//!
//! `activate`/`renew` always go over the network on a cache miss; there's
//! no background renewal thread here; call `renew` yourself on whatever
//! schedule fits your application.

use std::time::{Duration, SystemTime};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::appid::parse_app_id;
use crate::domain::CertChain;
use crate::error::LatteError;
use crate::key::{normalize_key, sanitize_key};
#[cfg(feature = "cache")]
use crate::validate::{in_grace_period, validate_at};
#[cfg(feature = "cache")]
use crate::verify::verify_activation_at;
use crate::{check_license_at, PublicLicense};
#[cfg(feature = "cache")]
use crate::{error::ValidateError, storage, CheckError};

/// The Ed25519 public key used to verify every certificate chain. This is
/// a public key, not a secret; it's meant to be embedded in every SDK.
const MASTER_PUBLIC_KEY_HEX: &str =
    "6773cdfdfb7fc44f13f097449b715e7147a2d73f525d9f09a8d25229e458a2fb";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for [`Sdk::new`].
///
/// The recommended way to build one is [`Config::with_app_id`], which fills
/// every other field with its default:
///
/// ```no_run
/// use latte_rs::http::{Config, Sdk};
///
/// let sdk = Sdk::new(Config::with_app_id("pk_live_..."))?;
/// # Ok::<(), latte_rs::error::LatteError>(())
/// ```
///
/// To override further fields, chain the other `with_*` builder methods
/// onto it:
///
/// ```no_run
/// use latte_rs::http::{Config, Sdk};
///
/// let sdk = Sdk::new(
///     Config::with_app_id("pk_live_...")
///         .with_base_url("https://relay.example.com"),
/// )?;
/// # Ok::<(), latte_rs::error::LatteError>(())
/// ```
///
/// This type is `#[non_exhaustive]`: it gains fields over time, so it can't
/// be constructed with a struct literal (not even with `..Default::default()`)
/// outside this crate — build it with `with_app_id`/`Default::default()` and
/// the other `with_*` methods instead.
#[non_exhaustive]
#[derive(Default)]
pub struct Config {
    /// `pk_{env}_{32-char key}`, shown in the LicenseLatte dashboard.
    pub app_id: String,
    /// Request timeout for `activate`/`renew`. Defaults to 30s if `None`.
    pub timeout: Option<Duration>,
    /// Override the API base URL that `app_id`'s environment would
    /// otherwise select. Useful for routing through a corporate
    /// proxy/self-hosted relay, or for pointing tests at a mock server.
    /// `None` uses the environment default.
    pub base_url: Option<String>,
    /// Override where the on-disk token cache lives. `None` resolves a
    /// per-project default location; set this to use a path of your
    /// choosing instead (or to point tests at a temp directory).
    #[cfg(feature = "cache")]
    pub cache_path: Option<std::path::PathBuf>,
}

impl Config {
    /// Builds a `Config` with `app_id` set and every other field at its
    /// default (30s timeout, environment-default base URL, default cache
    /// location). This is the recommended way to construct a `Config`;
    /// see the type-level docs for how to override individual fields on
    /// top of it.
    pub fn with_app_id(app_id: impl Into<String>) -> Self {
        Self {
            app_id: app_id.into(),
            ..Default::default()
        }
    }

    /// Overrides the request timeout for `activate`/`renew`. Defaults to
    /// 30s if never called.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Overrides the API base URL that `app_id`'s environment would
    /// otherwise select. Useful for routing through a corporate
    /// proxy/self-hosted relay, or for pointing tests at a mock server.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    /// Overrides where the on-disk token cache lives. Defaults to a
    /// per-project location if never called.
    #[cfg(feature = "cache")]
    pub fn with_cache_path(mut self, cache_path: impl Into<std::path::PathBuf>) -> Self {
        self.cache_path = Some(cache_path.into());
        self
    }
}

/// Activates and renews licenses over the network, with an optional local
/// cache so a valid activation survives across process restarts without a
/// network round trip.
pub struct Sdk {
    base_url: String,
    app_id: String,
    http: reqwest::Client,
    master_pub: VerifyingKey,
    #[cfg(feature = "cache")]
    cache_path: Option<std::path::PathBuf>,
}

impl Sdk {
    /// Parses and checksum-validates `config.app_id`, returning
    /// `LatteError::InvalidAppId` on failure. Building the underlying HTTP
    /// client can only fail on an invalid TLS/proxy configuration, which
    /// can't happen with this crate's own defaults, but is still surfaced
    /// as `LatteError::Network` rather than panicking.
    pub fn new(config: Config) -> Result<Self, LatteError> {
        let parsed = parse_app_id(&config.app_id)?;

        let master_bytes =
            hex::decode(MASTER_PUBLIC_KEY_HEX).expect("MASTER_PUBLIC_KEY_HEX is valid hex");
        let master_arr: [u8; 32] = master_bytes
            .try_into()
            .expect("MASTER_PUBLIC_KEY_HEX decodes to 32 bytes");
        let master_pub = VerifyingKey::from_bytes(&master_arr)
            .expect("MASTER_PUBLIC_KEY_HEX is a valid Ed25519 public key");

        let http = reqwest::Client::builder()
            .timeout(config.timeout.unwrap_or(DEFAULT_TIMEOUT))
            .build()
            .map_err(|e| LatteError::Network(e.to_string()))?;

        #[cfg(feature = "cache")]
        let cache_path = config
            .cache_path
            .clone()
            .or_else(|| storage::default_path(&parsed.key));

        Ok(Self {
            base_url: config
                .base_url
                .unwrap_or_else(|| parsed.env.base_url().to_string()),
            app_id: config.app_id,
            http,
            master_pub,
            #[cfg(feature = "cache")]
            cache_path,
        })
    }

    /// Activates `license_key` for `machine_id`.
    ///
    /// The key is normalized and given a minimal sanity check (non-empty,
    /// not implausibly long) before ever reaching the network — a license
    /// key may be native or a legacy-system alias (see the
    /// legacy-key-migration feature in license-latte-api,
    /// internal/usecase/api/activate_license.go), and only the server
    /// knows which, so anything beyond that minimal check is deferred to
    /// it.
    ///
    /// With the `cache` feature, a cached activation for this exact key is
    /// tried first; if it's still valid, it's returned without a network
    /// call. A cache hit matches either the cached license's native key
    /// (`sub` claim) against the sanitized input, or — for a license
    /// resolved via a legacy-key alias, where `sub` is the newly minted
    /// native key rather than the string the caller keeps passing — its
    /// `alias` claim against the normalized input. Any other outcome (no
    /// cache, a cache for a different key, or a cached token that fails
    /// verification/validation) falls through to a network call, and a
    /// successful result is written back to the cache. A server response
    /// that fails local verification/validation surfaces as
    /// `LatteError::Server`, not one of the sentinel variants (those are
    /// reserved for the server's HTTP status code itself).
    pub async fn activate(
        &self,
        license_key: &str,
        machine_id: &str,
    ) -> Result<PublicLicense, LatteError> {
        let sanitized = sanitize_key(license_key);
        let normalized = normalize_key(license_key);
        self.validate_license_key(&normalized)?;

        #[cfg(feature = "cache")]
        if let Some((lic, alias)) = self.cached_license(machine_id) {
            if lic.key == sanitized || (!alias.is_empty() && alias == normalized) {
                return Ok(lic);
            }
        }

        let body = ActivateRequest {
            project_key: &self.app_id,
            license_key: &normalized,
            machine_id,
        };
        let (token, chain) = self
            .post_and_handle_invalidation("/v1/activate", &body)
            .await?;
        let lic = self.verify_and_validate(&token, &chain, machine_id)?;
        #[cfg(feature = "cache")]
        self.save_to_cache(&token, &chain);
        Ok(lic)
    }

    /// Renews an existing activation.
    ///
    /// Unlike `activate`, this does not re-check the license-key format
    /// against the project key; it trusts the caller already holds a
    /// valid `activation_id` (from a prior `activate` call's
    /// `PublicLicense::activation_id`). Also unlike `activate`'s request,
    /// the wire request here carries no project-key field. On success, and
    /// with the `cache` feature enabled, the renewed token replaces
    /// whatever was previously cached.
    pub async fn renew(
        &self,
        activation_id: &str,
        license_key: &str,
        machine_id: &str,
    ) -> Result<PublicLicense, LatteError> {
        let body = RenewRequest {
            activation_id,
            license_key,
            machine_id,
        };
        let (token, chain) = self
            .post_and_handle_invalidation("/v1/renew", &body)
            .await?;
        let lic = self.verify_and_validate(&token, &chain, machine_id)?;
        #[cfg(feature = "cache")]
        self.save_to_cache(&token, &chain);
        Ok(lic)
    }

    /// Reads the cached activation for `machine_id` without making a
    /// network call. Requires the `cache` feature.
    ///
    /// Returns `LatteError::LicenseExpired` if there's a cached token but
    /// it's past its hard expiry, and `LatteError::NotActivated` for every
    /// other reason there's no currently-usable cached license: nothing
    /// cached, a cache that fails signature verification (corrupt,
    /// tampered, or simply not something this key can verify), or a cache
    /// that's valid but rejected for a different reason (out of its grace
    /// window, too old, or for a different machine ID); those don't get
    /// their own sentinel because the caller's correct response to all of
    /// them is the same: activate again.
    #[cfg(feature = "cache")]
    pub fn check(&self, machine_id: &str) -> Result<PublicLicense, LatteError> {
        let Some(path) = &self.cache_path else {
            return Err(LatteError::NotActivated);
        };
        let Some((token, chain)) = storage::load(path) else {
            return Err(LatteError::NotActivated);
        };

        match check_license_at(
            &self.master_pub,
            &token,
            &chain,
            machine_id,
            SystemTime::now(),
        ) {
            Ok(lic) => Ok(lic),
            Err(CheckError::Validate(ValidateError::HardExpired)) => {
                Err(LatteError::LicenseExpired)
            }
            Err(_) => Err(LatteError::NotActivated),
        }
    }

    /// A minimal local sanity check, not a format check: a license key
    /// may be native or a legacy-system alias (see the legacy-key-migration
    /// feature in license-latte-api, internal/usecase/api/activate_license.go),
    /// and only the server knows which. This exists only to reject
    /// obviously-not-a-key input (empty, or implausibly long) without a
    /// network round trip.
    fn validate_license_key(&self, normalized: &str) -> Result<(), LatteError> {
        if normalized.is_empty() || normalized.len() > 256 {
            return Err(LatteError::InvalidKey);
        }
        Ok(())
    }

    /// Verifies+validates the cached token, if any, returning both its
    /// public-facing shape and its (internal-only) alias claim so the
    /// fast path in `activate` can match a legacy-key alias too.
    #[cfg(feature = "cache")]
    fn cached_license(&self, machine_id: &str) -> Option<(PublicLicense, String)> {
        let (token, chain) = storage::load(self.cache_path.as_deref()?)?;
        let now = SystemTime::now();
        let license = verify_activation_at(&self.master_pub, &token, &chain, now).ok()?;
        validate_at(&license, machine_id, now).ok()?;
        let in_grace = in_grace_period(&license, now);
        let alias = license.alias.clone();
        let public = PublicLicense {
            key: license.key,
            activation_id: license.activation_id,
            project_id: license.project_id,
            issued_at: license.issued_at,
            expires_at: license.expires_at,
            grace_period: license.grace_period,
            in_grace_period: in_grace,
            license_type: license.license_type,
            metadata: license.metadata,
        };
        Some((public, alias))
    }

    #[cfg(feature = "cache")]
    fn save_to_cache(&self, token: &str, chain: &CertChain) {
        if let Some(path) = &self.cache_path {
            // Best-effort: a local write failure shouldn't turn a
            // successful network activation into an error.
            let _ = storage::save(path, token, chain);
        }
    }

    #[cfg(feature = "cache")]
    fn clear_cache(&self) {
        if let Some(path) = &self.cache_path {
            let _ = storage::clear(path);
        }
    }

    fn verify_and_validate(
        &self,
        token: &str,
        chain: &CertChain,
        machine_id: &str,
    ) -> Result<PublicLicense, LatteError> {
        check_license_at(
            &self.master_pub,
            token,
            chain,
            machine_id,
            SystemTime::now(),
        )
        .map_err(|e| LatteError::Server(format!("server returned invalid token: {e}")))
    }

    /// Calls `post`, and on a response that unambiguously means "this
    /// activation no longer exists" (not found / expired / wrong project
    /// key), drops any cached token for this project too; otherwise a
    /// later `check`/`activate` fast path would keep treating a
    /// server-revoked license as still active until it independently
    /// expires.
    async fn post_and_handle_invalidation<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<(String, CertChain), LatteError> {
        let result = self.post(path, body).await;
        #[cfg(feature = "cache")]
        if matches!(
            result,
            Err(LatteError::LicenseNotFound)
                | Err(LatteError::LicenseExpired)
                | Err(LatteError::InvalidProjectKey)
        ) {
            self.clear_cache();
        }
        result
    }

    /// Shared POST helper for `activate`/`renew`.
    async fn post<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<(String, CertChain), LatteError> {
        let resp = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .json(body)
            .send()
            .await
            .map_err(|e| LatteError::Network(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let err_body: ErrorResponse = resp.json().await.unwrap_or_default();
            return Err(match status.as_u16() {
                404 => LatteError::LicenseNotFound,
                403 => LatteError::LicenseExpired,
                409 => LatteError::SeatLimit,
                401 => LatteError::InvalidProjectKey,
                _ => LatteError::Server(if err_body.error.is_empty() {
                    format!("HTTP {status}")
                } else {
                    err_body.error
                }),
            });
        }

        let result: TokenResponse = resp
            .json()
            .await
            .map_err(|e| LatteError::Server(format!("decode response: {e}")))?;

        if result.token.is_empty() {
            return Err(LatteError::Server("server returned empty token".into()));
        }
        if result.chain.daily.is_empty()
            || result.chain.project.is_empty()
            || result.chain.submaster.is_empty()
        {
            return Err(LatteError::Server("server returned empty chain".into()));
        }

        Ok((result.token, result.chain))
    }
}

#[derive(Serialize)]
struct ActivateRequest<'a> {
    project_key: &'a str,
    license_key: &'a str,
    machine_id: &'a str,
}

#[derive(Serialize)]
struct RenewRequest<'a> {
    activation_id: &'a str,
    license_key: &'a str,
    machine_id: &'a str,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
    chain: CertChain,
}

#[derive(Deserialize, Default)]
struct ErrorResponse {
    #[serde(default)]
    error: String,
}
