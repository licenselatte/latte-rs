//! `Sdk`: activates and renews licenses over the network, with an optional
//! on-disk cache so repeat launches don't need a network call.
//!
//! Two independent Cargo features control what's compiled in:
//!
//! - `http` (default-on), the network client itself (`ureq`, blocking).
//!   Without it there's no `Sdk` at all; call `verify::verify_activation_at`
//!   / `validate::validate_at` directly against your own HTTP client instead.
//! - `cache` (default-on), the on-disk token cache (`crate::storage`).
//!   With `http` but without `cache`, `Sdk` still works, just without the
//!   fast path in `activate`/`renew` and without `check` (there'd be
//!   nothing for it to check). Turn this off for embedded/sandboxed
//!   targets with no writable filesystem.
//!
//! `activate`/`renew` always go over the network on a cache miss. With the
//! `cache` feature, `check` also renews a cached token in the background
//! once it is an hour old (see [`Sdk::check`]); `renew` stays available to
//! renew on a schedule of your own.
//!
//! The network methods block the calling thread until the server answers
//! or the request times out. Every request runs on a helper thread that is
//! abandoned shortly after its timeout, so even a DNS lookup that never
//! returns cannot hold a caller longer than that.

#[cfg(feature = "cache")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
#[cfg(feature = "cache")]
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, SystemTime};

use ed25519_dalek::VerifyingKey;
use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer, Serialize};
use ureq::http::StatusCode;

use crate::appid::parse_app_id;
use crate::domain::CertChain;
#[cfg(feature = "cache")]
use crate::domain::License;
use crate::error::LatteError;
use crate::key::{normalize_key, sanitize_key};
use crate::machine_id;
#[cfg(feature = "cache")]
use crate::validate::{in_grace_period, validate_at};
#[cfg(feature = "cache")]
use crate::verify::verify_activation_any_at;
use crate::verify::{master_public_keys, unix_to_system_time};
use crate::{check_license_any_at_with_renewal_failed, PublicLicense};
#[cfg(feature = "cache")]
use crate::{error::ValidateError, storage};

/// Overall limit on one network call unless [`Config::timeout`] sets
/// another.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Limit on resolving the host name, and separately on connecting, within
/// the overall limit.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long past its overall limit a request is waited for before its
/// helper thread is abandoned.
const ABANDON_AFTER: Duration = Duration::from_secs(1);

/// Overall limit on one background renewal.
#[cfg(feature = "cache")]
const BACKGROUND_TIMEOUT: Duration = Duration::from_secs(10);

/// A cached token this old or older is renewed in the background.
#[cfg(feature = "cache")]
const RENEW_AFTER: Duration = Duration::from_secs(60 * 60);

/// Background renewal attempts start at least this far apart.
#[cfg(feature = "cache")]
const RENEW_RETRY: Duration = Duration::from_secs(5 * 60);

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
    /// Overall limit on one network call (`activate`, `renew`,
    /// `deactivate`, `machines`, `rename_machine`), from resolving the host
    /// to reading the response. Defaults to 10s if `None`. Resolving the
    /// host and connecting are each also limited to 5s. The background
    /// renewal [`Sdk::check`] starts keeps its own limits, 5s to connect
    /// and 10s overall.
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
    /// Replaces the platform's machine ID as the identity of this install.
    /// `None` (or an empty string) reads the platform's machine ID.
    ///
    /// Either way the raw value never leaves the machine: the SDK sends
    /// lowercase hex `HMAC-SHA256(key = raw ID, message = "licenselatte_" +
    /// app_id)`, with a supplied value used byte for byte, without
    /// trimming. See [`crate::machine_id`].
    ///
    /// Set it when the platform ID does not identify what you want to count
    /// as one seat: containers that share their image's `/etc/machine-id`
    /// or have none, cloned VMs that share one ID, apps that want a seat per
    /// user rather than per machine, and tests. Changing it on an install
    /// that is already activated makes that install a new machine, which
    /// takes a new seat.
    pub machine_id: Option<String>,
    /// The name this machine is given when it activates, shown to the
    /// customer in [`Sdk::machines`] and the customer portal and to you in
    /// the dashboard. A name set later with [`Sdk::rename_machine`] is kept
    /// on re-activation.
    ///
    /// `None` sends the default name, which is none: the standard library
    /// has no hostname call and this crate takes no dependency for one, so
    /// pass the hostname here if you want machines named after it.
    /// `Some("")` sends no name either.
    pub machine_name: Option<String>,
}

impl Config {
    /// Builds a `Config` with `app_id` set and every other field at its
    /// default (10s timeout, environment-default base URL, default cache
    /// location). This is the recommended way to construct a `Config`;
    /// see the type-level docs for how to override individual fields on
    /// top of it.
    pub fn with_app_id(app_id: impl Into<String>) -> Self {
        Self {
            app_id: app_id.into(),
            ..Default::default()
        }
    }

    /// Overrides the overall limit on one network call. Defaults to 10s if
    /// never called. See [`Config::timeout`].
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

    /// Supplies the raw machine ID in place of the platform's. See
    /// [`Config::machine_id`] for when to use it.
    pub fn with_machine_id(mut self, machine_id: impl Into<String>) -> Self {
        self.machine_id = Some(machine_id.into());
        self
    }

    /// Names this machine on activation. See [`Config::machine_name`].
    pub fn with_machine_name(mut self, machine_name: impl Into<String>) -> Self {
        self.machine_name = Some(machine_name.into());
        self
    }
}

/// Activates and renews licenses over the network, with an optional local
/// cache so a valid activation survives across process restarts without a
/// network round trip.
///
/// Cloning is cheap and the clone shares the renewal state and the cache
/// with the original.
///
/// The network methods (`activate`, `renew`, `deactivate`, `machines`,
/// `rename_machine`) block until the server answers or the call times out
/// (see [`Config::timeout`]). Call them from a worker thread, not from a
/// GUI main thread, and from inside an async executor through its
/// blocking-task API (`tokio::task::spawn_blocking` and the like).
/// [`Sdk::check`] never touches the network and returns at once.
#[derive(Clone)]
pub struct Sdk {
    base_url: String,
    app_id: String,
    machine_id: String,
    machine_name: Option<String>,
    http: Http,
    /// The client of the background renewal, with its own fixed limits.
    #[cfg(feature = "cache")]
    background_http: Http,
    master_pubs: Vec<VerifyingKey>,
    #[cfg(feature = "cache")]
    cache_path: Option<std::path::PathBuf>,
    clock: Arc<dyn Fn() -> SystemTime + Send + Sync>,
    /// Background-renewal bookkeeping, and the lock every cache write that
    /// has to be conditional on what the cache holds goes through.
    #[cfg(feature = "cache")]
    renewal: Arc<Mutex<Renewal>>,
    /// Whether the last renewal attempt could not reach the server and
    /// nothing has succeeded or been rejected since. Written under the
    /// [`Sdk::renewal`] lock and read without it, so `check` never waits.
    /// Never persisted, so a fresh process starts false. It is the input of
    /// [`PublicLicense::in_grace_period`].
    #[cfg(feature = "cache")]
    renewal_failed: Arc<AtomicBool>,
}

#[cfg(feature = "cache")]
#[derive(Default)]
struct Renewal {
    /// Numbers the background renewals. Only the latest one owns
    /// `in_flight` and gets its outcome recorded.
    attempt: u64,
    /// When the latest background renewal started, while it runs.
    in_flight: Option<SystemTime>,
    /// When the last renewal attempt, background or manual, started.
    last_attempt: Option<SystemTime>,
}

/// Marks background renewal number `.1` finished when dropped, even on a
/// panic, so one that dies cannot stop every later one from starting. Once
/// a newer renewal has taken over, the newer one's mark is left alone.
#[cfg(feature = "cache")]
struct InFlight<'a>(&'a Sdk, u64);

#[cfg(feature = "cache")]
impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let mut state = self.0.renewal();
        if state.attempt == self.1 {
            state.in_flight = None;
        }
    }
}

impl Sdk {
    /// Parses and checksum-validates `config.app_id`, returning
    /// `LatteError::InvalidAppId` on failure, then derives this install's
    /// machine ID (see [`Config::machine_id`]), returning
    /// `LatteError::MachineIdUnavailable` when the platform's cannot be read
    /// and none was supplied. The proxy environment variables (see the
    /// README) are read here, once.
    pub fn new(config: Config) -> Result<Self, LatteError> {
        let parsed = parse_app_id(&config.app_id)?;
        let machine_id = machine_id::derive(&config.app_id, config.machine_id.as_deref())
            .ok_or(LatteError::MachineIdUnavailable)?;

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
            machine_id,
            machine_name: config.machine_name.filter(|n| !n.is_empty()),
            http: Http::new(config.timeout.unwrap_or(DEFAULT_TIMEOUT)),
            #[cfg(feature = "cache")]
            background_http: Http::new(BACKGROUND_TIMEOUT),
            master_pubs: master_public_keys(),
            #[cfg(feature = "cache")]
            cache_path,
            clock: Arc::new(SystemTime::now),
            #[cfg(feature = "cache")]
            renewal: Arc::default(),
            #[cfg(feature = "cache")]
            renewal_failed: Arc::default(),
        })
    }

    /// The machine ID this SDK sends and checks tokens against: the
    /// HMAC-derived value, never the raw ID. Pass it to
    /// [`crate::check_license_at`] and the other low-level functions when
    /// you verify a token yourself.
    pub fn machine_id(&self) -> &str {
        &self.machine_id
    }

    /// Activates `license_key` on this machine.
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
    pub fn activate(&self, license_key: &str) -> Result<PublicLicense, LatteError> {
        let machine_id = self.machine_id.as_str();
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
            machine_name: self.machine_name.as_deref(),
            sdk: SDK_INFO,
        };
        let (token, chain) = self.post_and_handle_invalidation("/v1/activate", &body)?;
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
    ///
    /// With the `cache` feature, a call counts as a renewal attempt for the
    /// background renewal in [`Sdk::check`], which waits five minutes after
    /// it before trying again. It also feeds
    /// [`PublicLicense::in_grace_period`] the same way: a call that fails
    /// with `LatteError::Network` sets it, and any other outcome clears it.
    pub fn renew(
        &self,
        activation_id: &str,
        license_key: &str,
    ) -> Result<PublicLicense, LatteError> {
        #[cfg(feature = "cache")]
        {
            self.renewal().last_attempt = Some((self.clock)());
        }
        let body = self.credentials(activation_id, license_key, None);
        let renewed = self.post_and_handle_invalidation("/v1/renew", &body);
        #[cfg(feature = "cache")]
        {
            let _state = self.renewal();
            self.note_renewal(activation_id, &renewed);
        }
        let (token, chain) = renewed?;
        let lic = self.verify_and_validate(&token, &chain, &self.machine_id)?;
        #[cfg(feature = "cache")]
        self.save_to_cache(&token, &chain);
        Ok(lic)
    }

    /// Releases this machine's seat so the licence can be activated on
    /// another machine: the "Deactivate" button in your application. Takes
    /// the same `activation_id` and `license_key` as [`Sdk::renew`].
    ///
    /// It needs the network. The server releases the seat first, and only
    /// once it has answered does the SDK delete the cached token (with the
    /// `cache` feature), after which `check` returns
    /// `LatteError::NotActivated` until the next `activate`. On any error
    /// the cached token is kept and the call can be retried. A release that
    /// already happened is success, with `released` false. A machine that
    /// is lost or dead cannot call this; its seat is released from the
    /// seller's customer portal instead.
    ///
    /// When the seller's deactivation policy refuses the release, the error
    /// is `LatteError::DeactivationBlocked`.
    pub fn deactivate(
        &self,
        activation_id: &str,
        license_key: &str,
    ) -> Result<DeactivateResult, LatteError> {
        let body = self.credentials(activation_id, license_key, None);
        let result = self.call(&self.http, "/v1/deactivate", &body)?;
        #[cfg(feature = "cache")]
        self.clear_cache();
        Ok(result)
    }

    /// Lists the machines holding a seat on this licence, for showing the
    /// customer where it is in use. It needs the network and an active
    /// activation on this machine (`LatteError::LicenseExpired` otherwise,
    /// from the server's 403).
    pub fn machines(
        &self,
        activation_id: &str,
        license_key: &str,
    ) -> Result<Vec<Machine>, LatteError> {
        let body = self.credentials(activation_id, license_key, None);
        let result: MachinesResponse = self.call(&self.http, "/v1/machines", &body)?;
        Ok(result.machines)
    }

    /// Names this machine and returns the name as stored, trimmed. The
    /// server refuses a name that is empty, longer than 64 characters or
    /// holds control characters, which surfaces as `LatteError::Server`.
    pub fn rename_machine(
        &self,
        activation_id: &str,
        license_key: &str,
        name: &str,
    ) -> Result<String, LatteError> {
        let body = self.credentials(activation_id, license_key, Some(name));
        let result: RenameResponse = self.call(&self.http, "/v1/machines/rename", &body)?;
        Ok(result.machine_name)
    }

    /// Reads the cached activation for this machine without making a
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
    ///
    /// The verdict comes from the cached token alone and `check` returns
    /// at once: it never waits on the network or on a lock. When that token
    /// is at least 60 minutes old, `check` also starts a renewal on a
    /// background thread, unless one is already running, the last attempt
    /// (this one or a manual [`Sdk::renew`]) began less than five minutes
    /// ago, or another thread is updating the renewal state at that moment;
    /// a later `check` then tries again. A renewal still running after ten
    /// minutes no longer counts as running: the next one takes over and the
    /// stale one's outcome is dropped. The thread is detached, so it never
    /// keeps the process alive, and its request gives up after 5s
    /// connecting or 10s overall. A renewal the server rejects as
    /// not-found, expired or for the wrong project key clears the cache,
    /// provided it still holds the activation that was renewed, so the
    /// next `check` returns `LatteError::NotActivated`. A renewal that
    /// succeeds replaces the cached token under the same condition. Every
    /// other failure is dropped: the cached token stays usable until its
    /// grace window ends, and a later `check` tries again.
    ///
    /// The renewal also starts for a token past its grace window or its
    /// licence end, provided its signature chain verifies and it was issued
    /// to this machine. That `check` still returns the error, but once the
    /// renewal has saved a new token a re-check a few seconds later returns
    /// the licence, so a host should re-check rather than send the user to
    /// activate again.
    ///
    /// `in_grace_period` on the result is true when the licence is still
    /// valid on cached data, the SDK has tried to renew it and could not
    /// reach the server, and the offline grace window has not run out. It
    /// comes from memory, not from the cache file, so it is false in a new
    /// process and changes only on a `check` made after the attempt.
    #[cfg(feature = "cache")]
    pub fn check(&self) -> Result<PublicLicense, LatteError> {
        let Some(path) = &self.cache_path else {
            return Err(LatteError::NotActivated);
        };
        let Some((token, chain)) = storage::load(path) else {
            return Err(LatteError::NotActivated);
        };

        let now = (self.clock)();
        let Ok(license) = verify_activation_any_at(&self.master_pubs, &token, &chain, now) else {
            return Err(LatteError::NotActivated);
        };
        let verdict = validate_at(&license, &self.machine_id, now);
        // A token that verifies but has outlived its grace window or its
        // licence end still names an activation the server can renew.
        if license.machine_id == self.machine_id
            && !license.activation_id.is_empty()
            && !license.key.is_empty()
        {
            self.renew_in_background(&license);
        }
        match verdict {
            Ok(()) => {
                let failed = self.renewal_failed.load(Ordering::Relaxed);
                let in_grace = in_grace_period(&license, now, failed);
                Ok(crate::to_public_license(license, in_grace))
            }
            Err(ValidateError::HardExpired) => Err(LatteError::LicenseExpired),
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
        let now = (self.clock)();
        let license = verify_activation_any_at(&self.master_pubs, &token, &chain, now).ok()?;
        validate_at(&license, machine_id, now).ok()?;
        let in_grace = in_grace_period(&license, now, self.renewal_failed.load(Ordering::Relaxed));
        let alias = license.alias.clone();
        Some((crate::to_public_license(license, in_grace), alias))
    }

    #[cfg(feature = "cache")]
    fn renewal(&self) -> MutexGuard<'_, Renewal> {
        self.renewal.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Starts a background renewal of `lic` if it is due: the token is at
    /// least [`RENEW_AFTER`] old, none is running (one running for over
    /// `2 * RENEW_RETRY` does not count), and the last attempt began at
    /// least [`RENEW_RETRY`] ago. Never blocks: while another thread holds
    /// the renewal state it starts nothing and leaves it to a later `check`.
    #[cfg(feature = "cache")]
    fn renew_in_background(&self, lic: &License) {
        let now = (self.clock)();
        let since = |t: SystemTime| now.duration_since(t).unwrap_or(Duration::ZERO);
        if since(lic.issued_at) < RENEW_AFTER {
            return;
        }
        let mut state = match self.renewal.try_lock() {
            Ok(state) => state,
            Err(TryLockError::Poisoned(e)) => e.into_inner(),
            Err(TryLockError::WouldBlock) => return,
        };
        // A renewal running longer than this is taken to be stuck.
        let running = state.in_flight.is_some_and(|t| since(t) <= 2 * RENEW_RETRY);
        let retried_recently = state.last_attempt.is_some_and(|t| since(t) < RENEW_RETRY);
        if running || retried_recently {
            return;
        }
        state.attempt += 1;
        state.in_flight = Some(now);
        state.last_attempt = Some(now);

        let (sdk, attempt) = (self.clone(), state.attempt);
        let (activation_id, license_key) = (lic.activation_id.clone(), lic.key.clone());
        let spawned = std::thread::Builder::new()
            .name("latte-renew".into())
            .spawn(move || sdk.renew_and_store(attempt, &activation_id, &license_key));
        if spawned.is_err() {
            state.in_flight = None;
        }
    }

    /// Background renewal number `attempt`, run on its own thread. Its
    /// outcome is dropped if a newer renewal has taken over in the
    /// meantime, so a stale one neither sets the flag nor touches the cache.
    #[cfg(feature = "cache")]
    fn renew_and_store(&self, attempt: u64, activation_id: &str, license_key: &str) {
        let _done = InFlight(self, attempt);
        let body = self.credentials(activation_id, license_key, None);
        let renewed = self
            .post(&self.background_http, "/v1/renew", &body)
            .and_then(|(token, chain)| {
                self.verify_and_validate(&token, &chain, &self.machine_id)?;
                Ok((token, chain))
            });

        let state = self.renewal();
        if state.attempt != attempt {
            return;
        }
        let holds = self.note_renewal(activation_id, &renewed);
        let (true, Some(path)) = (holds, &self.cache_path) else {
            return;
        };
        match renewed {
            Ok((token, chain)) => {
                let _ = storage::save(path, &token, &chain);
            }
            Err(
                LatteError::LicenseNotFound
                | LatteError::LicenseExpired
                | LatteError::InvalidProjectKey,
            ) => {
                let _ = storage::clear(path);
            }
            Err(_) => {}
        }
    }

    /// Records how a renewal of `activation_id` ended and returns whether
    /// the cache still holds that activation. Only a failure to reach the
    /// server sets the flag, and only while the cache holds the activation;
    /// every other outcome, including a server error, clears it, because
    /// the server answered or the failure is not about connectivity.
    /// Callers hold the [`Sdk::renewal`] lock.
    #[cfg(feature = "cache")]
    fn note_renewal<T>(&self, activation_id: &str, outcome: &Result<T, LatteError>) -> bool {
        let holds = self.holds_activation(activation_id);
        let failed = matches!(outcome, Err(LatteError::Network(_))) && holds;
        self.renewal_failed.store(failed, Ordering::Relaxed);
        holds
    }

    /// Whether the cache holds a verifiable token for `activation_id`.
    /// Callers hold the [`Sdk::renewal`] lock across this and the write it
    /// guards, so a deactivation or re-activation cannot slip in between.
    #[cfg(feature = "cache")]
    fn holds_activation(&self, activation_id: &str) -> bool {
        let Some((token, chain)) = self.cache_path.as_deref().and_then(storage::load) else {
            return false;
        };
        verify_activation_any_at(&self.master_pubs, &token, &chain, (self.clock)())
            .is_ok_and(|l| l.activation_id == activation_id)
    }

    #[cfg(feature = "cache")]
    fn save_to_cache(&self, token: &str, chain: &CertChain) {
        let _state = self.renewal();
        self.renewal_failed.store(false, Ordering::Relaxed);
        if let Some(path) = &self.cache_path {
            // Best-effort: a local write failure shouldn't turn a
            // successful network activation into an error.
            let _ = storage::save(path, token, chain);
        }
    }

    #[cfg(feature = "cache")]
    fn clear_cache(&self) {
        let _state = self.renewal();
        self.renewal_failed.store(false, Ordering::Relaxed);
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
        check_license_any_at_with_renewal_failed(
            &self.master_pubs,
            token,
            chain,
            machine_id,
            (self.clock)(),
            false,
        )
        .map_err(|e| LatteError::Server(format!("server returned invalid token: {e}")))
    }

    /// Calls `post`, and on a response that unambiguously means "this
    /// activation no longer exists" (not found / expired / wrong project
    /// key), drops any cached token for this project too; otherwise a
    /// later `check`/`activate` fast path would keep treating a
    /// server-revoked license as still active until it independently
    /// expires.
    fn post_and_handle_invalidation<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<(String, CertChain), LatteError> {
        let result = self.post(&self.http, path, body);
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

    fn credentials<'a>(
        &'a self,
        activation_id: &'a str,
        license_key: &'a str,
        machine_name: Option<&'a str>,
    ) -> CredentialsRequest<'a> {
        CredentialsRequest {
            activation_id,
            license_key,
            machine_id: &self.machine_id,
            machine_name,
            sdk: SDK_INFO,
        }
    }

    /// Token-returning POST for `activate`/`renew`.
    fn post<B: Serialize>(
        &self,
        http: &Http,
        path: &str,
        body: &B,
    ) -> Result<(String, CertChain), LatteError> {
        let result: TokenResponse = self.call(http, path, body)?;

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

    /// Posts `body` as JSON to `path` and decodes a 2xx answer, mapping
    /// every other status to its `LatteError`.
    fn call<B: Serialize, T: DeserializeOwned>(
        &self,
        http: &Http,
        path: &str,
        body: &B,
    ) -> Result<T, LatteError> {
        let body = serde_json::to_vec(body).map_err(|e| LatteError::Network(e.to_string()))?;
        let (status, resp) = http.post(format!("{}{}", self.base_url, path), body)?;

        if !status.is_success() {
            let err_body: ErrorResponse = resp
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
            return Err(match status.as_u16() {
                404 => LatteError::LicenseNotFound,
                403 => LatteError::LicenseExpired,
                // A 409 here is the seller's deactivation policy, never a
                // seat limit.
                409 if path == "/v1/deactivate" => LatteError::DeactivationBlocked {
                    message: err_body.error,
                    reason: err_body.reason,
                    available_at: err_body.available_at,
                },
                409 => LatteError::SeatLimit,
                401 => LatteError::InvalidProjectKey,
                _ => LatteError::Server(if err_body.error.is_empty() {
                    format!("HTTP {status}")
                } else {
                    err_body.error
                }),
            });
        }

        resp.and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
            .map_err(|e| LatteError::Server(format!("decode response: {e}")))
    }
}

/// A blocking HTTP client and the overall limit on one request through it.
#[derive(Clone)]
struct Http {
    agent: ureq::Agent,
    timeout: Duration,
}

impl Http {
    fn new(timeout: Duration) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .timeout_resolve(Some(CONNECT_TIMEOUT))
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .build()
            .new_agent();
        Self { agent, timeout }
    }

    /// POSTs the JSON `body` to `url` and returns the response status with
    /// the response body, or the error that cut reading it short. Fails
    /// with `LatteError::Network` when no response arrives. The request
    /// runs on a helper thread that is abandoned [`ABANDON_AFTER`] past
    /// `timeout`, which bounds hangs no client timeout covers, such as a
    /// DNS lookup that never returns.
    fn post(
        &self,
        url: String,
        body: Vec<u8>,
    ) -> Result<(StatusCode, Result<Vec<u8>, String>), LatteError> {
        let (tx, rx) = mpsc::channel();
        let agent = self.agent.clone();
        std::thread::Builder::new()
            .name("latte-http".into())
            .spawn(move || {
                let reply = agent
                    .post(&url)
                    .header("content-type", "application/json")
                    .send(&body[..])
                    .map(|mut resp| {
                        let body = resp.body_mut().read_to_vec();
                        (resp.status(), body.map_err(|e| e.to_string()))
                    })
                    .map_err(|e| e.to_string());
                let _ = tx.send(reply);
            })
            .map_err(|e| LatteError::Network(e.to_string()))?;

        match rx.recv_timeout(self.timeout + ABANDON_AFTER) {
            Ok(reply) => reply.map_err(LatteError::Network),
            Err(RecvTimeoutError::Timeout) => Err(LatteError::Network(format!(
                "no response within {:?}",
                self.timeout
            ))),
            Err(RecvTimeoutError::Disconnected) => {
                Err(LatteError::Network("request thread failed".into()))
            }
        }
    }
}

/// What [`Sdk::deactivate`] reports.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct DeactivateResult {
    /// False when the machine was already released, on an earlier call or
    /// by the seller. Both outcomes are success.
    pub released: bool,
    /// When the freed seat can be used by another machine, set when the
    /// seller's policy holds it until this machine's last token has
    /// expired. `None` means the seat is free now.
    #[serde(default, deserialize_with = "de_opt_time")]
    pub seat_free_at: Option<SystemTime>,
}

/// One machine holding a seat on the licence, as [`Sdk::machines`] lists
/// it. It identifies a machine for a person to recognise and is never a
/// handle for acting on one.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct Machine {
    /// The machine's name, `None` when it has none.
    #[serde(rename = "machine_name", default)]
    pub name: Option<String>,
    /// The first 12 characters of the machine ID hash.
    #[serde(rename = "machine_fingerprint")]
    pub fingerprint: String,
    #[serde(deserialize_with = "de_time")]
    pub activated_at: SystemTime,
    /// The machine's last activation or renewal.
    #[serde(deserialize_with = "de_time")]
    pub last_seen_at: SystemTime,
    /// Set on a released machine whose seat the seller's policy still
    /// holds, and is when that seat frees.
    #[serde(default, deserialize_with = "de_opt_time")]
    pub seat_free_at: Option<SystemTime>,
    /// Marks the machine the SDK is running on.
    pub current: bool,
}

/// Which SDK made a request, sent in the body of every request so the
/// server can tell SDK releases apart.
#[derive(Serialize, Clone, Copy)]
struct SdkInfo {
    language: &'static str,
    version: &'static str,
}

const SDK_INFO: SdkInfo = SdkInfo {
    language: "rust",
    version: env!("CARGO_PKG_VERSION"),
};

#[derive(Serialize)]
struct ActivateRequest<'a> {
    project_key: &'a str,
    license_key: &'a str,
    machine_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine_name: Option<&'a str>,
    sdk: SdkInfo,
}

/// Renew's body, which deactivate, machines and rename share; only rename
/// sends `machine_name`.
#[derive(Serialize)]
struct CredentialsRequest<'a> {
    activation_id: &'a str,
    license_key: &'a str,
    machine_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine_name: Option<&'a str>,
    sdk: SdkInfo,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
    chain: CertChain,
}

#[derive(Deserialize)]
struct MachinesResponse {
    machines: Vec<Machine>,
}

#[derive(Deserialize)]
struct RenameResponse {
    machine_name: String,
}

#[derive(Deserialize, Default)]
struct ErrorResponse {
    #[serde(default)]
    error: String,
    /// Set on a deactivation refused by the seller's policy.
    #[serde(default)]
    reason: String,
    #[serde(default, deserialize_with = "de_opt_time")]
    available_at: Option<SystemTime>,
}

fn de_time<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
    let s = String::deserialize(d)?;
    parse_rfc3339(&s).ok_or_else(|| D::Error::custom(format!("invalid timestamp {s:?}")))
}

fn de_opt_time<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SystemTime>, D::Error> {
    match Option::<String>::deserialize(d)? {
        Some(s) => parse_rfc3339(&s)
            .map(Some)
            .ok_or_else(|| D::Error::custom(format!("invalid timestamp {s:?}"))),
        None => Ok(None),
    }
}

/// Parses the RFC 3339 timestamps the API sends
/// (`2026-10-21T09:00:00Z`, optionally with fractional seconds or a
/// `+hh:mm` offset).
fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    fn digits(s: &str, r: std::ops::Range<usize>) -> Option<i64> {
        s.get(r)
            .filter(|d| d.bytes().all(|c| c.is_ascii_digit()))?
            .parse()
            .ok()
    }
    let num = |r| digits(s, r);
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }

    let mut rest = &s[19..];
    let mut nanos = 0;
    if let Some(frac) = rest.strip_prefix('.') {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return None;
        }
        nanos = format!("{:0<9}", &frac[..n.min(9)]).parse().ok()?;
        rest = &frac[n..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            if rest.len() != 6 || rest.as_bytes()[3] != b':' {
                return None;
            }
            sign * (digits(rest, 1..3)? * 3600 + digits(rest, 4..6)? * 60)
        }
    };

    // Days since 1970-01-01 in the proleptic Gregorian calendar (Howard
    // Hinnant's days_from_civil).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((mo + 9) % 12) + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;

    let secs = days * 86_400 + h * 3600 + mi * 60 + sec - offset;
    Some(unix_to_system_time(secs) + Duration::from_nanos(nanos))
}

#[cfg(all(test, feature = "cache"))]
mod renewal_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc3339() {
        let at = |secs: u64, nanos: u64| {
            SystemTime::UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_nanos(nanos)
        };
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(at(0, 0)));
        assert_eq!(
            parse_rfc3339("2026-10-21T09:00:00Z"),
            Some(at(1_792_573_200, 0))
        );
        assert_eq!(
            parse_rfc3339("2024-02-29T23:59:59.5Z"),
            Some(at(1_709_251_199, 500_000_000))
        );
        assert_eq!(
            parse_rfc3339("2026-10-21T11:00:00.123456789+02:00"),
            Some(at(1_792_573_200, 123_456_789))
        );
        assert_eq!(
            parse_rfc3339("2026-10-21T04:30:00-04:30"),
            Some(at(1_792_573_200, 0))
        );
        for bad in [
            "",
            "2026-10-21",
            "2026-10-21T09:00:00",
            "2026-13-01T00:00:00Z",
            "2026-10-21T09:00:00.Z",
            "2026-10-21T09:00:00+0200",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_request_no_client_timeout_ends_is_abandoned_after_its_own() {
        // Bound but never accepted: the connection opens and no reply comes.
        let stalled = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1/renew", stalled.local_addr().unwrap());
        let http = Http {
            agent: ureq::Agent::new_with_defaults(),
            timeout: Duration::from_millis(200),
        };

        let started = std::time::Instant::now();
        let err = http.post(url, b"{}".to_vec()).unwrap_err();
        assert!(matches!(err, LatteError::Network(_)), "got {err:?}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn calls_and_the_background_renewal_have_their_documented_limits() {
        let limits = |http: &Http| {
            let t = http.agent.config().timeouts();
            (http.timeout, t.global, t.resolve, t.connect)
        };
        let five = Some(Duration::from_secs(5));
        let config =
            || Config::with_app_id("pk_test_AHAK85389VQYXYB6S4BW66SKE53TWVTS").with_machine_id("m");

        let sdk = Sdk::new(config()).unwrap();
        let ten = Duration::from_secs(10);
        assert_eq!(limits(&sdk.http), (ten, Some(ten), five, five));
        #[cfg(feature = "cache")]
        assert_eq!(limits(&sdk.background_http), (ten, Some(ten), five, five));

        let sdk = Sdk::new(config().with_timeout(Duration::from_secs(60))).unwrap();
        let sixty = Duration::from_secs(60);
        assert_eq!(limits(&sdk.http), (sixty, Some(sixty), five, five));
        #[cfg(feature = "cache")]
        assert_eq!(limits(&sdk.background_http), (ten, Some(ten), five, five));
    }
}
