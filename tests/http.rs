//! Tests for `Sdk::activate`/`Sdk::renew`/`Sdk::check` and the machine
//! calls (`deactivate`/`machines`/`rename_machine`) against a mocked
//! LicenseLatte API (`wiremock`), covering:
//!   - the exact wire request shape for every call
//!   - status-code -> sentinel error mapping
//!   - transport-level failure -> `LatteError::Network`
//!   - malformed/empty response bodies -> `LatteError::Server`
//!   - bad license-key format short-circuiting before any network call
//!   - the on-disk cache: falling through when it's unreadable/unverifiable,
//!     not writing a token that failed verification, and clearing it when
//!     the server says the activation no longer exists
//!
//! What this file deliberately does *not* test: a full activate() success
//! path returning a real `PublicLicense`, or `check()`'s success/expired
//! branches. `Sdk` verifies against the hardcoded production master public
//! key; the matching private key lives only on LicenseLatte's real
//! backend, so nothing in this repo can produce a token this crate would
//! actually accept. The crypto pipeline itself (`check_license_at` and
//! everything it calls) is already exhaustively covered by
//! `tests/fixtures.rs` against real (test) key material, so this file only
//! needs to prove the network/cache plumbing correctly feeds a
//! syntactically-valid response into that pipeline, which the
//! "server-returned token fails verification" test below confirms end to
//! end (it just can't also assert *acceptance*, for the reason above).
//! `src/storage.rs`'s own unit tests separately cover the cache file
//! format/atomicity in isolation, with no key material involved at all.

#![cfg(all(feature = "http", feature = "cache"))]

use latte_rs::error::LatteError;
use latte_rs::http::{Config, Sdk};
use latte_rs::storage;
use serde_json::json;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// A valid AppID (`pk_test_{28-char data}{4-char checksum}`) and a matching
// license key (`{6-char short_id}{22 random}{2-char checksum}`), computed
// against the checksum algorithm in `src/key.rs` (its helpers are
// `pub(crate)`, not exported, so these can't be computed inline from an
// external integration test).
const TEST_APP_ID: &str = "pk_test_AHAK85389VQYXYB6S4BW66SKE53TWVTS";
const TEST_LICENSE_KEY: &str = "AHAK85BCDEFGHJKMNPQRSTVWXYZ00Z";
// The raw machine ID every test supplies, and the HMAC-derived value the
// SDK sends in its place (testdata/machine_id.json pins the derivation).
const TEST_RAW_MACHINE_ID: &str = "test-machine-id";

fn test_machine_id() -> String {
    latte_rs::machine_id::derive(TEST_APP_ID, Some(TEST_RAW_MACHINE_ID)).unwrap()
}

/// A fresh, isolated cache path per test: never the real OS config
/// directory, and never shared between tests (`cargo test` runs them
/// concurrently).
fn temp_cache_path() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.json");
    (dir, path)
}

fn sdk_against(mock_server: &MockServer, cache_path: std::path::PathBuf) -> Sdk {
    let config = Config::with_app_id(TEST_APP_ID)
        .with_base_url(mock_server.uri())
        .with_cache_path(cache_path)
        .with_machine_id(TEST_RAW_MACHINE_ID);
    Sdk::new(config).expect("valid test AppID")
}

#[tokio::test]
async fn activate_sends_the_documented_request_shape() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    Mock::given(method("POST"))
        .and(path("/v1/activate"))
        .and(body_json(json!({
            "project_key": TEST_APP_ID,
            "license_key": TEST_LICENSE_KEY,
            "machine_id": test_machine_id(),
            "sdk": {"language": "rust", "version": env!("CARGO_PKG_VERSION")},
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token": "not-a-real-jwt",
            "activation_id": "11111111-1111-1111-1111-111111111111",
            "chain": {"submaster": "s", "project": "p", "daily": "d"},
        })))
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path);
    // The mock only matches the exact expected body; a mismatch would 404
    // and surface as LicenseNotFound instead of the Server error we expect
    // from the deliberately-bogus token below.
    let err = sdk.activate(TEST_LICENSE_KEY).unwrap_err();
    assert!(matches!(err, LatteError::Server(_)), "got {err:?}");
}

#[tokio::test]
async fn renew_sends_the_documented_request_shape_without_project_key() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    let activation_id = "11111111-1111-1111-1111-111111111111";
    Mock::given(method("POST"))
        .and(path("/v1/renew"))
        .and(body_json(json!({
            "activation_id": activation_id,
            "license_key": TEST_LICENSE_KEY,
            "machine_id": test_machine_id(),
            "sdk": {"language": "rust", "version": env!("CARGO_PKG_VERSION")},
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token": "not-a-real-jwt",
            "activation_id": activation_id,
            "chain": {"submaster": "s", "project": "p", "daily": "d"},
        })))
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path);
    let err = sdk.renew(activation_id, TEST_LICENSE_KEY).unwrap_err();
    assert!(matches!(err, LatteError::Server(_)), "got {err:?}");
}

#[tokio::test]
async fn server_returned_token_that_fails_verification_is_a_server_error_not_a_panic() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    Mock::given(method("POST"))
        .and(path("/v1/activate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token": "not-a-real-jwt",
            "activation_id": "11111111-1111-1111-1111-111111111111",
            "chain": {"submaster": "s", "project": "p", "daily": "d"},
        })))
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path);
    let err = sdk.activate(TEST_LICENSE_KEY).unwrap_err();
    match err {
        LatteError::Server(msg) => assert!(msg.starts_with("server returned invalid token:")),
        other => panic!("expected Server error, got {other:?}"),
    }
}

#[tokio::test]
async fn status_codes_map_to_the_documented_sentinels() {
    let cases = [
        (404, LatteErrorKind::LicenseNotFound),
        (403, LatteErrorKind::LicenseExpired),
        (409, LatteErrorKind::SeatLimit),
        (401, LatteErrorKind::InvalidProjectKey),
    ];

    for (status, expected) in cases {
        let mock_server = MockServer::start().await;
        let (_dir, cache_path) = temp_cache_path();
        Mock::given(method("POST"))
            .and(path("/v1/activate"))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({"error": "nope"})))
            .mount(&mock_server)
            .await;

        let sdk = sdk_against(&mock_server, cache_path);
        let err = sdk.activate(TEST_LICENSE_KEY).unwrap_err();
        assert_eq!(LatteErrorKind::from(&err), expected, "status {status}");
    }
}

#[tokio::test]
async fn unmapped_status_code_is_a_server_error_with_the_server_message() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    Mock::given(method("POST"))
        .and(path("/v1/activate"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"error": "something broke"})))
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path);
    let err = sdk.activate(TEST_LICENSE_KEY).unwrap_err();
    match err {
        LatteError::Server(msg) => assert_eq!(msg, "something broke"),
        other => panic!("expected Server error, got {other:?}"),
    }
}

#[tokio::test]
async fn empty_token_in_a_200_response_is_a_server_error() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    Mock::given(method("POST"))
        .and(path("/v1/activate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token": "",
            "activation_id": "11111111-1111-1111-1111-111111111111",
            "chain": {"submaster": "s", "project": "p", "daily": "d"},
        })))
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path);
    let err = sdk.activate(TEST_LICENSE_KEY).unwrap_err();
    match err {
        LatteError::Server(msg) => assert_eq!(msg, "server returned empty token"),
        other => panic!("expected Server error, got {other:?}"),
    }
}

#[test]
fn transport_failure_is_a_network_error() {
    // Nothing is listening on this port (a closed/unbound loopback port),
    // so the connection itself fails before any HTTP response exists.
    let (_dir, cache_path) = temp_cache_path();
    let config = Config::with_app_id(TEST_APP_ID)
        .with_timeout(std::time::Duration::from_millis(500))
        .with_base_url("http://127.0.0.1:1")
        .with_cache_path(cache_path)
        .with_machine_id(TEST_RAW_MACHINE_ID);
    let sdk = Sdk::new(config).unwrap();

    let err = sdk.activate(TEST_LICENSE_KEY).unwrap_err();
    assert!(matches!(err, LatteError::Network(_)), "got {err:?}");
}

#[test]
fn a_server_that_never_answers_is_a_network_error_once_the_timeout_passes() {
    // Bound but never accepted: the connection opens and no reply comes.
    let stalled = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (_dir, cache_path) = temp_cache_path();
    let config = Config::with_app_id(TEST_APP_ID)
        .with_timeout(std::time::Duration::from_millis(300))
        .with_base_url(format!("http://{}", stalled.local_addr().unwrap()))
        .with_cache_path(cache_path)
        .with_machine_id(TEST_RAW_MACHINE_ID);
    let sdk = Sdk::new(config).unwrap();

    let started = std::time::Instant::now();
    let err = sdk.activate(TEST_LICENSE_KEY).unwrap_err();
    assert!(matches!(err, LatteError::Network(_)), "got {err:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
}

#[tokio::test]
async fn empty_license_key_never_reaches_the_network() {
    // No mock is mounted at all: if activate() incorrectly made a network
    // call here, wiremock's default "no matching stub" 404 response would
    // surface as LicenseNotFound instead of InvalidKey, so this test would
    // fail either way a bug could manifest.
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    let sdk = sdk_against(&mock_server, cache_path);

    let err = sdk.activate("").unwrap_err();
    assert!(matches!(err, LatteError::InvalidKey), "got {err:?}");
}

#[tokio::test]
async fn non_native_format_key_reaches_the_network_instead_of_being_rejected_locally() {
    // Doesn't match this project's short_id and fails the checksum -- the
    // strict format gate used to reject this before ever calling the
    // network. Now the server is the sole arbiter of native vs.
    // legacy-alias vs. not-found, so it must reach the network unchanged
    // (normalized only: uppercased, separators stripped).
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    Mock::given(method("POST"))
        .and(path("/v1/activate"))
        .and(body_json(json!({
            "project_key": TEST_APP_ID,
            "license_key": "ACMELEGACY2019KEY",
            "machine_id": test_machine_id(),
            "sdk": {"language": "rust", "version": env!("CARGO_PKG_VERSION")},
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token": "not-a-real-jwt",
            "activation_id": "11111111-1111-1111-1111-111111111111",
            "chain": {"submaster": "s", "project": "p", "daily": "d"},
        })))
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path);
    let err = sdk.activate("acme-legacy-2019-key").unwrap_err();
    assert!(matches!(err, LatteError::Server(_)), "got {err:?}");
}

// --- cache ---

fn garbage_chain() -> latte_rs::domain::CertChain {
    latte_rs::domain::CertChain {
        submaster: "s".to_string(),
        project: "p".to_string(),
        daily: "d".to_string(),
    }
}

#[test]
fn check_reports_not_activated_when_nothing_is_cached() {
    let (_dir, cache_path) = temp_cache_path();
    let config = Config::with_app_id(TEST_APP_ID)
        .with_cache_path(cache_path)
        .with_machine_id(TEST_RAW_MACHINE_ID);
    let sdk = Sdk::new(config).unwrap();

    let err = sdk.check().unwrap_err();
    assert!(matches!(err, LatteError::NotActivated), "got {err:?}");
}

#[test]
fn check_reports_not_activated_for_a_cache_that_fails_verification() {
    let (_dir, cache_path) = temp_cache_path();
    storage::save(&cache_path, "not-a-real-jwt", &garbage_chain()).unwrap();

    let config = Config::with_app_id(TEST_APP_ID)
        .with_cache_path(cache_path)
        .with_machine_id(TEST_RAW_MACHINE_ID);
    let sdk = Sdk::new(config).unwrap();

    let err = sdk.check().unwrap_err();
    assert!(matches!(err, LatteError::NotActivated), "got {err:?}");
}

#[tokio::test]
async fn activate_falls_through_to_the_network_when_the_cache_is_unverifiable() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    storage::save(&cache_path, "not-a-real-jwt", &garbage_chain()).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/activate"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path);
    // LicenseNotFound only happens on the network path; reaching it proves
    // the unverifiable cache entry didn't short-circuit into a false
    // "success" or a cache-specific error.
    let err = sdk.activate(TEST_LICENSE_KEY).unwrap_err();
    assert!(matches!(err, LatteError::LicenseNotFound), "got {err:?}");
}

#[tokio::test]
async fn activate_does_not_cache_a_server_response_that_fails_verification() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    Mock::given(method("POST"))
        .and(path("/v1/activate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token": "not-a-real-jwt",
            "activation_id": "11111111-1111-1111-1111-111111111111",
            "chain": {"submaster": "s", "project": "p", "daily": "d"},
        })))
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path.clone());
    let _ = sdk.activate(TEST_LICENSE_KEY);

    assert!(storage::load(&cache_path).is_none());
}

#[tokio::test]
async fn activate_clears_an_existing_cache_entry_on_license_not_found() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    storage::save(&cache_path, "not-a-real-jwt", &garbage_chain()).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/activate"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path.clone());
    let _ = sdk.activate(TEST_LICENSE_KEY);

    assert!(storage::load(&cache_path).is_none());
}

#[tokio::test]
async fn renew_clears_an_existing_cache_entry_on_license_expired() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    storage::save(&cache_path, "not-a-real-jwt", &garbage_chain()).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/renew"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path.clone());
    let activation_id = "11111111-1111-1111-1111-111111111111";
    let _ = sdk.renew(activation_id, TEST_LICENSE_KEY);

    assert!(storage::load(&cache_path).is_none());
}

#[tokio::test]
async fn activate_leaves_an_existing_cache_entry_alone_on_an_unrelated_server_error() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    storage::save(&cache_path, "not-a-real-jwt", &garbage_chain()).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/activate"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path.clone());
    let _ = sdk.activate(TEST_LICENSE_KEY);

    // A 500 doesn't mean the activation is gone, just that something else
    // went wrong; an existing cache entry (unverifiable or not) shouldn't
    // be touched over it.
    assert!(cache_path.exists());
}

// --- deactivate, machines, rename ---

const TEST_ACTIVATION_ID: &str = "11111111-1111-1111-1111-111111111111";

fn credentials_body() -> serde_json::Value {
    json!({
        "activation_id": TEST_ACTIVATION_ID,
        "license_key": TEST_LICENSE_KEY,
        "machine_id": test_machine_id(),
        "sdk": {"language": "rust", "version": env!("CARGO_PKG_VERSION")},
    })
}

fn unix(secs: u64) -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)
}

#[tokio::test]
async fn deactivate_sends_renews_credentials_and_forgets_the_token() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    storage::save(&cache_path, "not-a-real-jwt", &garbage_chain()).unwrap();
    Mock::given(method("POST"))
        .and(path("/v1/deactivate"))
        .and(body_json(credentials_body()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"released": true, "seat_free_at": "2026-10-21T09:00:00Z"})),
        )
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path.clone());
    let res = sdk
        .deactivate(TEST_ACTIVATION_ID, TEST_LICENSE_KEY)
        .unwrap();
    assert!(res.released);
    assert_eq!(res.seat_free_at, Some(unix(1_792_573_200)));
    assert!(storage::load(&cache_path).is_none());
    let err = sdk.check().unwrap_err();
    assert!(matches!(err, LatteError::NotActivated), "got {err:?}");
}

#[tokio::test]
async fn deactivate_that_was_already_released_is_success_and_forgets_the_token() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    storage::save(&cache_path, "not-a-real-jwt", &garbage_chain()).unwrap();
    Mock::given(method("POST"))
        .and(path("/v1/deactivate"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"released": false, "seat_free_at": null})),
        )
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path.clone());
    let res = sdk
        .deactivate(TEST_ACTIVATION_ID, TEST_LICENSE_KEY)
        .unwrap();
    assert!(!res.released);
    assert_eq!(res.seat_free_at, None);
    assert!(storage::load(&cache_path).is_none());
}

#[tokio::test]
async fn deactivate_refused_by_policy_is_deactivation_blocked_and_keeps_the_token() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    storage::save(&cache_path, "not-a-real-jwt", &garbage_chain()).unwrap();
    Mock::given(method("POST"))
        .and(path("/v1/deactivate"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error": "Wait a week.",
            "reason": "deactivation_cooldown",
            "available_at": "2026-10-21T09:00:00Z",
        })))
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path.clone());
    let err = sdk
        .deactivate(TEST_ACTIVATION_ID, TEST_LICENSE_KEY)
        .unwrap_err();
    match err {
        LatteError::DeactivationBlocked {
            message,
            reason,
            available_at,
        } => {
            assert_eq!(message, "Wait a week.");
            assert_eq!(reason, "deactivation_cooldown");
            assert_eq!(available_at, Some(unix(1_792_573_200)));
        }
        other => panic!("expected DeactivationBlocked, got {other:?}"),
    }
    assert!(storage::load(&cache_path).is_some());
}

#[tokio::test]
async fn deactivate_keeps_the_token_on_statuses_that_clear_it_for_renew() {
    for status in [403, 404, 401] {
        let mock_server = MockServer::start().await;
        let (_dir, cache_path) = temp_cache_path();
        storage::save(&cache_path, "not-a-real-jwt", &garbage_chain()).unwrap();
        Mock::given(method("POST"))
            .and(path("/v1/deactivate"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&mock_server)
            .await;

        let sdk = sdk_against(&mock_server, cache_path.clone());
        assert!(sdk
            .deactivate(TEST_ACTIVATION_ID, TEST_LICENSE_KEY)
            .is_err());
        assert!(storage::load(&cache_path).is_some(), "status {status}");
    }
}

#[test]
fn deactivate_network_failure_keeps_the_token() {
    let (_dir, cache_path) = temp_cache_path();
    storage::save(&cache_path, "not-a-real-jwt", &garbage_chain()).unwrap();
    let config = Config::with_app_id(TEST_APP_ID)
        .with_timeout(std::time::Duration::from_millis(500))
        .with_base_url("http://127.0.0.1:1")
        .with_cache_path(cache_path.clone())
        .with_machine_id(TEST_RAW_MACHINE_ID);
    let sdk = Sdk::new(config).unwrap();

    let err = sdk
        .deactivate(TEST_ACTIVATION_ID, TEST_LICENSE_KEY)
        .unwrap_err();
    assert!(matches!(err, LatteError::Network(_)), "got {err:?}");
    assert!(storage::load(&cache_path).is_some());
}

#[tokio::test]
async fn machines_parses_the_list() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    Mock::given(method("POST"))
        .and(path("/v1/machines"))
        .and(body_json(credentials_body()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"machines": [
            {"machine_name": "Studio", "machine_fingerprint": "9f1c4a0b2d3e", "activated_at": "2026-10-01T00:00:00Z", "last_seen_at": "2026-10-14T00:00:00Z", "current": true},
            {"machine_fingerprint": "0a1b2c3d4e5f", "activated_at": "2026-09-01T00:00:00Z", "last_seen_at": "2026-09-02T00:00:00Z", "seat_free_at": "2026-10-20T00:00:00Z", "current": false},
        ]})))
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path);
    let machines = sdk.machines(TEST_ACTIVATION_ID, TEST_LICENSE_KEY).unwrap();
    assert_eq!(machines.len(), 2);
    assert_eq!(machines[0].name.as_deref(), Some("Studio"));
    assert_eq!(machines[0].fingerprint, "9f1c4a0b2d3e");
    assert_eq!(machines[0].activated_at, unix(1_790_812_800));
    assert_eq!(machines[0].last_seen_at, unix(1_791_936_000));
    assert_eq!(machines[0].seat_free_at, None);
    assert!(machines[0].current);
    assert_eq!(machines[1].name, None);
    assert_eq!(machines[1].seat_free_at, Some(unix(1_792_454_400)));
    assert!(!machines[1].current);
}

#[tokio::test]
async fn rename_machine_sends_the_name_and_returns_the_stored_one() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    let mut body = credentials_body();
    body["machine_name"] = json!(" Studio Mac ");
    Mock::given(method("POST"))
        .and(path("/v1/machines/rename"))
        .and(body_json(body))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"machine_name": "Studio Mac"})),
        )
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path);
    let name = sdk
        .rename_machine(TEST_ACTIVATION_ID, TEST_LICENSE_KEY, " Studio Mac ")
        .unwrap();
    assert_eq!(name, "Studio Mac");
}

#[tokio::test]
async fn activate_sends_machine_name_when_configured_and_omits_it_when_empty() {
    for (configured, sent) in [("Studio Mac", Some("Studio Mac")), ("", None)] {
        let mock_server = MockServer::start().await;
        let (_dir, cache_path) = temp_cache_path();
        let mut body = json!({
            "project_key": TEST_APP_ID,
            "license_key": TEST_LICENSE_KEY,
            "machine_id": test_machine_id(),
            "sdk": {"language": "rust", "version": env!("CARGO_PKG_VERSION")},
        });
        if let Some(name) = sent {
            body["machine_name"] = json!(name);
        }
        // Only the exact body answers 401; anything else falls through to
        // wiremock's 404.
        Mock::given(method("POST"))
            .and(path("/v1/activate"))
            .and(body_json(body))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let config = Config::with_app_id(TEST_APP_ID)
            .with_base_url(mock_server.uri())
            .with_cache_path(cache_path)
            .with_machine_id(TEST_RAW_MACHINE_ID)
            .with_machine_name(configured);
        let sdk = Sdk::new(config).unwrap();
        let err = sdk.activate(TEST_LICENSE_KEY).unwrap_err();
        assert!(
            matches!(err, LatteError::InvalidProjectKey),
            "name {configured:?}: got {err:?}"
        );
    }
}

/// A `PartialEq`-able projection of the sentinel `LatteError` variants
/// under test, so the table-driven status-code test above can compare
/// outcomes without `LatteError` itself needing to derive `PartialEq`
/// (its `Server`/`Network` variants intentionally carry free-form
/// messages that shouldn't participate in equality).
#[derive(Debug, PartialEq, Eq)]
enum LatteErrorKind {
    LicenseNotFound,
    LicenseExpired,
    SeatLimit,
    InvalidProjectKey,
    Other,
}

impl From<&LatteError> for LatteErrorKind {
    fn from(e: &LatteError) -> Self {
        match e {
            LatteError::LicenseNotFound => LatteErrorKind::LicenseNotFound,
            LatteError::LicenseExpired => LatteErrorKind::LicenseExpired,
            LatteError::SeatLimit => LatteErrorKind::SeatLimit,
            LatteError::InvalidProjectKey => LatteErrorKind::InvalidProjectKey,
            _ => LatteErrorKind::Other,
        }
    }
}

#[test]
fn sdk_exposes_the_derived_machine_id_never_the_raw_one() {
    let config = Config::with_app_id(TEST_APP_ID).with_machine_id(TEST_RAW_MACHINE_ID);
    let sdk = Sdk::new(config).unwrap();
    assert_eq!(sdk.machine_id(), test_machine_id());
    assert_ne!(sdk.machine_id(), TEST_RAW_MACHINE_ID);
    assert_eq!(sdk.machine_id().len(), 64);
}
