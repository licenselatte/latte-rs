//! Tests for `Sdk::activate`/`Sdk::renew`/`Sdk::check` against a mocked
//! LicenseLatte API (`wiremock`), covering:
//!   - the exact wire request shape for activate/renew
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

use latte::error::LatteError;
use latte::http::{Config, Sdk};
use latte::storage;
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
const TEST_MACHINE_ID: &str = "test-machine-id";

/// A fresh, isolated cache path per test: never the real OS config
/// directory, and never shared between tests (`cargo test` runs them
/// concurrently).
fn temp_cache_path() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.json");
    (dir, path)
}

async fn sdk_against(mock_server: &MockServer, cache_path: std::path::PathBuf) -> Sdk {
    let config = Config::with_app_id(TEST_APP_ID)
        .with_base_url(mock_server.uri())
        .with_cache_path(cache_path);
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
            "machine_id": TEST_MACHINE_ID,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token": "not-a-real-jwt",
            "activation_id": "11111111-1111-1111-1111-111111111111",
            "chain": {"submaster": "s", "project": "p", "daily": "d"},
        })))
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path).await;
    // The mock only matches the exact expected body; a mismatch would 404
    // and surface as LicenseNotFound instead of the Server error we expect
    // from the deliberately-bogus token below.
    let err = sdk
        .activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)
        .await
        .unwrap_err();
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
            "machine_id": TEST_MACHINE_ID,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token": "not-a-real-jwt",
            "activation_id": activation_id,
            "chain": {"submaster": "s", "project": "p", "daily": "d"},
        })))
        .mount(&mock_server)
        .await;

    let sdk = sdk_against(&mock_server, cache_path).await;
    let err = sdk
        .renew(activation_id, TEST_LICENSE_KEY, TEST_MACHINE_ID)
        .await
        .unwrap_err();
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

    let sdk = sdk_against(&mock_server, cache_path).await;
    let err = sdk
        .activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)
        .await
        .unwrap_err();
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

        let sdk = sdk_against(&mock_server, cache_path).await;
        let err = sdk
            .activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)
            .await
            .unwrap_err();
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

    let sdk = sdk_against(&mock_server, cache_path).await;
    let err = sdk
        .activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)
        .await
        .unwrap_err();
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

    let sdk = sdk_against(&mock_server, cache_path).await;
    let err = sdk
        .activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)
        .await
        .unwrap_err();
    match err {
        LatteError::Server(msg) => assert_eq!(msg, "server returned empty token"),
        other => panic!("expected Server error, got {other:?}"),
    }
}

#[tokio::test]
async fn transport_failure_is_a_network_error() {
    // Nothing is listening on this port (a closed/unbound loopback port),
    // so the connection itself fails before any HTTP response exists.
    let (_dir, cache_path) = temp_cache_path();
    let config = Config::with_app_id(TEST_APP_ID)
        .with_timeout(std::time::Duration::from_millis(500))
        .with_base_url("http://127.0.0.1:1")
        .with_cache_path(cache_path);
    let sdk = Sdk::new(config).unwrap();

    let err = sdk
        .activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)
        .await
        .unwrap_err();
    assert!(matches!(err, LatteError::Network(_)), "got {err:?}");
}

#[tokio::test]
async fn bad_license_key_format_never_reaches_the_network() {
    // No mock is mounted at all: if activate() incorrectly made a network
    // call here, wiremock's default "no matching stub" 404 response would
    // surface as LicenseNotFound instead of InvalidKey, so this test would
    // fail either way a bug could manifest.
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    let sdk = sdk_against(&mock_server, cache_path).await;

    let err = sdk
        .activate("too-short", TEST_MACHINE_ID)
        .await
        .unwrap_err();
    assert!(matches!(err, LatteError::InvalidKey), "got {err:?}");
}

#[tokio::test]
async fn license_key_short_id_must_match_this_projects_app_key() {
    let mock_server = MockServer::start().await;
    let (_dir, cache_path) = temp_cache_path();
    let sdk = sdk_against(&mock_server, cache_path).await;

    // Right length and checksum, but a short_id belonging to a different
    // project.
    let wrong_project_key = "ZZZZZZBCDEFGHJKMNPQRSTVWXYZ00Z";
    let err = sdk
        .activate(wrong_project_key, TEST_MACHINE_ID)
        .await
        .unwrap_err();
    assert!(matches!(err, LatteError::InvalidKey), "got {err:?}");
}

// --- cache ---

fn garbage_chain() -> latte::domain::CertChain {
    latte::domain::CertChain {
        submaster: "s".to_string(),
        project: "p".to_string(),
        daily: "d".to_string(),
    }
}

#[tokio::test]
async fn check_reports_not_activated_when_nothing_is_cached() {
    let (_dir, cache_path) = temp_cache_path();
    let config = Config::with_app_id(TEST_APP_ID).with_cache_path(cache_path);
    let sdk = Sdk::new(config).unwrap();

    let err = sdk.check(TEST_MACHINE_ID).unwrap_err();
    assert!(matches!(err, LatteError::NotActivated), "got {err:?}");
}

#[tokio::test]
async fn check_reports_not_activated_for_a_cache_that_fails_verification() {
    let (_dir, cache_path) = temp_cache_path();
    storage::save(&cache_path, "not-a-real-jwt", &garbage_chain()).unwrap();

    let config = Config::with_app_id(TEST_APP_ID).with_cache_path(cache_path);
    let sdk = Sdk::new(config).unwrap();

    let err = sdk.check(TEST_MACHINE_ID).unwrap_err();
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

    let sdk = sdk_against(&mock_server, cache_path).await;
    // LicenseNotFound only happens on the network path; reaching it proves
    // the unverifiable cache entry didn't short-circuit into a false
    // "success" or a cache-specific error.
    let err = sdk
        .activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)
        .await
        .unwrap_err();
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

    let sdk = sdk_against(&mock_server, cache_path.clone()).await;
    let _ = sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID).await;

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

    let sdk = sdk_against(&mock_server, cache_path.clone()).await;
    let _ = sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID).await;

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

    let sdk = sdk_against(&mock_server, cache_path.clone()).await;
    let activation_id = "11111111-1111-1111-1111-111111111111";
    let _ = sdk
        .renew(activation_id, TEST_LICENSE_KEY, TEST_MACHINE_ID)
        .await;

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

    let sdk = sdk_against(&mock_server, cache_path.clone()).await;
    let _ = sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID).await;

    // A 500 doesn't mean the activation is gone, just that something else
    // went wrong; an existing cache entry (unverifiable or not) shouldn't
    // be touched over it.
    assert!(cache_path.exists());
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
