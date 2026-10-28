//! Background renewal driven from `Sdk::check`, against a mocked API and
//! the shared test vectors. These live inside the crate because `Sdk`
//! verifies against the production master keys and the system clock; the
//! tests swap in the vectors' key and a settable clock through its private
//! fields, which an integration test cannot reach.

use super::*;
use crate::storage;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_APP_ID: &str = "pk_test_AHAK85389VQYXYB6S4BW66SKE53TWVTS";
const ACTIVATION_ID: &str = "act_22222222-2222-2222-2222-222222222222";
const LICENSE_KEY: &str = "AHAK85T628WZ639CMVHF8TNDDX260Z";

#[derive(Deserialize)]
struct Vector {
    now: String,
    master_public_key_hex: String,
    token: String,
    chain: CertChain,
}

impl Vector {
    fn load(name: &str) -> Self {
        let file = format!(
            "{}/testdata/vectors/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap()
    }

    fn key(&self) -> VerifyingKey {
        let bytes: [u8; 32] = hex::decode(&self.master_public_key_hex)
            .unwrap()
            .try_into()
            .unwrap();
        VerifyingKey::from_bytes(&bytes).unwrap()
    }

    fn now(&self) -> SystemTime {
        parse_rfc3339(&self.now).unwrap()
    }

    fn response(&self) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "token": self.token,
            "activation_id": ACTIVATION_ID,
            "chain": {
                "submaster": self.chain.submaster,
                "project": self.chain.project,
                "daily": self.chain.daily,
            },
        }))
    }
}

/// An `Sdk` whose cache holds one vector, whose clock reads that vector's
/// pinned `now` until moved, and whose server is a mock.
struct Rig {
    server: MockServer,
    sdk: Sdk,
    cache: std::path::PathBuf,
    clock: Arc<AtomicU64>,
    renewed: Vector,
    _dir: tempfile::TempDir,
}

impl Rig {
    /// `cached` is the vector the cache starts with; a renewal that
    /// succeeds returns `valid_fresh`.
    async fn new(cached: &str) -> Self {
        let cached = Vector::load(cached);
        let renewed = Vector::load("valid_fresh");
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache.json");
        storage::save(&cache, &cached.token, &cached.chain).unwrap();

        let mut sdk = Sdk::new(
            Config::with_app_id(TEST_APP_ID)
                .with_base_url(server.uri())
                .with_cache_path(&cache)
                .with_machine_id("test-machine-001"),
        )
        .unwrap();
        sdk.machine_id = "test-machine-001".into();
        sdk.master_pubs = vec![cached.key(), renewed.key()];
        let secs = cached
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let clock = Arc::new(AtomicU64::new(secs));
        let c = clock.clone();
        sdk.clock = Arc::new(move || {
            SystemTime::UNIX_EPOCH + Duration::from_secs(c.load(Ordering::SeqCst))
        });

        Rig {
            server,
            sdk,
            cache,
            clock,
            renewed,
            _dir: dir,
        }
    }

    async fn reply(&self, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/v1/renew"))
            .respond_with(response)
            .mount(&self.server)
            .await;
    }

    fn advance(&self, secs: u64) {
        self.clock.fetch_add(secs, Ordering::SeqCst);
    }

    /// Waits for the renewal `check` started, if it started one.
    async fn idle(&self) {
        for _ in 0..1000 {
            if !self.sdk.renewal().in_flight {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("renewal still in flight after 5s");
    }

    async fn requests(&self) -> Vec<wiremock::Request> {
        self.server.received_requests().await.unwrap()
    }

    fn cached_token(&self) -> Option<String> {
        storage::load(&self.cache).map(|(token, _)| token)
    }
}

#[tokio::test]
async fn an_old_token_is_renewed_in_the_background_and_the_new_one_is_cached() {
    let rig = Rig::new("valid_in_grace_period").await;
    rig.reply(rig.renewed.response()).await;

    let lic = rig.sdk.check().unwrap();
    assert!(lic.in_grace_period, "check answers from the cached token");
    rig.idle().await;

    let requests = rig.requests().await;
    assert_eq!(requests.len(), 1);
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["activation_id"], ACTIVATION_ID);
    assert_eq!(body["license_key"], LICENSE_KEY);
    assert_eq!(rig.cached_token(), Some(rig.renewed.token.clone()));
    assert!(!rig.sdk.check().unwrap().in_grace_period);
}

#[tokio::test]
async fn a_token_under_sixty_minutes_old_is_not_renewed() {
    let rig = Rig::new("valid_fresh").await;
    rig.reply(rig.renewed.response()).await;

    rig.sdk.check().unwrap();
    rig.idle().await;
    assert!(rig.requests().await.is_empty());

    rig.advance(59 * 60);
    rig.sdk.check().unwrap();
    rig.idle().await;
    assert!(rig.requests().await.is_empty());

    rig.advance(60);
    rig.sdk.check().unwrap();
    rig.idle().await;
    assert_eq!(rig.requests().await.len(), 1);
}

#[tokio::test]
async fn check_returns_while_the_renewal_is_still_running_and_starts_no_second_one() {
    let rig = Rig::new("valid_in_grace_period").await;
    rig.reply(rig.renewed.response().set_delay(Duration::from_millis(300)))
        .await;

    rig.sdk.check().unwrap();
    assert!(rig.sdk.renewal().in_flight);

    rig.advance(10 * 60);
    rig.sdk.check().unwrap();
    rig.idle().await;
    assert_eq!(rig.requests().await.len(), 1);
}

#[tokio::test]
async fn attempts_are_at_least_five_minutes_apart_even_when_they_fail() {
    let rig = Rig::new("valid_in_grace_period").await;
    rig.reply(ResponseTemplate::new(500)).await;

    for (advance, total) in [(0, 1), (0, 1), (299, 1), (1, 2), (299, 2), (1, 3)] {
        rig.advance(advance);
        rig.sdk.check().unwrap();
        rig.idle().await;
        assert_eq!(rig.requests().await.len(), total, "after +{advance}s");
    }
}

#[tokio::test]
async fn a_rejection_clears_the_cache_and_every_other_failure_keeps_it() {
    for (status, cleared) in [
        (404, true),
        (403, true),
        (401, true),
        (409, false),
        (429, false),
        (500, false),
        (503, false),
    ] {
        let rig = Rig::new("valid_in_grace_period").await;
        let before = rig.cached_token();
        rig.reply(ResponseTemplate::new(status).set_body_json(json!({"error": "nope"})))
            .await;

        rig.sdk.check().unwrap();
        rig.idle().await;

        let expected = if cleared { None } else { before };
        assert_eq!(rig.cached_token(), expected, "status {status}");
        if cleared {
            assert!(matches!(rig.sdk.check(), Err(LatteError::NotActivated)));
        }
    }
}

#[tokio::test]
async fn an_unreachable_server_or_a_bad_renewed_token_keeps_the_cached_one() {
    let mut rig = Rig::new("valid_in_grace_period").await;
    let before = rig.cached_token();
    rig.sdk.base_url = "http://127.0.0.1:1".into();
    rig.sdk.check().unwrap();
    rig.idle().await;
    assert_eq!(rig.cached_token(), before);

    let rig = Rig::new("valid_in_grace_period").await;
    let before = rig.cached_token();
    rig.reply(ResponseTemplate::new(200).set_body_json(json!({
        "token": "not-a-jwt",
        "activation_id": ACTIVATION_ID,
        "chain": {"submaster": "s", "project": "p", "daily": "d"},
    })))
    .await;
    rig.sdk.check().unwrap();
    rig.idle().await;
    assert_eq!(rig.requests().await.len(), 1);
    assert_eq!(rig.cached_token(), before);
}

#[tokio::test]
async fn a_renewal_never_writes_back_or_wipes_an_activation_the_cache_no_longer_holds() {
    // A success that lands after the cache was emptied (a deactivation).
    let rig = Rig::new("valid_in_grace_period").await;
    rig.reply(rig.renewed.response().set_delay(Duration::from_millis(200)))
        .await;
    rig.sdk.check().unwrap();
    storage::clear(&rig.cache).unwrap();
    rig.idle().await;
    assert_eq!(rig.cached_token(), None);

    // A rejection that lands after a different token was cached.
    let rig = Rig::new("valid_in_grace_period").await;
    rig.reply(
        ResponseTemplate::new(404)
            .set_body_json(json!({"error": "gone"}))
            .set_delay(Duration::from_millis(200)),
    )
    .await;
    rig.sdk.check().unwrap();
    let chain = rig.renewed.chain.clone();
    storage::save(&rig.cache, "someone-else", &chain).unwrap();
    rig.idle().await;
    assert_eq!(rig.cached_token().as_deref(), Some("someone-else"));
}

#[tokio::test]
async fn a_manual_renew_counts_as_an_attempt() {
    let rig = Rig::new("valid_in_grace_period").await;
    rig.reply(ResponseTemplate::new(500)).await;

    rig.sdk.renew(ACTIVATION_ID, LICENSE_KEY).await.unwrap_err();
    rig.sdk.check().unwrap();
    rig.idle().await;
    assert_eq!(rig.requests().await.len(), 1);

    rig.advance(300);
    rig.sdk.check().unwrap();
    rig.idle().await;
    assert_eq!(rig.requests().await.len(), 2);
}

#[tokio::test]
async fn a_manual_renew_saves_the_new_token() {
    let rig = Rig::new("valid_in_grace_period").await;
    rig.reply(rig.renewed.response()).await;

    let lic = rig.sdk.renew(ACTIVATION_ID, LICENSE_KEY).await.unwrap();
    assert!(!lic.in_grace_period);
    assert_eq!(rig.cached_token(), Some(rig.renewed.token.clone()));
}

#[tokio::test]
async fn a_token_past_its_grace_deadline_is_renewed_and_a_later_check_succeeds() {
    let rig = Rig::new("expired_past_grace_deadline").await;
    rig.reply(rig.renewed.response()).await;

    assert!(matches!(rig.sdk.check(), Err(LatteError::NotActivated)));
    rig.idle().await;
    assert_eq!(rig.requests().await.len(), 1);
    assert_eq!(rig.cached_token(), Some(rig.renewed.token.clone()));

    let lic = rig.sdk.check().unwrap();
    assert_eq!(lic.activation_id, ACTIVATION_ID);
    rig.idle().await;
    assert_eq!(rig.requests().await.len(), 1);
}

#[tokio::test]
async fn a_token_whose_licence_and_daily_cert_have_lapsed_is_renewed_too() {
    let rig = Rig::new("clock_skew_after_cert_validity").await;
    rig.reply(rig.renewed.response()).await;

    assert!(matches!(rig.sdk.check(), Err(LatteError::LicenseExpired)));
    rig.idle().await;
    assert_eq!(rig.requests().await.len(), 1);
    assert!(rig.sdk.check().is_ok());
}

#[tokio::test]
async fn a_token_that_does_not_verify_or_is_for_another_machine_is_never_renewed() {
    for cached in [
        "tampered_payload",
        "invalid_signature",
        "malformed_garbage_token",
    ] {
        let rig = Rig::new(cached).await;
        rig.reply(rig.renewed.response()).await;
        rig.advance(2 * 60 * 60);
        assert!(rig.sdk.check().is_err());
        rig.idle().await;
        assert!(rig.requests().await.is_empty(), "{cached}");
    }

    let mut rig = Rig::new("expired_past_grace_deadline").await;
    rig.reply(rig.renewed.response()).await;
    rig.sdk.machine_id = "another-machine".into();
    assert!(rig.sdk.check().is_err());
    rig.idle().await;
    assert!(rig.requests().await.is_empty());
}

#[tokio::test]
async fn a_rejected_renewal_of_a_past_grace_token_clears_the_cache() {
    let rig = Rig::new("expired_past_grace_deadline").await;
    rig.reply(ResponseTemplate::new(404).set_body_json(json!({"error": "gone"})))
        .await;

    assert!(rig.sdk.check().is_err());
    rig.idle().await;
    assert_eq!(rig.requests().await.len(), 1);
    assert_eq!(rig.cached_token(), None);
}

#[tokio::test]
async fn a_failed_renewal_of_a_past_grace_token_keeps_the_cache_and_waits_five_minutes() {
    let mut rig = Rig::new("expired_past_grace_deadline").await;
    let before = rig.cached_token();
    rig.sdk.base_url = "http://127.0.0.1:1".into();
    assert!(rig.sdk.check().is_err());
    rig.idle().await;
    assert_eq!(rig.cached_token(), before);

    let rig = Rig::new("expired_past_grace_deadline").await;
    let before = rig.cached_token();
    rig.reply(ResponseTemplate::new(503)).await;
    for (advance, total) in [(0, 1), (299, 1), (1, 2)] {
        rig.advance(advance);
        assert!(rig.sdk.check().is_err());
        rig.idle().await;
        assert_eq!(rig.requests().await.len(), total, "after +{advance}s");
    }
    assert_eq!(rig.cached_token(), before);
}
