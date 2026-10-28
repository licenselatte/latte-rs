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
    assert!(!lic.in_grace_period, "no renewal has failed");
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

// --- the in_grace_period flag ---

/// A client whose requests give up after 200ms, for a server that answers
/// later than that.
fn quick_timeout() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap()
}

impl Rig {
    /// Runs one background renewal against a server nothing listens on. The
    /// clock stays put, so a `check` that follows starts no renewal of its
    /// own until the test advances it.
    async fn fail_to_reach_the_server(&mut self) {
        let reachable = std::mem::replace(&mut self.sdk.base_url, "http://127.0.0.1:1".into());
        self.sdk.check().unwrap();
        self.idle().await;
        self.sdk.base_url = reachable;
    }
}

#[tokio::test]
async fn a_background_renewal_that_cannot_reach_the_server_sets_the_flag() {
    let mut rig = Rig::new("valid_in_grace_period").await;

    rig.fail_to_reach_the_server().await;

    assert!(rig.sdk.check().unwrap().in_grace_period);
}

#[tokio::test]
async fn a_failed_renewal_does_not_flag_a_token_under_sixty_minutes_old() {
    let mut rig = Rig::new("valid_in_grace_period").await;
    rig.sdk.base_url = "http://127.0.0.1:1".into();
    rig.sdk.check().unwrap();
    rig.idle().await;
    assert!(rig.sdk.renewal().renewal_failed);

    let fresh = Vector::load("valid_fresh");
    storage::save(&rig.cache, &fresh.token, &fresh.chain).unwrap();
    rig.clock.store(
        fresh
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        Ordering::SeqCst,
    );
    assert!(!rig.sdk.check().unwrap().in_grace_period);
}

#[tokio::test]
async fn a_flagged_token_is_still_rejected_past_the_grace_deadline() {
    let mut rig = Rig::new("valid_in_grace_period").await;
    rig.fail_to_reach_the_server().await;
    rig.advance(8 * 24 * 60 * 60);
    assert!(matches!(rig.sdk.check(), Err(LatteError::NotActivated)));
}

#[tokio::test]
async fn every_outcome_but_a_network_failure_clears_the_flag() {
    // Each reply is one the server can give to a renewal that was reached.
    for status in [200, 404, 403, 401, 409, 429, 500, 503] {
        let mut rig = Rig::new("valid_in_grace_period").await;
        rig.fail_to_reach_the_server().await;
        assert!(rig.sdk.renewal().renewal_failed);

        let reply = match status {
            200 => rig.renewed.response(),
            _ => ResponseTemplate::new(status).set_body_json(json!({"error": "nope"})),
        };
        rig.reply(reply).await;
        rig.advance(300);
        rig.sdk.check().unwrap();
        rig.idle().await;

        assert!(!rig.sdk.renewal().renewal_failed, "status {status}");
    }
}

#[tokio::test]
async fn a_renewed_token_that_does_not_verify_and_an_undecodable_reply_clear_the_flag() {
    for body in [
        json!({
            "token": "not-a-jwt",
            "activation_id": ACTIVATION_ID,
            "chain": {"submaster": "s", "project": "p", "daily": "d"},
        }),
        json!({"unexpected": true}),
    ] {
        let mut rig = Rig::new("valid_in_grace_period").await;
        rig.fail_to_reach_the_server().await;
        rig.reply(ResponseTemplate::new(200).set_body_json(body))
            .await;
        rig.advance(300);
        rig.sdk.check().unwrap();
        rig.idle().await;
        assert!(!rig.sdk.renewal().renewal_failed);
        assert!(!rig.sdk.check().unwrap().in_grace_period);
    }
}

#[tokio::test]
async fn a_success_replaces_the_token_and_the_next_check_is_not_in_grace() {
    let mut rig = Rig::new("valid_in_grace_period").await;
    rig.fail_to_reach_the_server().await;
    assert!(rig.sdk.check().unwrap().in_grace_period);

    rig.advance(300);
    rig.reply(rig.renewed.response()).await;
    rig.sdk.check().unwrap();
    rig.idle().await;

    assert!(!rig.sdk.check().unwrap().in_grace_period);
}

#[tokio::test]
async fn a_manual_renew_sets_and_clears_the_flag_the_same_way() {
    let mut rig = Rig::new("valid_in_grace_period").await;
    rig.sdk.base_url = "http://127.0.0.1:1".into();
    let err = rig.sdk.renew(ACTIVATION_ID, LICENSE_KEY).await.unwrap_err();
    assert!(matches!(err, LatteError::Network(_)), "got {err:?}");
    assert!(rig.sdk.check().unwrap().in_grace_period);

    rig.sdk.base_url = rig.server.uri();
    rig.reply(ResponseTemplate::new(500)).await;
    rig.sdk.renew(ACTIVATION_ID, LICENSE_KEY).await.unwrap_err();
    assert!(!rig.sdk.check().unwrap().in_grace_period);
}

#[tokio::test]
async fn a_rejected_manual_renew_wipes_the_cache_and_clears_the_flag() {
    let mut rig = Rig::new("valid_in_grace_period").await;
    rig.sdk.base_url = "http://127.0.0.1:1".into();
    rig.sdk.renew(ACTIVATION_ID, LICENSE_KEY).await.unwrap_err();
    assert!(rig.sdk.renewal().renewal_failed);

    rig.sdk.base_url = rig.server.uri();
    rig.reply(ResponseTemplate::new(404).set_body_json(json!({"error": "gone"})))
        .await;
    rig.sdk.renew(ACTIVATION_ID, LICENSE_KEY).await.unwrap_err();

    assert!(!rig.sdk.renewal().renewal_failed);
    assert!(matches!(rig.sdk.check(), Err(LatteError::NotActivated)));
}

#[tokio::test]
async fn a_network_failure_is_ignored_once_the_cache_no_longer_holds_the_activation() {
    let mut rig = Rig::new("valid_in_grace_period").await;
    rig.sdk.http = quick_timeout();
    rig.reply(rig.renewed.response().set_delay(Duration::from_secs(2)))
        .await;
    rig.sdk.check().unwrap();
    storage::clear(&rig.cache).unwrap();
    rig.idle().await;
    assert!(!rig.sdk.renewal().renewal_failed);
}

#[tokio::test]
async fn deactivate_and_activate_reset_the_flag() {
    let mut rig = Rig::new("valid_in_grace_period").await;
    rig.fail_to_reach_the_server().await;
    assert!(rig.sdk.renewal().renewal_failed);
    Mock::given(method("POST"))
        .and(path("/v1/deactivate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"released": true})))
        .mount(&rig.server)
        .await;
    rig.sdk
        .deactivate(ACTIVATION_ID, LICENSE_KEY)
        .await
        .unwrap();
    assert!(!rig.sdk.renewal().renewal_failed);

    let mut rig = Rig::new("valid_in_grace_period").await;
    rig.fail_to_reach_the_server().await;
    assert!(rig.sdk.renewal().renewal_failed);
    Mock::given(method("POST"))
        .and(path("/v1/activate"))
        .respond_with(rig.renewed.response())
        .mount(&rig.server)
        .await;
    rig.sdk.activate("A-DIFFERENT-KEY").await.unwrap();
    assert!(!rig.sdk.renewal().renewal_failed);
}
