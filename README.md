# latte-rs

Rust SDK for [LicenseLatte](https://licenselatte.com), the software
licensing platform. This is an idiomatic, memory-safe, no-`unsafe`,
no-FFI Rust implementation of license activation and verification, not a
binding on top of the C SDK.

Full docs: [licenselatte.com/docs/sdks/rust](https://licenselatte.com/docs/sdks/rust)

> [!NOTE]
> The Rust SDK versions independently from the other language bindings and follows semver. It's currently on v0.x, meaning the public API may still change without a major version bump. It moves to 1.0.0 once the API is validated across real integrations.

---

## What this crate verifies

LicenseLatte licenses are issued as a chain of Ed25519-signed JWTs:

```
Master (root, hardcoded in the SDK)
  -> Submaster cert
       -> Project cert
            -> Daily cert
                 -> Activation token (what you actually check against a machine)
```

Each link in the chain is a standard compact-serialization JWT
(`base64url(header).base64url(payload).base64url(signature)`, `alg: EdDSA`,
signed with Ed25519, see [RFC 8037]). Verifying a license means:

1. Verify the submaster cert's signature against the hardcoded master public
   keys (any one of them may have signed it), extract the submaster's own
   public key from its `spk` claim.
2. Verify the project cert's signature against the submaster's public key,
   extract `ppk`.
3. Verify the daily cert's signature against the project's public key,
   extract `dpk`.
4. Verify the activation token's signature against the daily key.
5. Cross-check the claims (project ID agreement, timing consistency between
   the activation token and the daily cert that signed it).
6. Apply grace-period math: is the token still within its hard expiry, and,
   if the device has been offline, still within its configured grace
   window (30-90 days, chosen when the license is issued)?

This is a standard certificate-chain-of-trust design (the same shape as an
X.509 chain, just JWTs instead of X.509 certs), documented publicly here per
Kerckhoffs's principle: the *mechanism* is not the secret, the master
private key is. This SDK ships only the master **public** keys
(`verify::MASTER_PUBLIC_KEYS_HEX`); key rotation
cadence, key storage, and the tooling that issues certs are intentionally
not documented in any SDK repo.

[RFC 8037]: https://www.rfc-editor.org/rfc/rfc8037

## Cryptography

- **Ed25519** signature verification via [`ed25519-dalek`](https://docs.rs/ed25519-dalek)
  (audited, widely used; no hand-rolled crypto anywhere in this crate).
- JWT compact-serialization parsing is hand-written (`src/jwt.rs`); this is
  structural (base64url + JSON), not cryptographic, so implementing it
  directly instead of pulling in a general-purpose JWT crate is a
  reasonable, minimal-dependency choice for four call sites with one fixed
  algorithm.
- No `unsafe` appears anywhere in this crate.

## Installation

```toml
[dependencies]
latte-rs = "0"
```

Two features are on by default and independently toggleable:

- `http`: network activation/renewal, deactivation and the machine list
  via `reqwest`.
- `cache`: the on-disk token cache (`Sdk::check`, and the fast path inside
  `activate`/`renew`).

If you only want the pure verify/validate functions and don't want either
dependency:

```toml
[dependencies]
latte-rs = { version = "0", default-features = false }
```

`default-features = false, features = ["http"]` gets you network activation
without the local cache, useful in a sandboxed/read-only-filesystem
environment where writing a cache file isn't possible.

## Quick start: activating a license

```rust
use latte_rs::{Config, Sdk};

#[tokio::main]
async fn main() {
    // from the LicenseLatte dashboard; other fields default to a 30s
    // timeout, app_id's environment base URL, and a per-project cache path
    let sdk = Sdk::new(Config::with_app_id("pk_live_..."))
        .expect("invalid app_id");

    match sdk.activate("USER-PROVIDED-LICENSE-KEY").await {
        Ok(lic) => {
            println!("license OK, expires {:?}", lic.expires_at);
            if lic.in_grace_period {
                println!("warning: offline a while, please reconnect soon");
            }
            // Keep `lic.activation_id` around (in your own storage) so you
            // can call `sdk.renew(&lic.activation_id, &key)` later.
        }
        Err(e) => eprintln!("activation failed: {e}"),
    }
}
```

With the `cache` feature (on by default), a successful `activate`/`renew`
is written to disk, and a later `activate` call for the same key returns
the cached result without a network round trip as long as it's still
valid. `check` also keeps the cached token fresh in the background (see
below); you can still call `renew` yourself on whatever schedule fits your
application.

## Machine ID

`Sdk::new` works out this install's machine ID once, and `activate`,
`renew` and `check` all use it. The raw ID never leaves the machine: what
is sent, and compared with the token's `mid` claim, is lowercase hex
`HMAC-SHA256(key = raw ID, message = "licenselatte_" + app_id)`, the same
value latte-go sends. The raw ID is the platform's machine ID
(`/var/lib/dbus/machine-id` or `/etc/machine-id` on Linux, `IOPlatformUUID`
on macOS, `MachineGuid` on Windows, `/etc/hostid` or the SMBIOS UUID on the
BSDs) unless you supply your own:

```rust
use latte_rs::{Config, Sdk};

let sdk = Sdk::new(Config::with_app_id("pk_live_...").with_machine_id(user_id))?;
```

A supplied ID is used byte for byte, without trimming. Supply one when the
platform ID does not identify what you want to count as one seat:

- containers that share their image's `/etc/machine-id`, or have none;
- cloned VMs that all carry the same ID;
- a seat per user rather than per machine;
- tests.

Changing it on an install that is already activated makes that install a
new machine, which takes a new seat. When no ID was supplied and the
platform's cannot be read, `Sdk::new` returns
`LatteError::MachineIdUnavailable`.

`Sdk::machine_id()` returns the derived value, which is what the low-level
functions below take. Without the `http` feature, compute it with
`latte_rs::machine_id::derive(app_id, raw)`.

## Machine name

`activate` can send a name for this machine, which the customer sees in
`Sdk::machines` and the customer portal and you see in the dashboard. The
standard library has no hostname call and this crate takes no dependency
for one, so no name is sent unless you set it:

```rust
let sdk = Sdk::new(Config::with_app_id("pk_live_...").with_machine_name(hostname))?;
```

An empty name sends none. The name is stored only when the activation is
created, and a name the customer sets later with `rename_machine` is kept
on re-activation.

## Releasing this machine (deactivate)

```rust
use latte_rs::error::LatteError;

match sdk.deactivate(&activation_id, &key).await {
    Ok(res) => match res.seat_free_at {
        Some(at) => println!("released; the seat frees at {at:?}"),
        None => println!("released; activate the licence on your other machine"),
    },
    Err(LatteError::DeactivationBlocked { message, .. }) => println!("{message}"),
    Err(e) => println!("could not release, nothing was changed; try again: {e}"),
}
```

`deactivate(activation_id, license_key)` takes the same arguments as
`renew` and releases this machine's seat so the licence can move to
another one: the "Deactivate" button in your application. It needs the
network. The server releases the seat first, and only once it has
answered with success does the SDK delete the cached token, after which
`check` returns `LatteError::NotActivated` until the next `activate`. If
the call fails, nothing changes locally and the user can try again; the
seat is never lost to a dropped connection. Repeating a release that
already went through is success, with `released` false.

A machine that is lost, dead or wiped cannot call this; its seat is
released from the seller's customer portal instead.

Releases are limited on every plan: a fixed number per licence per year, or on plans with the deactivation policy engine the seller's cooldown and yearly cap. A refusal is
`LatteError::DeactivationBlocked { message, reason, available_at }`:
`message` is written to be shown to the user, `reason` is
`"deactivation_cooldown"` or `"deactivation_limit_reached"`, and
`available_at` says when to try again. The seller may also hold the freed
seat until this machine's last token has expired, which
`DeactivateResult::seat_free_at` reports.

## Listing and naming machines

```rust
pub async fn machines(&self, activation_id: &str, license_key: &str) -> Result<Vec<Machine>, LatteError>
pub async fn rename_machine(&self, activation_id: &str, license_key: &str, name: &str) -> Result<String, LatteError>
```

`machines` lists the machines holding a seat on the licence: `name`
(optional), a 12-character `fingerprint`, `activated_at`, `last_seen_at`,
`current` for this machine, and `seat_free_at` for a released machine
whose seat is still held. It is for showing the customer where their
licence is in use; it cannot release another machine, which is the
customer portal's job.

`rename_machine` names this machine and returns the name as stored,
trimmed. The server refuses a name that is empty, longer than 64
characters or holds control characters (`LatteError::Server`). Both calls
need the network and an active activation on this machine
(`LatteError::LicenseExpired` otherwise, from the server's 403).

## Checking a cached activation without a network call

```rust
use latte_rs::error::LatteError;

fn on_startup(sdk: &latte_rs::Sdk) {
    match sdk.check() {
        Ok(lic) => println!("license OK, expires {:?}", lic.expires_at),
        Err(LatteError::LicenseExpired) => eprintln!("license expired, please renew"),
        Err(LatteError::NotActivated) => eprintln!("not activated, call activate()"),
        Err(e) => eprintln!("unexpected error: {e}"),
    }
}
```

## Re-verifying a token you're storing yourself

If you'd rather manage persistence yourself instead of using the `cache`
feature, `check_license_any_at` runs the same verify+validate pipeline
`Sdk::activate`/`Sdk::check` do, against a token/chain you already have.
Pass it `verify::master_public_keys()` to trust the same roots `Sdk` does,
and `Sdk::machine_id()` (or `machine_id::derive`) as the machine ID:

```rust
use latte_rs::{check_license_any_at, CheckError};
use latte_rs::domain::CertChain;
use latte_rs::verify::master_public_keys;
use std::time::SystemTime;

fn check(token: &str, chain: &CertChain, machine_id: &str) {
    let masters = master_public_keys();
    match check_license_any_at(&masters, token, chain, machine_id, SystemTime::now()) {
        Ok(lic) => {
            println!("license OK, expires {:?}", lic.expires_at);
            if lic.in_grace_period {
                println!("warning: offline a while, please reconnect soon");
            }
        }
        Err(CheckError::Verify(e)) => {
            // Chain/signature/format problem, treat as "not activated".
            eprintln!("could not verify license: {e}");
        }
        Err(CheckError::Validate(e)) => {
            // Chain verified fine; grace-period/expiry/machine-id rejected it.
            eprintln!("license rejected: {e}");
        }
    }
}
```

`check_license_any_at` takes an explicit `now: SystemTime` rather than reading
the system clock internally. That's what makes this crate's test suite
fully reproducible against a fixed set of test vectors, and it also lets
you (if you ever need to) reject certificates whose validity window
doesn't cover a securely-obtained external time source, not just the local
clock.

## Offline grace period

The grace period is an offline tolerance window measured **from the license's
last issuance/renewal** (`issued_at`), not from `expires_at`:

```
issued_at ──────────────────────────────────> expires_at
              |                   |
              └── grace_period ───┘
                  ^ offline window
```

While `now <= issued_at + grace_period`, the license is still usable without
a network call. Once that deadline passes, `check_license_at` returns
`ValidateError::GraceExpired`; once `now > expires_at`, it returns
`ValidateError::HardExpired` (checked first, hard expiry always wins).
A licence that never ends has `expires_at` 2099-01-01T00:00:00Z.

The SDK reads two activation-token formats, told apart by whether the
token carries a `grc` claim:

| Format | `expires_at` | `grace_period` |
|---|---|---|
| with `grc` | `exp` | `grc` |
| without `grc` | `lex`, or 2099-01-01T00:00:00Z when absent | `exp - iat` |

In the second format `exp` is the offline deadline itself, already capped
at the licence's end by the server. Either way `exp` is enforced by the
validate step above, with those two reasons, and never by the JWT parse.

`PublicLicense::in_grace_period` is a softer, earlier warning signal: it
turns `true` once more than 60 minutes have passed since the last
issuance/renewal without a fresh one arriving, while still inside the grace
window; surface it as a "please reconnect soon" hint, distinct from an
outright rejection.

## License-key format utilities

`latte_rs::key` and `latte_rs::appid` implement the same license-key/AppID
normalization and checksum validation as every other LicenseLatte SDK
(uppercase, strip separators, fold `O/I/L` to `0/1/1`, verify a 2- or
4-character trailing checksum). This is a typo-catcher for end users pasting
keys, not a security boundary.

## Background renewal

`check` answers from the cached token alone and returns immediately. When
that token is at least 60 minutes old, `check` also starts a renewal on a
detached background thread, so the cached token stays fresh while the app
is online. It starts one only if none is running and the last attempt,
background or a manual `renew`, began at least five minutes ago, so a host
that calls `check` often still sends at most one request per five minutes.
Nothing in `check` waits for it, and the thread never keeps your process
from exiting.

- A renewal that succeeds replaces the cached token.
- A renewal the server rejects as not found, expired or for the wrong
  project key clears the cache, so the next `check` returns
  `LatteError::NotActivated`. Deactivating a licence in the dashboard
  therefore takes effect at the next renewal attempt, not instantly.
- Every other failure (no network, a timeout, a 5xx or 429, a response that
  does not verify) is dropped. The cached token stays valid until its
  grace period ends, and a later `check` tries again.

The renewal also starts for a cached token whose grace window has already
ended, as long as its signature chain verifies and it was issued to this
machine. A computer that was off longer than the grace window therefore
recovers by itself: the first `check` after launch returns
`LatteError::NotActivated` (or `LatteError::LicenseExpired`), the SDK
renews in the background, and a `check` a few seconds later, while online,
returns the licence. Hosts should re-check rather than send the user to
activate again. A token that fails verification or belongs to another
machine starts no request.

The thread builds its own small `tokio` runtime, so `check` stays a
plain synchronous call that works with or without an async runtime of
your own. The crate depends on `tokio`'s `rt`, `net` and `time` features
for this; `reqwest` already pulls the same crate in.

## The cache file

With the `cache` feature, `Sdk` stores an activated license as a small JSON
file under your OS's per-user config directory
(`{config_dir}/licenselatte/{project_key}.json`):

```json
{
  "timestamp": 1700000000,
  "token": "<activation JWT>",
  "submaster": "<submaster cert JWT>",
  "project": "<project cert JWT>",
  "daily": "<daily cert JWT>"
}
```

Writes go to a temp file in the same directory and get renamed into place,
so a crash or a concurrent write can't leave a half-written file behind.
`Config::cache_path` overrides the location if you want it somewhere else.

## Entitlements

Entitlements are the typed answers a seller signed into a licence about what
their customer bought. Two questions, and only two: *may this customer do X*
(a boolean) and *how many Y do they get* (an integer).

```rust
let lic = sdk.activate(&key)?;

if lic.can("export_pdf") {
    enable_pdf_export();
}

if let Some(max) = lic.limit("max_projects") {
    if max != latte_rs::UNLIMITED && used >= max {
        return Err(Error::ProjectLimitReached);
    }
}
```

You set the values on a policy and override them per licence in the
dashboard; the server resolves the two and signs the result into the
activation token, so `can` and `limit` answer offline with no network call.

`UNLIMITED` is `-1`. `limit` returns it as-is — compare against the exported
constant rather than testing for a negative number.

### The rules

| | |
|---|---|
| **Absence denies.** | An unset key is ``can() == false``, ``limit() == None``. |
| **No coercion.** | `can` on an integer is false even when it is non-zero. `limit` on a boolean misses rather than returning 1 or 0. |
| **Keys are byte-exact.** | No case folding, no trimming. |
| **A bad value is dropped, never fatal.** | If a value reaches the token that is neither a boolean nor an integer, that one entry vanishes and the licence stays valid. |

### Rolling this out without switching your own features off

Absence denies, and that has a consequence worth reading twice: **a token
issued before you set any entitlements answers `false` to everything.** Ship
`if !lic.can("export_pdf") { hide(); }` and every customer still holding a
cached token from before the change loses PDF export until they renew.

`has_entitlements()` exists for exactly this, and it is not a convenience
accessor:

```rust
let enabled = if lic.has_entitlements() {
    lic.can("export_pdf")
} else {
    legacy_behaviour() // this token predates entitlements
};
```

The published order is: set the values in the dashboard first, wait one
grace window for the installed base to renew, then ship the release that
reads them behind `has_entitlements()`, and drop the fallback once the base
has turned over.

`has_entitlements()` reports whether the claim was **present**, including
when it is empty — which is why it is not a length check on
`lic.entitlements`.

### Entitlements are not metadata

Entitlements and `metadata` are separate namespaces and never merge.
Metadata is arbitrary display data, filtered per field in the dashboard, and
untyped; entitlements are booleans and integers, unfiltered, and exist
precisely to be read on the customer's machine. The same key may appear in
both meaning different things.

Entitlements are a distribution mechanism for a signed answer, not a
tamper-proofing one — see the threat-model section above. Entitlements
change nothing about it. If real revenue depends on a feature, re-validate
it server-side.

---

## What this crate does *not* do

There's no scheduler beyond the background renewal `check` starts.
`Sdk::renew` is the building block for anything more: call it on a timer,
in response to a UI action, or whatever fits your application.

## Testing

```sh
cargo test
```

Runs unit tests for the checksum algorithm, chain verification (valid
chains, tampered signatures, broken intermediate links, cross-check
failures, clock-skew edge cases), and grace-period math (including exact
boundary conditions), plus the full shared cross-language fixture suite in
`testdata/`.

## License

MIT, see [LICENSE](LICENSE).
