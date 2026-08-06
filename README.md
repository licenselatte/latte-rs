# latte-rs

Rust SDK for [LicenseLatte](https://licenselatte.com), the software
licensing platform. This is an idiomatic, memory-safe, no-`unsafe`,
no-FFI Rust implementation of license activation and verification, not a
binding on top of the C SDK.

> [!NOTE]
> The rust library has its own version line independent of other SDKs. Rust SDK is on v0.x while working on the most stable solution possible.

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
   key, extract the submaster's own public key from its `spk` claim.
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
private key is. This SDK ships only the master **public** key; key rotation
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
latte = { path = "../latte-rs" }  # or a registry version, once published
```

Two features are on by default and independently toggleable:

- `http`: network activation/renewal via `reqwest`.
- `cache`: the on-disk token cache (`Sdk::check`, and the fast path inside
  `activate`/`renew`).

If you only want the pure verify/validate functions and don't want either
dependency:

```toml
[dependencies]
latte = { path = "../latte-rs", default-features = false }
```

`default-features = false, features = ["http"]` gets you network activation
without the local cache, useful in a sandboxed/read-only-filesystem
environment where writing a cache file isn't possible.

## Quick start: activating a license

```rust
use latte::{Config, Sdk};

#[tokio::main]
async fn main() {
    // from the LicenseLatte dashboard; other fields default to a 30s
    // timeout, app_id's environment base URL, and a per-project cache path
    let sdk = Sdk::new(Config::with_app_id("pk_live_..."))
        .expect("invalid app_id");

    match sdk.activate("USER-PROVIDED-LICENSE-KEY", "opaque-machine-id").await {
        Ok(lic) => {
            println!("license OK, expires {:?}", lic.expires_at);
            if lic.in_grace_period {
                println!("warning: offline a while, please reconnect soon");
            }
            // Keep `lic.activation_id` around (in your own storage) so you
            // can call `sdk.renew(&lic.activation_id, ...)` later.
        }
        Err(e) => eprintln!("activation failed: {e}"),
    }
}
```

With the `cache` feature (on by default), a successful `activate`/`renew`
is written to disk, and a later `activate` call for the same key returns
the cached result without a network round trip as long as it's still
valid. There's no background renewal thread; call `renew` yourself on
whatever schedule fits your application.

## Checking a cached activation without a network call

```rust
use latte::error::LatteError;

fn on_startup(sdk: &latte::Sdk, machine_id: &str) {
    match sdk.check(machine_id) {
        Ok(lic) => println!("license OK, expires {:?}", lic.expires_at),
        Err(LatteError::LicenseExpired) => eprintln!("license expired, please renew"),
        Err(LatteError::NotActivated) => eprintln!("not activated, call activate()"),
        Err(e) => eprintln!("unexpected error: {e}"),
    }
}
```

## Re-verifying a token you're storing yourself

If you'd rather manage persistence yourself instead of using the `cache`
feature, `check_license_at` runs the same verify+validate pipeline
`Sdk::activate`/`Sdk::check` do, against a token/chain you already have:

```rust
use latte::{check_license_at, CheckError};
use latte::domain::CertChain;
use ed25519_dalek::VerifyingKey;
use std::time::SystemTime;

fn check(master_pub: &VerifyingKey, token: &str, chain: &CertChain, machine_id: &str) {
    match check_license_at(master_pub, token, chain, machine_id, SystemTime::now()) {
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

`check_license_at` takes an explicit `now: SystemTime` rather than reading
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

`PublicLicense::in_grace_period` is a softer, earlier warning signal: it
turns `true` once more than 60 minutes have passed since the last
issuance/renewal without a fresh one arriving, while still inside the grace
window; surface it as a "please reconnect soon" hint, distinct from an
outright rejection.

## License-key format utilities

`latte::key` and `latte::appid` implement the same license-key/AppID
normalization and checksum validation as every other LicenseLatte SDK
(uppercase, strip separators, fold `O/I/L` to `0/1/1`, verify a 2- or
4-character trailing checksum). This is a typo-catcher for end users pasting
keys, not a security boundary.

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

## What this crate does *not* do

OS-level machine-ID fingerprinting and background renewal scheduling are
intentionally out of scope. Pass your own machine-ID string into
`activate`/`renew`/`check`/`check_license_at`; only the opaque string
compared against the token's `mid` claim matters, not the algorithm that
produces it. For renewal, there's no scheduler here; `Sdk::renew` is the
building block; call it on a timer, in response to a UI action, or
whatever fits your application.

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
