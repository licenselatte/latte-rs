//! On-disk caching for an activated license, so an application doesn't
//! have to hit the network on every startup.
//!
//! The file is a small flat JSON record:
//!
//! ```json
//! {
//!   "timestamp": 1700000000,
//!   "token": "<activation JWT>",
//!   "submaster": "<submaster cert JWT>",
//!   "project": "<project cert JWT>",
//!   "daily": "<daily cert JWT>"
//! }
//! ```
//!
//! `timestamp` (unix seconds, set at save time) is metadata for a human
//! reading the file, not used by anything in this crate; the token's own
//! `iat`/`exp` claims are what govern expiry and grace-period math.
//!
//! Every function here treats "can't read/parse the cache" and "no cache
//! exists" identically: both just mean the caller falls back to activating
//! over the network. A corrupted or unreadable file is never a hard error.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::domain::CertChain;

#[derive(Serialize, Deserialize)]
struct CachedActivation {
    timestamp: i64,
    token: String,
    submaster: String,
    project: String,
    daily: String,
}

/// The default cache file location for a given project key: a
/// `licenselatte` folder under the OS's per-user config directory (chosen
/// over a cache directory because it isn't subject to being cleared by
/// disk-cleanup tools; losing this file just means one extra activation
/// call, but there's no reason to invite that), named after the 32-char
/// project key segment so multiple projects on the same machine don't
/// collide. Returns `None` if the OS config directory can't be determined
/// (some minimal/sandboxed environments); callers should treat that as
/// "caching unavailable" rather than an error.
pub fn default_path(project_key: &str) -> Option<PathBuf> {
    let mut path = dirs::config_dir()?;
    path.push("licenselatte");
    path.push(format!("{project_key}.json"));
    Some(path)
}

/// Reads and parses the cache file at `path`. Returns `None` on any
/// problem at all (missing file, permission error, corrupt/foreign JSON)
/// since every caller's response to a cache miss and a cache error is the
/// same: proceed as if nothing was cached.
pub fn load(path: &Path) -> Option<(String, CertChain)> {
    let data = fs::read(path).ok()?;
    let record: CachedActivation = serde_json::from_slice(&data).ok()?;
    Some((
        record.token,
        CertChain {
            submaster: record.submaster,
            project: record.project,
            daily: record.daily,
        },
    ))
}

/// Writes `token`/`chain` to the cache file at `path`, creating parent
/// directories as needed. Writes to a temporary file in the same directory
/// first and renames it into place, so a process interrupted mid-write (or
/// a crash) can never leave a half-written, corrupt cache file behind;
/// readers only ever see the previous complete version or the new one.
pub fn save(path: &Path, token: &str, chain: &CertChain) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }

    let record = CachedActivation {
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        token: token.to_string(),
        submaster: chain.submaster.clone(),
        project: chain.project.clone(),
        daily: chain.daily.clone(),
    };
    let data =
        serde_json::to_vec(&record).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let tmp_path = path.with_extension("json.tmp");
    fs::write(&tmp_path, data)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Deletes the cache file at `path`, if it exists. Used to drop a token the
/// server has told us is no longer valid, so a future `activate`/`check`
/// doesn't keep finding it. Missing-file is not an error.
pub fn clear(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_chain() -> CertChain {
        CertChain {
            submaster: "s".to_string(),
            project: "p".to_string(),
            daily: "d".to_string(),
        }
    }

    #[test]
    fn round_trips_through_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.json");

        save(&path, "the-token", &test_chain()).unwrap();
        let (token, chain) = load(&path).unwrap();

        assert_eq!(token, "the-token");
        assert_eq!(chain.submaster, "s");
        assert_eq!(chain.project, "p");
        assert_eq!(chain.daily, "d");
    }

    #[test]
    fn writes_snake_case_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.json");
        save(&path, "the-token", &test_chain()).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let obj = value.as_object().unwrap();
        assert!(obj.contains_key("timestamp"));
        assert!(obj.contains_key("token"));
        assert!(obj.contains_key("submaster"));
        assert!(obj.contains_key("project"));
        assert!(obj.contains_key("daily"));
        // No PascalCase keys.
        assert!(!obj.contains_key("Token"));
        assert!(!obj.contains_key("Timestamp"));
    }

    #[test]
    fn load_returns_none_for_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        assert!(load(&path).is_none());
    }

    #[test]
    fn load_returns_none_for_corrupt_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.json");
        fs::write(&path, b"not json").unwrap();
        assert!(load(&path).is_none());
    }

    #[test]
    fn save_creates_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("dir").join("token.json");
        save(&path, "the-token", &test_chain()).unwrap();
        assert!(load(&path).is_some());
    }

    #[test]
    fn save_overwrites_an_existing_file_without_leaving_a_temp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.json");

        save(&path, "first", &test_chain()).unwrap();
        save(&path, "second", &test_chain()).unwrap();

        let (token, _) = load(&path).unwrap();
        assert_eq!(token, "second");
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn clear_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.json");
        save(&path, "the-token", &test_chain()).unwrap();

        clear(&path).unwrap();
        assert!(load(&path).is_none());
    }

    #[test]
    fn clear_on_a_missing_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        assert!(clear(&path).is_ok());
    }
}
