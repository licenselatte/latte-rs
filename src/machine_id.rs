//! The machine ID this SDK sends as `machine_id` and compares with a
//! token's `mid` claim.
//!
//! The value is never the raw machine ID. It is lowercase hex
//! `HMAC-SHA256(key = raw ID, message = "licenselatte_" + app_id)`, so the
//! raw ID never leaves the machine and two products on the same machine
//! send unrelated values. The raw ID is the one the caller supplies, used
//! byte for byte without trimming, or else the platform's machine ID, read
//! the way `denisbrodbeck/machineid` reads it (which is what latte-go
//! uses):
//!
//! - Linux: `/var/lib/dbus/machine-id`, then `/etc/machine-id`.
//! - macOS: `IOPlatformUUID` from `ioreg -rd1 -c IOPlatformExpertDevice`.
//! - Windows: `MachineGuid` under `HKLM\SOFTWARE\Microsoft\Cryptography`
//!   (64-bit registry view).
//! - FreeBSD, NetBSD, OpenBSD, DragonFly, Solaris, illumos: `/etc/hostid`,
//!   then `kenv -q smbios.system.uuid`.
//!
//! A platform value that reads as empty counts as unavailable, so machines
//! with a blank `/etc/machine-id` do not all share one ID.

use sha2::{Digest, Sha256};

/// The machine ID to send and to check tokens against, for `app_id` (the
/// full `pk_{env}_...` project key).
///
/// `raw` is your own machine identity; `None` or an empty string reads the
/// platform's machine ID instead. Returns `None` only when `raw` is absent
/// and the platform ID cannot be read, in which case supply one.
///
/// [`crate::http::Sdk`] calls this once in `Sdk::new` and exposes the result
/// as `Sdk::machine_id`; call it yourself only when you drive
/// [`crate::check_license_at`] or [`crate::validate::validate_at`] without
/// `Sdk`.
pub fn derive(app_id: &str, raw: Option<&str>) -> Option<String> {
    let raw = match raw {
        Some(r) if !r.is_empty() => r.to_string(),
        _ => platform_id()?,
    };
    Some(protect(&raw, app_id))
}

fn protect(raw: &str, app_id: &str) -> String {
    let msg = format!("licenselatte_{app_id}");
    hex::encode(hmac_sha256(raw.as_bytes(), msg.as_bytes()))
}

/// RFC 2104 HMAC over SHA-256.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let inner = Sha256::new()
        .chain_update(&ipad)
        .chain_update(msg)
        .finalize();
    Sha256::new()
        .chain_update(&opad)
        .chain_update(inner)
        .finalize()
        .into()
}

fn non_empty(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos"
))]
fn read_file(path: &str) -> Option<String> {
    non_empty(&std::fs::read_to_string(path).ok()?)
}

#[cfg(any(
    target_os = "macos",
    target_os = "windows",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos"
))]
fn run(cmd: &mut std::process::Command) -> Option<String> {
    let out = cmd.stdin(std::process::Stdio::null()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

#[cfg(target_os = "linux")]
fn platform_id() -> Option<String> {
    read_file("/var/lib/dbus/machine-id").or_else(|| read_file("/etc/machine-id"))
}

#[cfg(target_os = "macos")]
fn platform_id() -> Option<String> {
    let out = run(std::process::Command::new("/usr/sbin/ioreg").args([
        "-rd1",
        "-c",
        "IOPlatformExpertDevice",
    ]))?;
    parse_ioreg(&out)
}

#[cfg(target_os = "windows")]
fn platform_id() -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let reg = std::env::var_os("SystemRoot")
        .map(|root| std::path::Path::new(&root).join("System32").join("reg.exe"))
        .unwrap_or_else(|| r"C:\Windows\System32\reg.exe".into());
    let out = run(std::process::Command::new(reg)
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
            "/reg:64",
        ])
        .creation_flags(CREATE_NO_WINDOW))?;
    parse_reg_query(&out)
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos"
))]
fn platform_id() -> Option<String> {
    read_file("/etc/hostid").or_else(|| {
        non_empty(&run(
            std::process::Command::new("/bin/kenv").args(["-q", "smbios.system.uuid"])
        )?)
    })
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos"
)))]
fn platform_id() -> Option<String> {
    None
}

/// The `IOPlatformUUID` value from `ioreg` output, a line of the form
/// `"IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"`.
#[cfg(any(target_os = "macos", test))]
fn parse_ioreg(out: &str) -> Option<String> {
    out.lines()
        .filter(|line| line.contains("IOPlatformUUID"))
        .find_map(|line| {
            let (_, value) = line.split_once("\" = \"")?;
            non_empty(value.trim_end_matches('"'))
        })
}

/// The `MachineGuid` value from `reg query` output, a line of the form
/// `    MachineGuid    REG_SZ    xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
#[cfg(any(target_os = "windows", test))]
fn parse_reg_query(out: &str) -> Option<String> {
    out.lines().find_map(|line| {
        let rest = line.trim_start().strip_prefix("MachineGuid")?;
        let value = rest.trim_start().strip_prefix("REG_SZ")?;
        non_empty(value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vectors {
        cases: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Case {
        raw_machine_id: String,
        app_id: String,
        expect_machine_id: String,
    }

    #[test]
    fn matches_every_shared_vector() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/machine_id.json");
        let data = std::fs::read_to_string(path).expect("testdata submodule checked out");
        let vectors: Vectors = serde_json::from_str(&data).unwrap();
        assert!(!vectors.cases.is_empty());
        for c in vectors.cases {
            assert_eq!(
                protect(&c.raw_machine_id, &c.app_id),
                c.expect_machine_id,
                "raw {:?}",
                c.raw_machine_id
            );
            assert_eq!(
                derive(&c.app_id, Some(&c.raw_machine_id)).as_deref(),
                Some(c.expect_machine_id.as_str())
            );
        }
    }

    #[test]
    fn hashes_keys_longer_than_a_block() {
        // RFC 4231 test case 6.
        let mac = hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            hex::encode(mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn empty_supplied_id_reads_the_platform() {
        assert_eq!(derive("pk_test_x", Some("")), derive("pk_test_x", None));
    }

    #[test]
    fn parses_ioreg_output() {
        let out = r#"+-o J316sAP  <class IOPlatformExpertDevice, id 0x100000215, registered, matched, active, busy 0 (0 ms), retain 39>
    {
      "IOPlatformSerialNumber" = "C02XXXXXXXXX"
      "IOPlatformUUID" = "4C4C4544-0042-3510-8051-B4C04F4B4E32"
      "IOPolledInterface" = "AppleARMWatchdogTimerHibernateHandler is not serializable"
    }
"#;
        assert_eq!(
            parse_ioreg(out).as_deref(),
            Some("4C4C4544-0042-3510-8051-B4C04F4B4E32")
        );
        assert_eq!(parse_ioreg("\"IOPlatformSerialNumber\" = \"X\"\n"), None);
        assert_eq!(parse_ioreg("\"IOPlatformUUID\" = \"\"\n"), None);
    }

    #[test]
    fn parses_reg_query_output() {
        let out = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n    MachineGuid    REG_SZ    b08f1a2c-3d4e-5f60-7182-93a4b5c6d7e8\r\n\r\n";
        assert_eq!(
            parse_reg_query(out).as_deref(),
            Some("b08f1a2c-3d4e-5f60-7182-93a4b5c6d7e8")
        );
        assert_eq!(
            parse_reg_query(
                "ERROR: The system was unable to find the specified registry key or value.\r\n"
            ),
            None
        );
    }
}
