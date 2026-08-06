//! `AppId` (`pk_{env}_{32-char key}`) parsing and validation.

use crate::error::AppIdError;
use crate::key::validate_key;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Live,
    Test,
    Local,
}

impl Environment {
    /// The API base URL this environment talks to.
    pub fn base_url(&self) -> &'static str {
        match self {
            Environment::Live => "https://api.licenselatte.com",
            Environment::Test => "https://test.api.licenselatte.com",
            Environment::Local => "http://localhost:8080",
        }
    }
}

#[derive(Debug)]
pub struct AppId {
    pub env: Environment,
    /// The 32-character key segment, including its trailing 4-char checksum.
    pub key: String,
}

/// Parses and checksum-validates an AppID of the form `pk_{env}_{32-char key}`.
pub fn parse_app_id(app_id: &str) -> Result<AppId, AppIdError> {
    let parts: Vec<&str> = app_id.split('_').collect();
    if parts.len() != 3 || parts[0] != "pk" {
        return Err(AppIdError::InvalidFormat);
    }

    let env = match parts[1] {
        "live" => Environment::Live,
        "test" => Environment::Test,
        "local" => Environment::Local,
        other => return Err(AppIdError::UnknownEnvironment(other.to_string())),
    };

    let key = parts[2];
    if key.len() != 32 {
        return Err(AppIdError::InvalidKeySegment);
    }
    if !validate_key(key, 4) {
        return Err(AppIdError::InvalidChecksum);
    }

    Ok(AppId {
        env,
        key: key.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::calculate_checksum;

    #[test]
    fn accepts_well_formed_live_app_id() {
        let data = "AHAK85389VQYXYB6S4BW66SKE53T"; // 28 chars
        let checksum = calculate_checksum(data, 4);
        let parsed = parse_app_id(&format!("pk_live_{data}{checksum}")).unwrap();
        assert_eq!(parsed.env, Environment::Live);
        assert_eq!(parsed.env.base_url(), "https://api.licenselatte.com");
    }

    #[test]
    fn supports_undocumented_local_environment() {
        let data = "AHAK85389VQYXYB6S4BW66SKE53T";
        let checksum = calculate_checksum(data, 4);
        let parsed = parse_app_id(&format!("pk_local_{data}{checksum}")).unwrap();
        assert_eq!(parsed.env.base_url(), "http://localhost:8080");
    }

    #[test]
    fn rejects_bad_checksum() {
        let data = "AHAK85389VQYXYB6S4BW66SKE53T";
        let err = parse_app_id(&format!("pk_live_{data}XXXX")).unwrap_err();
        assert_eq!(err, AppIdError::InvalidChecksum);
    }

    #[test]
    fn rejects_unknown_environment() {
        let data = "AHAK85389VQYXYB6S4BW66SKE53T";
        let checksum = calculate_checksum(data, 4);
        let err = parse_app_id(&format!("pk_staging_{data}{checksum}")).unwrap_err();
        assert!(matches!(err, AppIdError::UnknownEnvironment(_)));
    }
}
