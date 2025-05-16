use thiserror::Error;
use crate::tcp::OsFingerprint;

/// Error returned when the username suffix isn’t a valid fingerprint.
#[derive(Debug, Error)]
pub enum ParseUsernameError {
    #[error("invalid fingerprint value: {0}")]
    InvalidFingerprint(String),
}

/// Parses `input` which may be either:
///   - `"username"`
///   - `"username-fingerprint-Windows"`
///   - `"username-fingerprint-Linux"`
///   - `"username-fingerprint-Android"`
/// (case-insensitive on the fingerprint tag)
///
/// Returns the bare username, plus `Some(fingerprint)` if found.
pub fn parse_username(
    input: &str,
    fingerprint: OsFingerprint,
) -> Result<(String, OsFingerprint), ParseUsernameError> {
    const SEP: &str = "-fingerprint-";
    if let Some(idx) = input.find(SEP) {
        let (name, rest) = input.split_at(idx);
        let val = &rest[SEP.len()..];
        // case-insensitive compare
        let fp = match val.to_ascii_lowercase().as_str() {
            "windows" => OsFingerprint::Windows,
            "linux"   => OsFingerprint::Linux,
            "android" => OsFingerprint::Android,
            other     => return Err(ParseUsernameError::InvalidFingerprint(other.to_string())),
        };
        Ok((name.to_string(), fp))
    } else {
        Ok((input.to_string(), fingerprint))
    }
}