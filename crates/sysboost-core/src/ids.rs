//! Strongly typed identifiers used across the domain and protocol boundaries.

use core::fmt;
use core::str::FromStr;

/// Error returned when a textual identifier is not safe or well formed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentifierError {
    name: &'static str,
    reason: &'static str,
}

impl IdentifierError {
    fn new(name: &'static str, reason: &'static str) -> Self {
        Self { name, reason }
    }
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {}: {}", self.name, self.reason)
    }
}

impl std::error::Error for IdentifierError {}

fn validate_text(name: &'static str, value: &str) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::new(name, "must not be empty"));
    }
    if value.len() > 128 {
        return Err(IdentifierError::new(name, "must be at most 128 bytes"));
    }
    if value
        .bytes()
        .any(|byte| byte == 0 || byte.is_ascii_whitespace())
    {
        return Err(IdentifierError::new(
            name,
            "must not contain whitespace or NUL",
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(IdentifierError::new(
            name,
            "may contain only ASCII letters, digits, '.', '_', ':', and '-'",
        ));
    }
    Ok(())
}

macro_rules! text_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Construct an identifier after validating its textual form.
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                let value = value.into();
                validate_text(stringify!($name), &value)?;
                Ok(Self(value))
            }

            /// Return the stable textual identifier.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = IdentifierError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

text_id!(
    /// Identifies a compiled-in backend.
    BackendId
);
text_id!(
    /// Identifies a semantic capability.
    CapabilityId
);
text_id!(
    /// Identifies one typed operation vocabulary entry.
    OperationId
);
text_id!(
    /// Identifies a planned transaction.
    TargetId
);

/// Identifies a planned transaction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlanId([u8; 16]);

impl PlanId {
    /// Construct an ID from deterministic bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Return the underlying bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Identifies a live session. The helper must generate this from an approved
/// entropy source; tests can use [`SessionId::from_bytes`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId([u8; 16]);

impl SessionId {
    /// Construct an ID from deterministic bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Return the underlying bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Render the ID as lowercase hexadecimal for logs and filenames.
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_hex(&self.0))
    }
}

impl FromStr for SessionId {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = decode_hex(value)
            .map_err(|_| IdentifierError::new("SessionId", "must be 32 hexadecimal characters"))?;
        let mut result = [0_u8; 16];
        result.copy_from_slice(&bytes);
        Ok(Self(result))
    }
}

/// Identifies a single mutation within a plan.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MutationId(u32);

impl MutationId {
    /// Construct a mutation ID. The planner owns uniqueness within a plan.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the numeric ID.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for MutationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2) {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let raw = value.as_bytes();
    for index in (0..raw.len()).step_by(2) {
        let high = hex_value(raw[index]).ok_or(())?;
        let low = hex_value(raw[index + 1]).ok_or(())?;
        bytes.push((high << 4) | low);
    }
    if bytes.len() != 16 {
        return Err(());
    }
    Ok(bytes)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_round_trips_as_hex() {
        let original = SessionId::from_bytes([0xabu8; 16]);
        let encoded = original.to_string();
        let decoded: SessionId = encoded.parse().expect("valid session ID");
        assert_eq!(decoded, original);
    }

    #[test]
    fn text_ids_reject_path_like_values() {
        assert!(TargetId::new("../sysfs").is_err());
        assert!(TargetId::new("cpu.policy.0").is_ok());
    }
}
