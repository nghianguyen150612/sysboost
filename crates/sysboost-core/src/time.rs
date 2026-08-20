//! Time values shared by deterministic domain code and platform clocks.

use core::fmt;

/// A non-negative Unix timestamp in milliseconds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Timestamp(u128);

impl Timestamp {
    /// Construct a timestamp from Unix milliseconds.
    pub const fn from_unix_millis(value: u128) -> Self {
        Self(value)
    }

    /// Return Unix milliseconds.
    pub const fn as_unix_millis(self) -> u128 {
        self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
