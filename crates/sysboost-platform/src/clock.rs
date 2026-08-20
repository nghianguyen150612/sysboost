//! Injectable time sources for deterministic sessions and tests.

use std::time::{SystemTime, UNIX_EPOCH};

use sysboost_core::{ErrorCode, SysboostError, Timestamp};

/// Clock port used by detection, journaling, and logging.
pub trait Clock {
    /// Return the current timestamp.
    fn now(&self) -> Result<Timestamp, SysboostError>;
}

/// Production wall-clock adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<Timestamp, SysboostError> {
        let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
            SysboostError::new(
                ErrorCode::InvariantViolation,
                "system clock precedes Unix epoch",
            )
        })?;
        Ok(Timestamp::from_unix_millis(duration.as_millis()))
    }
}

/// Fixed clock for deterministic tests.
#[derive(Clone, Copy, Debug)]
pub struct FixedClock {
    timestamp: Timestamp,
}

impl FixedClock {
    /// Construct a fixed clock.
    pub const fn new(timestamp: Timestamp) -> Self {
        Self { timestamp }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Result<Timestamp, SysboostError> {
        Ok(self.timestamp)
    }
}
