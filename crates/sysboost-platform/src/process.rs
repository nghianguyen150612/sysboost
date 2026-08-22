//! Process identity ports used for session ownership and deterministic tests.
//!
//! A PID is only a locator.  Linux can reuse it after a process exits, so the
//! production identity also carries the kernel process start time and the
//! boot identity.  The tuple is persisted in lock metadata and compared again
//! before stale-lock recovery.

use std::fs;
use std::io;

use sysboost_core::{ErrorCode, SysboostError};

/// Stable process identity for a helper/controller lease.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProcessIdentity {
    /// Operating-system process ID.
    pub pid: u32,
    /// Kernel process start-time token (Linux `/proc/<pid>/stat` field 22).
    pub generation: u64,
    /// Boot identity from `/proc/sys/kernel/random/boot_id`.
    pub boot_id: [u8; 16],
}

impl ProcessIdentity {
    /// Construct a process identity from platform evidence.
    ///
    /// This constructor is retained for deterministic fixtures.  Production
    /// code should use [`CurrentProcess`] so the boot identity is populated.
    pub fn new(pid: u32, generation: u64) -> Result<Self, SysboostError> {
        if pid == 0 {
            Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "process ID must be non-zero",
            ))
        } else {
            Ok(Self {
                pid,
                generation,
                boot_id: [0; 16],
            })
        }
    }

    /// Construct a process identity with an explicit boot identity.
    pub fn with_boot_id(
        pid: u32,
        generation: u64,
        boot_id: [u8; 16],
    ) -> Result<Self, SysboostError> {
        if pid == 0 {
            Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "process ID must be non-zero",
            ))
        } else if generation == 0 || boot_id == [0; 16] {
            Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "process identity requires a non-zero start and boot identity",
            ))
        } else {
            Ok(Self {
                pid,
                generation,
                boot_id,
            })
        }
    }

    /// Construct a fixture identity without requiring Linux process evidence.
    pub const fn fixture(pid: u32, generation: u64, boot_id: [u8; 16]) -> Self {
        Self {
            pid,
            generation,
            boot_id,
        }
    }

    /// Whether two identities refer to the same process generation.
    pub fn same_generation(self, other: Self) -> bool {
        self.pid == other.pid
            && self.generation != 0
            && self.generation == other.generation
            && self.boot_id != [0; 16]
            && self.boot_id == other.boot_id
    }
}

/// Process identity provider used by session ownership checks.
pub trait ProcessIdentityProvider {
    /// Return the current process identity.
    fn current(&self) -> Result<ProcessIdentity, SysboostError>;
}

/// Portable current-process adapter. Linux may later add a start-time token.
#[derive(Clone, Copy, Debug, Default)]
pub struct CurrentProcess;

impl ProcessIdentityProvider for CurrentProcess {
    fn current(&self) -> Result<ProcessIdentity, SysboostError> {
        current_process_identity()
    }
}

/// Probe a Linux process identity without treating PID existence as proof of
/// ownership. `Ok(None)` means the process no longer exists; other errors are
/// inconclusive and must fail closed during stale-lock recovery.
pub fn probe_process(pid: u32) -> Result<Option<ProcessIdentity>, SysboostError> {
    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/{pid}/stat");
        let stat = match fs::read_to_string(&path) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => {
                return Err(SysboostError::new(
                    ErrorCode::DurabilityError,
                    "process identity could not be inspected",
                ))
            }
        };
        let generation = parse_start_time(&stat).ok_or_else(|| {
            SysboostError::new(
                ErrorCode::JournalCorrupt,
                "process identity metadata is malformed",
            )
        })?;
        let boot_id = read_boot_id()?;
        Ok(Some(ProcessIdentity::with_boot_id(
            pid, generation, boot_id,
        )?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        Ok(None)
    }
}

fn current_process_identity() -> Result<ProcessIdentity, SysboostError> {
    let pid = std::process::id();
    #[cfg(target_os = "linux")]
    {
        let Some(identity) = probe_process(pid)? else {
            return Err(SysboostError::new(
                ErrorCode::DurabilityError,
                "current process identity disappeared",
            ));
        };
        Ok(identity)
    }
    #[cfg(not(target_os = "linux"))]
    {
        ProcessIdentity::with_boot_id(pid, 1, [1; 16])
    }
}

#[cfg(target_os = "linux")]
fn parse_start_time(stat: &str) -> Option<u64> {
    // The comm field may contain spaces and parentheses.  The final ')' is
    // therefore the only safe delimiter before the whitespace-separated
    // fields beginning at field 3.
    let close = stat.rfind(')')?;
    stat.get(close + 1..)?
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0)
}

#[cfg(target_os = "linux")]
fn read_boot_id() -> Result<[u8; 16], SysboostError> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| {
        SysboostError::new(
            ErrorCode::DurabilityError,
            "boot identity could not be inspected",
        )
    })?;
    let value = value.trim().replace('-', "");
    if value.len() != 32 {
        return Err(SysboostError::new(
            ErrorCode::JournalCorrupt,
            "boot identity metadata has an invalid length",
        ));
    }
    let mut output = [0_u8; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        let high = hex_value(value.as_bytes()[index * 2]).ok_or_else(|| {
            SysboostError::new(
                ErrorCode::JournalCorrupt,
                "boot identity metadata is not hexadecimal",
            )
        })?;
        let low = hex_value(value.as_bytes()[index * 2 + 1]).ok_or_else(|| {
            SysboostError::new(
                ErrorCode::JournalCorrupt,
                "boot identity metadata is not hexadecimal",
            )
        })?;
        *byte = (high << 4) | low;
    }
    if output == [0; 16] {
        return Err(SysboostError::new(
            ErrorCode::JournalCorrupt,
            "boot identity metadata is zero",
        ));
    }
    Ok(output)
}

#[cfg(target_os = "linux")]
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Fixed process identity for tests and protocol fixtures.
#[derive(Clone, Copy, Debug)]
pub struct FixedProcessIdentity {
    identity: ProcessIdentity,
}

impl FixedProcessIdentity {
    /// Construct a fixed provider.
    pub const fn new(identity: ProcessIdentity) -> Self {
        Self { identity }
    }
}

impl ProcessIdentityProvider for FixedProcessIdentity {
    fn current(&self) -> Result<ProcessIdentity, SysboostError> {
        Ok(self.identity)
    }
}
