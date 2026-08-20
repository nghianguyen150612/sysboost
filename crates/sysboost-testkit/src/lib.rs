#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Deterministic fake ports for core and backend contract tests.

use std::collections::BTreeMap;

use sysboost_core::{ErrorCode, Session, Snapshot, SysboostError, Timestamp, TransitionRecord};
use sysboost_platform::{
    DirectoryEntry, EntryKind, FileMetadata, JournalStore, ProcessIdentity,
    ProcessIdentityProvider, ReadOnlyFileSystem, RelativePath, StoredIntent,
};

/// In-memory filesystem fixture with no host path access.
#[derive(Clone, Debug, Default)]
pub struct MemoryFileSystem {
    files: BTreeMap<RelativePath, MemoryFile>,
}

#[derive(Clone, Debug)]
struct MemoryFile {
    bytes: Vec<u8>,
    read_only: bool,
}

impl MemoryFileSystem {
    /// Create an empty memory fixture.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a node for a fixture test.
    pub fn seed(&mut self, path: RelativePath, bytes: impl Into<Vec<u8>>, read_only: bool) {
        self.files.insert(
            path,
            MemoryFile {
                bytes: bytes.into(),
                read_only,
            },
        );
    }

    /// Simulate a concurrent external writer in a test fixture.
    pub fn external_replace(&mut self, path: &RelativePath, bytes: impl Into<Vec<u8>>) {
        if let Some(file) = self.files.get_mut(path) {
            file.bytes = bytes.into();
        }
    }
}

impl ReadOnlyFileSystem for MemoryFileSystem {
    fn read(&self, path: &RelativePath) -> Result<Vec<u8>, SysboostError> {
        self.files
            .get(path)
            .map(|file| file.bytes.clone())
            .ok_or_else(|| {
                SysboostError::new(ErrorCode::TargetError, "memory fixture node is missing")
            })
    }

    fn metadata(&self, path: &RelativePath) -> Result<FileMetadata, SysboostError> {
        self.files
            .get(path)
            .map(|file| FileMetadata {
                len: file.bytes.len() as u64,
                read_only: file.read_only,
            })
            .ok_or_else(|| {
                SysboostError::new(ErrorCode::TargetError, "memory fixture node is missing")
            })
    }

    fn list(&self, path: Option<&RelativePath>) -> Result<Vec<DirectoryEntry>, SysboostError> {
        let prefix = path.map(RelativePath::as_str);
        let mut entries = BTreeMap::new();
        let mut path_exists = path.is_none();
        for file_path in self.files.keys() {
            let remainder = match prefix {
                Some(prefix) => {
                    if file_path.as_str() == prefix {
                        path_exists = true;
                        continue;
                    }
                    let prefix_with_separator = format!("{prefix}/");
                    let Some(remainder) = file_path.as_str().strip_prefix(&prefix_with_separator)
                    else {
                        continue;
                    };
                    path_exists = true;
                    remainder
                }
                None => file_path.as_str(),
            };
            let Some((name, suffix)) = remainder.split_once('/') else {
                entries.insert(remainder.to_owned(), EntryKind::File);
                continue;
            };
            if !name.is_empty() && !suffix.is_empty() {
                entries.insert(name.to_owned(), EntryKind::Directory);
            }
        }
        if let Some(path) = path {
            if self.files.contains_key(path) {
                return Err(SysboostError::new(
                    ErrorCode::TargetError,
                    "memory list target is not a directory",
                ));
            }
        }
        if !path_exists {
            return Err(SysboostError::new(
                ErrorCode::TargetError,
                "memory directory is missing",
            ));
        }
        Ok(entries
            .into_iter()
            .map(|(name, kind)| DirectoryEntry { name, kind })
            .collect())
    }
}

/// Journal fixture with explicit failure injection.
#[derive(Clone, Debug, Default)]
pub struct MemoryJournal {
    /// Durable intents captured by the fixture.
    pub intents: Vec<StoredIntent>,
    /// Durable transitions captured by the fixture.
    pub transitions: Vec<TransitionRecord>,
    /// If set, intent creation fails.
    pub fail_create: bool,
    /// If set, transition persistence fails.
    pub fail_append: bool,
}

impl JournalStore for MemoryJournal {
    fn create_intent(
        &mut self,
        session: &Session,
        snapshots: &[Snapshot],
    ) -> Result<(), SysboostError> {
        if self.fail_create {
            return Err(SysboostError::new(
                ErrorCode::DurabilityError,
                "memory journal injected intent failure",
            ));
        }
        self.intents.push(StoredIntent {
            session: session.clone(),
            snapshots: snapshots.to_vec(),
        });
        Ok(())
    }

    fn append_transition(&mut self, transition: &TransitionRecord) -> Result<(), SysboostError> {
        if self.fail_append {
            return Err(SysboostError::new(
                ErrorCode::DurabilityError,
                "memory journal injected transition failure",
            ));
        }
        self.transitions.push(transition.clone());
        Ok(())
    }

    fn load_unfinished(&self) -> Result<Vec<StoredIntent>, SysboostError> {
        Ok(self
            .intents
            .iter()
            .filter(|intent| !matches!(intent.session.state, sysboost_core::SessionState::Restored))
            .cloned()
            .collect())
    }
}

/// Deterministic clock.
#[derive(Clone, Copy, Debug)]
pub struct FakeClock {
    /// Fixed timestamp.
    pub timestamp: Timestamp,
}

impl FakeClock {
    /// Construct a fixed test clock.
    pub const fn new(timestamp: Timestamp) -> Self {
        Self { timestamp }
    }
}

impl sysboost_platform::Clock for FakeClock {
    fn now(&self) -> Result<Timestamp, SysboostError> {
        Ok(self.timestamp)
    }
}

/// Deterministic process identity.
#[derive(Clone, Copy, Debug)]
pub struct FakeProcess {
    /// Fixed identity.
    pub identity: ProcessIdentity,
}

impl FakeProcess {
    /// Construct a fixed process provider.
    pub const fn new(identity: ProcessIdentity) -> Self {
        Self { identity }
    }
}

impl ProcessIdentityProvider for FakeProcess {
    fn current(&self) -> Result<ProcessIdentity, SysboostError> {
        Ok(self.identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_fixture_supports_external_change_simulation() {
        let path = RelativePath::new("fixture/value").expect("valid fixture path");
        let mut filesystem = MemoryFileSystem::new();
        filesystem.seed(path.clone(), b"before", false);
        filesystem.external_replace(&path, b"external");
        assert_eq!(filesystem.read(&path).unwrap(), b"external");
    }

    #[test]
    fn journal_failure_is_explicit() {
        let mut journal = MemoryJournal {
            fail_create: true,
            ..MemoryJournal::default()
        };
        let result = journal.create_intent(
            &Session {
                header: sysboost_core::SessionHeader {
                    session_id: sysboost_core::SessionId::from_bytes([1; 16]),
                    plan_id: sysboost_core::PlanId::from_bytes([2; 16]),
                    plan_digest: [3; 32],
                    created_at: Timestamp::from_unix_millis(1),
                    targets: Vec::new(),
                },
                state: sysboost_core::SessionState::New,
            },
            &[],
        );
        assert_eq!(result.unwrap_err().code, ErrorCode::DurabilityError);
    }

    #[test]
    fn journal_persists_intent_transitions_and_filters_restored_sessions() {
        let session_id = sysboost_core::SessionId::from_bytes([4; 16]);
        let mut journal = MemoryJournal::default();
        let session = Session {
            header: sysboost_core::SessionHeader {
                session_id,
                plan_id: sysboost_core::PlanId::from_bytes([5; 16]),
                plan_digest: [6; 32],
                created_at: Timestamp::from_unix_millis(2),
                targets: Vec::new(),
            },
            state: sysboost_core::SessionState::New,
        };

        journal
            .create_intent(&session, &[])
            .expect("intent is retained in memory");
        let transition = TransitionRecord {
            sequence: 1,
            session_id,
            from: sysboost_core::SessionState::New,
            to: sysboost_core::SessionState::Detected,
            at: Timestamp::from_unix_millis(3),
            reason: "fixture transition".to_owned(),
        };
        journal
            .append_transition(&transition)
            .expect("transition is retained in memory");

        assert_eq!(journal.intents.len(), 1);
        assert_eq!(journal.transitions, vec![transition]);
        assert_eq!(journal.load_unfinished().unwrap().len(), 1);

        journal.intents[0].session.state = sysboost_core::SessionState::Restored;
        assert!(journal.load_unfinished().unwrap().is_empty());
    }
}
