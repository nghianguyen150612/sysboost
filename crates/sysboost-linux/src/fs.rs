//! Rooted Linux filesystem adapters and in-memory fixtures.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use sysboost_core::{ErrorCode, SysboostError, TargetIdentity};
use sysboost_platform::{
    DirectoryEntry, EntryKind, FileMetadata, ReadOnlyFileSystem, RelativePath,
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// Read-only adapter rooted at one explicitly selected mount/fixture.
#[derive(Clone, Debug)]
pub struct RootedFilesystem {
    root: PathBuf,
}

impl RootedFilesystem {
    /// Open an existing directory as a read-only adapter root.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, SysboostError> {
        let root = fs::canonicalize(root.as_ref()).map_err(|error| {
            SysboostError::new(
                ErrorCode::TargetError,
                format!("cannot resolve adapter root: {error}"),
            )
        })?;
        if !root.is_dir() {
            return Err(SysboostError::new(
                ErrorCode::TargetError,
                "adapter root is not a directory",
            ));
        }
        Ok(Self { root })
    }

    /// Return the canonical adapter root for diagnostics.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn resolve_existing(&self, path: &RelativePath) -> Result<PathBuf, SysboostError> {
        let mut candidate = self.root.clone();
        for component in path.as_str().split('/') {
            candidate.push(component);
            let metadata = fs::symlink_metadata(&candidate).map_err(|error| {
                SysboostError::new(
                    ErrorCode::TargetError,
                    format!("cannot inspect adapter node: {error}"),
                )
            })?;
            if metadata.file_type().is_symlink() {
                return Err(SysboostError::new(
                    ErrorCode::TargetError,
                    "symlink traversal is not accepted by the rooted adapter",
                ));
            }
        }
        let resolved = fs::canonicalize(&candidate).map_err(|error| {
            SysboostError::new(
                ErrorCode::TargetError,
                format!("cannot resolve adapter node: {error}"),
            )
        })?;
        if !resolved.starts_with(&self.root) {
            return Err(SysboostError::new(
                ErrorCode::TargetError,
                "resolved adapter node escapes its approved root",
            ));
        }
        Ok(resolved)
    }
}

impl ReadOnlyFileSystem for RootedFilesystem {
    fn read(&self, path: &RelativePath) -> Result<Vec<u8>, SysboostError> {
        let resolved = self.resolve_existing(path)?;
        fs::read(resolved).map_err(|error| {
            SysboostError::new(
                ErrorCode::CapabilityError,
                format!("cannot read adapter node: {error}"),
            )
        })
    }

    fn metadata(&self, path: &RelativePath) -> Result<FileMetadata, SysboostError> {
        let resolved = self.resolve_existing(path)?;
        let metadata = fs::metadata(resolved).map_err(|error| {
            SysboostError::new(
                ErrorCode::CapabilityError,
                format!("cannot read adapter metadata: {error}"),
            )
        })?;
        Ok(FileMetadata {
            len: metadata.len(),
            read_only: metadata.permissions().readonly(),
        })
    }

    fn identity(&self, path: &RelativePath) -> Result<TargetIdentity, SysboostError> {
        let resolved = self.resolve_existing(path)?;
        let metadata = fs::symlink_metadata(resolved).map_err(|error| {
            SysboostError::new(
                ErrorCode::CapabilityError,
                format!("cannot read adapter identity: {error}"),
            )
        })?;
        if metadata.file_type().is_symlink()
            || (!metadata.file_type().is_file() && !metadata.file_type().is_dir())
        {
            return Err(SysboostError::new(
                ErrorCode::TargetError,
                "adapter identity target has an unexpected type",
            ));
        }
        Ok(target_identity_from_metadata(&metadata))
    }

    fn list(&self, path: Option<&RelativePath>) -> Result<Vec<DirectoryEntry>, SysboostError> {
        let directory = match path {
            Some(path) => self.resolve_existing(path)?,
            None => self.root.clone(),
        };
        let metadata = fs::metadata(&directory).map_err(|error| {
            SysboostError::new(
                ErrorCode::TargetError,
                format!("cannot inspect adapter directory: {error}"),
            )
        })?;
        if !metadata.is_dir() {
            return Err(SysboostError::new(
                ErrorCode::TargetError,
                "adapter list target is not a directory",
            ));
        }

        let mut entries = Vec::new();
        for entry in fs::read_dir(directory).map_err(|error| {
            SysboostError::new(
                ErrorCode::CapabilityError,
                format!("cannot enumerate adapter directory: {error}"),
            )
        })? {
            let entry = entry.map_err(|error| {
                SysboostError::new(
                    ErrorCode::CapabilityError,
                    format!("cannot inspect adapter directory entry: {error}"),
                )
            })?;
            let kind = entry.file_type().map_err(|error| {
                SysboostError::new(
                    ErrorCode::CapabilityError,
                    format!("cannot read adapter entry type: {error}"),
                )
            })?;
            let entry_kind = if kind.is_file() {
                EntryKind::File
            } else if kind.is_dir() {
                EntryKind::Directory
            } else if kind.is_symlink() {
                EntryKind::Symlink
            } else {
                EntryKind::Other
            };
            entries.push(DirectoryEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                kind: entry_kind,
            });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }
}

/// In-memory fixture implementing the same read-only port without touching a
/// host filesystem. `set_fixture_value` is test setup, not a privileged port.
#[derive(Clone, Debug, Default)]
pub struct FixtureFilesystem {
    files: BTreeMap<RelativePath, FixtureFile>,
}

#[derive(Clone, Debug)]
struct FixtureFile {
    bytes: Vec<u8>,
    read_only: bool,
}

impl FixtureFilesystem {
    /// Create an empty fixture filesystem.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed or replace a fixture node for a test.
    pub fn set_fixture_value(
        &mut self,
        path: RelativePath,
        bytes: impl Into<Vec<u8>>,
        read_only: bool,
    ) {
        self.files.insert(
            path,
            FixtureFile {
                bytes: bytes.into(),
                read_only,
            },
        );
    }

    /// Return the number of fixture nodes.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether the fixture has no nodes.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

impl ReadOnlyFileSystem for FixtureFilesystem {
    fn read(&self, path: &RelativePath) -> Result<Vec<u8>, SysboostError> {
        self.files
            .get(path)
            .map(|file| file.bytes.clone())
            .ok_or_else(|| SysboostError::new(ErrorCode::TargetError, "fixture node is missing"))
    }

    fn metadata(&self, path: &RelativePath) -> Result<FileMetadata, SysboostError> {
        self.files
            .get(path)
            .map(|file| FileMetadata {
                len: file.bytes.len() as u64,
                read_only: file.read_only,
            })
            .ok_or_else(|| SysboostError::new(ErrorCode::TargetError, "fixture node is missing"))
    }

    fn identity(&self, path: &RelativePath) -> Result<TargetIdentity, SysboostError> {
        if self.files.contains_key(path)
            || self.files.keys().any(|candidate| {
                candidate
                    .as_str()
                    .starts_with(&format!("{}/", path.as_str()))
            })
        {
            Ok(fixture_target_identity(path))
        } else {
            Err(SysboostError::new(
                ErrorCode::TargetError,
                "fixture identity target is missing",
            ))
        }
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
                    "fixture list target is not a directory",
                ));
            }
        }
        if !path_exists {
            return Err(SysboostError::new(
                ErrorCode::TargetError,
                "fixture directory is missing",
            ));
        }
        Ok(entries
            .into_iter()
            .map(|(name, kind)| DirectoryEntry { name, kind })
            .collect())
    }
}

/// Deterministic identity evidence for an in-memory fixture node.
pub fn fixture_target_identity(path: &RelativePath) -> TargetIdentity {
    let mut lanes = [0xcbf29ce484222325_u64, 0x84222325cbf29ce4_u64];
    for (index, byte) in path.as_str().bytes().enumerate() {
        let lane = index % lanes.len();
        lanes[lane] ^= u64::from(byte);
        lanes[lane] = lanes[lane]
            .wrapping_mul(0x100000001b3)
            .rotate_left(((index % 63) + 1) as u32);
    }
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&lanes[0].to_be_bytes());
    bytes[8..].copy_from_slice(&lanes[1].to_be_bytes());
    TargetIdentity::from_bytes(bytes)
}

#[cfg(unix)]
fn target_identity_from_metadata(metadata: &fs::Metadata) -> TargetIdentity {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&metadata.dev().to_be_bytes());
    bytes[8..].copy_from_slice(&metadata.ino().to_be_bytes());
    TargetIdentity::from_bytes(bytes)
}

#[cfg(not(unix))]
fn target_identity_from_metadata(metadata: &fs::Metadata) -> TargetIdentity {
    fixture_target_identity(
        &RelativePath::new(format!("metadata:{}", metadata.len()))
            .expect("static identity fixture path is valid"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn rooted_adapter_rejects_symlink_traversal_and_root_escape() {
        use std::os::unix::fs::symlink;

        let suffix = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after the Unix epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(format!("sysboost-rooted-{suffix}"));
        let outside = std::env::temp_dir().join(format!("sysboost-outside-{suffix}"));
        std::fs::create_dir_all(root.join("inside")).expect("create rooted fixture");
        std::fs::create_dir_all(&outside).expect("create outside fixture");
        std::fs::write(root.join("inside/value"), b"inside").expect("write rooted fixture");
        std::fs::write(outside.join("value"), b"outside").expect("write outside fixture");
        symlink(root.join("inside"), root.join("alias")).expect("create internal symlink");
        symlink(&outside, root.join("escape")).expect("create escaping symlink");

        let adapter = RootedFilesystem::new(&root).expect("open rooted fixture");
        let internal_link = RelativePath::new("alias/value").expect("valid internal link path");
        let external_link = RelativePath::new("escape/value").expect("valid external link path");
        assert!(adapter.read(&internal_link).is_err());
        assert!(adapter.read(&external_link).is_err());

        std::fs::remove_dir_all(root).expect("remove rooted fixture");
        std::fs::remove_dir_all(outside).expect("remove outside fixture");
    }

    #[test]
    fn fixture_reads_values_without_host_io() {
        let path = RelativePath::new("sys/kernel/osrelease").expect("safe fixture path");
        let mut fixture = FixtureFilesystem::new();
        fixture.set_fixture_value(path.clone(), b"fixture-kernel\n", true);
        assert_eq!(fixture.read(&path).unwrap(), b"fixture-kernel\n");
        assert_eq!(fixture.metadata(&path).unwrap().len, 15);
    }
}
