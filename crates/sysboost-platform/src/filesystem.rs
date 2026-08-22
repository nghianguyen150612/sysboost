//! Read-only, root-independent filesystem port.

use core::fmt;

use sysboost_core::{ErrorCode, SysboostError, TargetIdentity};

/// A validated relative path used by a non-privileged read port.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RelativePath(String);

impl RelativePath {
    /// Validate and construct a slash-separated relative path.
    pub fn new(value: impl Into<String>) -> Result<Self, SysboostError> {
        let value = value.into();
        if value.is_empty() || value.len() > 256 {
            return Err(invalid_path("path must be non-empty and at most 256 bytes"));
        }
        if value.starts_with('/')
            || value.contains('\\')
            || value.contains(':')
            || value.contains('\0')
        {
            return Err(invalid_path(
                "path must be relative and contain no drive prefix, NUL, or backslash",
            ));
        }
        for component in value.split('/') {
            if component.is_empty() || component == "." || component == ".." {
                return Err(invalid_path(
                    "path contains an empty, '.', or '..' component",
                ));
            }
        }
        Ok(Self(value))
    }

    /// Append one validated component without allowing traversal.
    pub fn join_component(&self, component: &str) -> Result<Self, SysboostError> {
        if component.is_empty() || component.contains('/') || component.contains('\\') {
            return Err(invalid_path(
                "path component is not a single safe component",
            ));
        }
        Self::new(format!("{}/{}", self.0, component))
    }

    /// Return the canonical slash-separated form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RelativePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Metadata exposed by a read-only fixture/adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMetadata {
    /// Byte length.
    pub len: u64,
    /// Whether the adapter reports the node as read-only.
    pub read_only: bool,
}

/// Kind of entry returned by a read-only directory enumeration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EntryKind {
    /// A regular file or kernel pseudo-file.
    File,
    /// A directory that can be enumerated further.
    Directory,
    /// A symbolic link that must not be followed by the adapter.
    Symlink,
    /// An entry that is neither a regular file nor a directory.
    Other,
}

/// One bounded, name-only directory entry.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DirectoryEntry {
    /// Entry name relative to the enumerated directory.
    pub name: String,
    /// Entry kind observed without following a symlink.
    pub kind: EntryKind,
}

/// Read-only filesystem port. There is intentionally no generic write method.
pub trait ReadOnlyFileSystem {
    /// Read a validated relative node.
    fn read(&self, path: &RelativePath) -> Result<Vec<u8>, SysboostError>;

    /// Read metadata for a validated relative node.
    fn metadata(&self, path: &RelativePath) -> Result<FileMetadata, SysboostError>;

    /// Return backend-owned identity evidence for an existing node when the
    /// adapter can prove it.  Mutation-capable backends must not infer a
    /// target identity from an untrusted path string alone.
    fn identity(&self, path: &RelativePath) -> Result<TargetIdentity, SysboostError> {
        let _ = path;
        Err(SysboostError::new(
            ErrorCode::Unsupported,
            "filesystem adapter cannot prove node identity",
        ))
    }

    /// Enumerate one approved directory without following symlinks.
    ///
    /// `None` addresses the adapter root. Implementations may retain the
    /// default unsupported result when directory enumeration is not available
    /// for a particular fixture.
    fn list(&self, path: Option<&RelativePath>) -> Result<Vec<DirectoryEntry>, SysboostError> {
        let _ = path;
        Err(SysboostError::new(
            ErrorCode::Unsupported,
            "directory enumeration is unavailable for this filesystem port",
        ))
    }
}

fn invalid_path(message: &str) -> SysboostError {
    SysboostError::new(ErrorCode::TargetError, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths_reject_escape_forms() {
        assert!(RelativePath::new("sys/kernel").is_ok());
        assert!(RelativePath::new("/sys/kernel").is_err());
        assert!(RelativePath::new("sys/../proc").is_err());
        assert!(RelativePath::new("sys\\kernel").is_err());
        assert!(RelativePath::new("C:/outside").is_err());
        assert!(RelativePath::new("sys/ker\0nel").is_err());
    }

    #[test]
    fn component_join_remains_relative() {
        let path = RelativePath::new("devices/system/cpu").expect("valid base");
        assert_eq!(
            path.join_component("policy0").unwrap().as_str(),
            "devices/system/cpu/policy0"
        );
        assert!(path.join_component("../policy0").is_err());
    }
}
