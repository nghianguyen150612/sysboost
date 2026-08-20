//! Closed procfs read nodes. No generic `/proc/sys` writer is exposed.

use sysboost_core::SysboostError;
use sysboost_platform::{ReadOnlyFileSystem, RelativePath};

/// Procfs nodes used by report-only detection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProcfsNode {
    /// Kernel release string.
    KernelVersion,
    /// Current process status.
    SelfStatus,
    /// Load average report.
    LoadAverage,
}

impl ProcfsNode {
    /// Resolve to a fixed relative path.
    pub fn relative_path(self) -> RelativePath {
        let path = match self {
            Self::KernelVersion => "sys/kernel/osrelease",
            Self::SelfStatus => "self/status",
            Self::LoadAverage => "loadavg",
        };
        RelativePath::new(path).expect("static procfs paths are valid")
    }
}

/// Typed procfs reader over an injected filesystem port.
#[derive(Clone, Debug)]
pub struct ProcfsAccess<F> {
    filesystem: F,
}

impl<F> ProcfsAccess<F>
where
    F: ReadOnlyFileSystem,
{
    /// Construct a procfs reader.
    pub fn new(filesystem: F) -> Self {
        Self { filesystem }
    }

    /// Read one approved procfs node.
    pub fn read(&self, node: ProcfsNode) -> Result<Vec<u8>, SysboostError> {
        self.filesystem.read(&node.relative_path())
    }
}
