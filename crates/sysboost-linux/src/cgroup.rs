//! Typed, read-only cgroup access abstraction.

use sysboost_core::{CgroupId, SysboostError};
use sysboost_platform::{ReadOnlyFileSystem, RelativePath};

/// Cgroup filesystem generation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CgroupVersion {
    /// cgroup v1 semantics.
    V1,
    /// cgroup v2 semantics.
    V2,
}

/// Reviewed cgroup file vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CgroupFile {
    /// CPU weight/shares.
    CpuWeight,
    /// CPU quota and period.
    CpuMax,
    /// Effective CPU set.
    CpusetCpus,
}

impl CgroupFile {
    fn filename(self, version: CgroupVersion) -> &'static str {
        match (version, self) {
            (CgroupVersion::V1, Self::CpuWeight) => "cpu.shares",
            (CgroupVersion::V2, Self::CpuWeight) => "cpu.weight",
            (CgroupVersion::V1, Self::CpuMax) => "cpu.cfs_quota_us",
            (CgroupVersion::V2, Self::CpuMax) => "cpu.max",
            (_, Self::CpusetCpus) => "cpuset.cpus",
        }
    }
}

/// Existing cgroup target validated during discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CgroupTarget {
    /// Opaque identity evidence.
    pub identity: CgroupId,
    /// Validated relative path supplied by the Linux enumerator, never by the
    /// privileged wire caller.
    pub relative_path: RelativePath,
    /// Cgroup generation.
    pub version: CgroupVersion,
}

impl CgroupTarget {
    /// Resolve one reviewed file to an internal relative node.
    pub fn file_path(&self, file: CgroupFile) -> Result<RelativePath, SysboostError> {
        self.relative_path
            .join_component(file.filename(self.version))
    }
}

/// Read-only cgroup adapter. Mutation methods belong to a future reviewed
/// backend and are deliberately absent from this skeleton.
#[derive(Clone, Debug)]
pub struct CgroupAccess<F> {
    filesystem: F,
}

impl<F> CgroupAccess<F>
where
    F: ReadOnlyFileSystem,
{
    /// Construct a cgroup reader.
    pub fn new(filesystem: F) -> Self {
        Self { filesystem }
    }

    /// Read one reviewed cgroup file.
    pub fn read(&self, target: &CgroupTarget, file: CgroupFile) -> Result<Vec<u8>, SysboostError> {
        let path = target.file_path(file)?;
        self.filesystem.read(&path).map_err(|error| {
            error
                .with_stage(sysboost_core::Stage::Detect)
                .with_target(target.identity.handle.clone())
        })
    }
}
