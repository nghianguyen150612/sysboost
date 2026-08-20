//! Closed sysfs read nodes.

use sysboost_core::{CpuPolicyId, SysboostError};
use sysboost_platform::{ReadOnlyFileSystem, RelativePath};

/// Sysfs nodes reserved by the CPU policy backend.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SysfsNode {
    /// CPU policy minimum frequency.
    CpuPolicyMinFrequency(CpuPolicyId),
    /// CPU policy maximum frequency.
    CpuPolicyMaxFrequency(CpuPolicyId),
    /// CPU policy governor.
    CpuPolicyGovernor(CpuPolicyId),
    /// CPU policy energy preference.
    CpuPolicyEnergyPreference(CpuPolicyId),
}

impl SysfsNode {
    /// Resolve an approved semantic node to an internal relative path.
    pub fn relative_path(self) -> Result<RelativePath, SysboostError> {
        let (policy, file) = match self {
            Self::CpuPolicyMinFrequency(policy) => (policy.get(), "scaling_min_freq"),
            Self::CpuPolicyMaxFrequency(policy) => (policy.get(), "scaling_max_freq"),
            Self::CpuPolicyGovernor(policy) => (policy.get(), "scaling_governor"),
            Self::CpuPolicyEnergyPreference(policy) => {
                (policy.get(), "energy_performance_preference")
            }
        };
        RelativePath::new(format!("devices/system/cpu/cpufreq/policy{policy}/{file}"))
    }
}

/// Typed sysfs reader over an injected filesystem port.
#[derive(Clone, Debug)]
pub struct SysfsAccess<F> {
    filesystem: F,
}

impl<F> SysfsAccess<F>
where
    F: ReadOnlyFileSystem,
{
    /// Construct a sysfs reader.
    pub fn new(filesystem: F) -> Self {
        Self { filesystem }
    }

    /// Read one approved sysfs node.
    pub fn read(&self, node: SysfsNode) -> Result<Vec<u8>, SysboostError> {
        let path = node.relative_path()?;
        self.filesystem.read(&path).map_err(|error| {
            error.with_stage(sysboost_core::Stage::Detect).with_target(
                sysboost_core::TargetId::new(format!("sysfs.{}", path.as_str())).unwrap_or_else(
                    |_| sysboost_core::TargetId::new("sysfs.node").expect("static target"),
                ),
            )
        })
    }

    /// Borrow the underlying read-only adapter.
    pub fn filesystem(&self) -> &F {
        &self.filesystem
    }
}
