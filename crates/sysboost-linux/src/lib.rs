#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Linux adapters and fake-root fixtures.
//!
//! This skeleton only reads through typed nodes. Runtime mutation backends are
//! intentionally not implemented here.

pub mod backend;
pub mod cgroup;
pub mod discovery;
pub mod fs;
pub mod procfs;
pub mod sysfs;

pub use backend::ReportOnlyBackend;
pub use cgroup::{CgroupAccess, CgroupFile, CgroupTarget, CgroupVersion};
pub use discovery::{
    CapabilityDiscovery, CapabilityFinding, CpuFreqFacts, CpuFreqPolicyFacts, CpuTopologyEntry,
    CpuTopologyFacts, DiscoveryReport, DiscoverySources, DiscoveryStatus, EnvironmentFacts,
    GpuDeviceFacts, GpuFacts, HostRoots, IrqEntryFacts, IrqFacts, MemoryFacts, NumaFacts,
    NumaNodeFacts, SchedulerFacts, SystemdFacts,
};
pub use fs::{FixtureFilesystem, RootedFilesystem};
pub use procfs::{ProcfsAccess, ProcfsNode};
pub use sysfs::{SysfsAccess, SysfsNode};

#[cfg(test)]
mod tests {
    use super::*;
    use sysboost_core::{CgroupId, CpuPolicyId, TargetId};
    use sysboost_platform::{ReadOnlyFileSystem, RelativePath};

    #[test]
    fn sysfs_procfs_and_cgroup_nodes_use_the_same_fake_root_contract() {
        let sysfs_node = SysfsNode::CpuPolicyGovernor(CpuPolicyId::new(0));
        let procfs_node = ProcfsNode::KernelVersion;
        let cgroup_target = CgroupTarget {
            identity: CgroupId::new(
                1,
                2,
                TargetId::new("service.main").expect("valid opaque handle"),
            ),
            relative_path: RelativePath::new("service.main").expect("valid relative path"),
            version: CgroupVersion::V2,
        };
        let cgroup_path = cgroup_target
            .file_path(CgroupFile::CpuWeight)
            .expect("valid cgroup node");

        let mut fixture = FixtureFilesystem::new();
        fixture.set_fixture_value(
            sysfs_node.relative_path().expect("valid sysfs node"),
            b"performance\n",
            true,
        );
        fixture.set_fixture_value(procfs_node.relative_path(), b"6.9-test\n", true);
        fixture.set_fixture_value(cgroup_path, b"100\n", false);

        let sysfs = SysfsAccess::new(fixture.clone());
        let procfs = ProcfsAccess::new(fixture.clone());
        let cgroup = CgroupAccess::new(fixture);
        assert_eq!(sysfs.read(sysfs_node).unwrap(), b"performance\n");
        assert_eq!(procfs.read(procfs_node).unwrap(), b"6.9-test\n");
        assert_eq!(
            cgroup.read(&cgroup_target, CgroupFile::CpuWeight).unwrap(),
            b"100\n"
        );
    }

    #[test]
    fn rooted_path_contract_rejects_missing_fake_nodes() {
        let fixture = FixtureFilesystem::new();
        let missing = RelativePath::new("missing/node").expect("valid relative path");
        assert!(fixture.read(&missing).is_err());
    }
}
