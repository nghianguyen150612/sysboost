#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Linux adapters and fake-root fixtures.
//!
//! Runtime mutation is limited to the reviewed typed CPU and scheduler/cgroup
//! workload backends; all other Linux facilities remain report-only.

pub mod backend;
pub mod cgroup;
pub mod cpu;
pub mod discovery;
pub mod fs;
pub mod procfs;
pub mod sysfs;
pub mod topology;
pub mod workload;

pub use backend::ReportOnlyBackend;
pub use cgroup::{CgroupAccess, CgroupFile, CgroupTarget, CgroupVersion};
pub use cpu::{
    cpu_operation_catalog, CpuBackend, CpuBoostInterface, CpuFixture, CpuInspection, CpuNode,
    CpuNodeState, CPU_BACKEND_ID,
};
pub use discovery::{
    CapabilityDiscovery, CapabilityFinding, CpuFreqFacts, CpuFreqPolicyFacts, CpuTopologyEntry,
    CpuTopologyFacts, DiscoveryReport, DiscoverySources, DiscoveryStatus, EnvironmentFacts,
    GpuDeviceFacts, GpuFacts, HostRoots, IrqEntryFacts, IrqFacts, MemoryFacts, NumaFacts,
    NumaNodeFacts, SchedulerFacts, SystemdFacts,
};
pub use fs::{FixtureFilesystem, RootedFilesystem};
pub use procfs::{ProcfsAccess, ProcfsNode};
pub use sysfs::{SysfsAccess, SysfsNode};
pub use topology::{
    parse_cpu_list, CpuAffinityMask, CpuCapacityMode, CpuCoreGroup, CpuIsolationPlan,
    CpuIsolationPlanner, CpuPerformanceClass, CpuPlacementFallback, CpuPlacementPolicy,
    CpuSelectionPolicy, CpuTopology, CpuTopologyCpu, CpuTopologyPlanner, TopologyRevision,
    CPU_ISOLATION_OUTPUT_GATE, PREFER_PERFORMANCE_CORES_FLAG,
};
pub use workload::{
    workload_operation_catalog, CgroupFixture, ChildProcessSupervisor, WorkloadBackend,
    WorkloadInspection, WorkloadNode, WorkloadTarget, WORKLOAD_BACKEND_ID,
};

/// Return the combined closed-operation catalog for the reviewed Linux CPU
/// and scheduler/workload backends.
pub fn linux_operation_catalog() -> sysboost_core::OperationCatalog {
    let mut contracts = cpu_operation_catalog().contracts().to_vec();
    contracts.extend(workload_operation_catalog().contracts().iter().cloned());
    sysboost_core::OperationCatalog::new(contracts)
}

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
