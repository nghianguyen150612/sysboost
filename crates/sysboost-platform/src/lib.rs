#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Platform ports with no Linux path knowledge.

pub mod backend;
pub mod clock;
pub mod filesystem;
pub mod journal;
pub mod logging;
pub mod privilege;
pub mod process;
pub mod state;
pub mod transaction;

pub use backend::{BackendDescriptor, BackendRegistry, CapabilityDetector, MutationBackend};
pub use clock::{Clock, FixedClock, SystemClock};
pub use filesystem::{DirectoryEntry, EntryKind, FileMetadata, ReadOnlyFileSystem, RelativePath};
pub use journal::{JournalStore, StoredIntent};
pub use logging::JsonLogger;
pub use privilege::{ApprovedPlanCatalog, PrivilegeBroker, PrivilegeService, SessionHandle};
pub use process::{CurrentProcess, FixedProcessIdentity, ProcessIdentity, ProcessIdentityProvider};
pub use state::{
    ExclusiveSessionLock, FileSessionLock, FileSessionLockGuard, FileStateStore,
    RuntimeStatePolicy, SessionIdSource, SessionStateStore, SystemSessionIdSource,
    DEFAULT_STATE_ROOT,
};
pub use transaction::{BackendExecutionToken, TransactionEngine, TransactionStatus};
