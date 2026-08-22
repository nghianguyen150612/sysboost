//! Durable session state and the exclusive mutating-session lease.
//!
//! The production state root is `/run/sysboost`.  The implementation accepts
//! an explicitly supplied root so all tests can use a temporary directory or
//! an in-memory store; no test needs to touch the host's runtime state.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sysboost_core::{
    ErrorCode, Retryability, SessionId, SessionRecord, SysboostError, MAX_SESSION_RECORD_BYTES,
};

use crate::process::{probe_process, CurrentProcess, ProcessIdentity, ProcessIdentityProvider};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

/// Default runtime state root used by the privileged service.
pub const DEFAULT_STATE_ROOT: &str = "/run/sysboost";

/// Required owner and mode policy for the private runtime-state directory.
///
/// Production composition uses [`Self::root_owned`].  Explicit-root
/// constructors use the current process credentials so deterministic tests can
/// use a private temporary directory without weakening the production policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeStatePolicy {
    /// Expected numeric owner UID.
    pub owner_uid: u32,
    /// Expected numeric owner GID.
    pub owner_gid: u32,
    /// Exact permission bits for the state directory.
    pub directory_mode: u32,
    /// Exact permission bits for state and lock files.
    pub file_mode: u32,
}

impl RuntimeStatePolicy {
    /// Root-owned production policy for `/run/sysboost`.
    pub const fn root_owned() -> Self {
        Self {
            owner_uid: 0,
            owner_gid: 0,
            directory_mode: 0o700,
            file_mode: 0o600,
        }
    }

    /// Current-process policy for explicitly supplied test roots.
    pub fn current_process() -> Self {
        let (owner_uid, owner_gid) = current_process_credentials().unwrap_or((0, 0));
        Self {
            owner_uid,
            owner_gid,
            directory_mode: 0o700,
            file_mode: 0o600,
        }
    }
}

/// Port for atomically replacing complete session records.
pub trait SessionStateStore {
    /// Create a new session state file.  Existing session IDs are rejected.
    fn create(&mut self, record: &SessionRecord) -> Result<(), SysboostError>;

    /// Atomically replace an existing session state file.
    fn replace(&mut self, record: &SessionRecord) -> Result<(), SysboostError>;

    /// Load one session by its typed ID.
    fn load(&self, session_id: SessionId) -> Result<SessionRecord, SysboostError>;

    /// Load all sessions that are not positively restored.
    fn load_unfinished(&self) -> Result<Vec<SessionRecord>, SysboostError>;

    /// Remove a session state file when no mutation was ever admitted.
    fn remove(&mut self, session_id: SessionId) -> Result<(), SysboostError>;
}

/// Exclusive lock port for the one mutating session allowed by the first
/// transaction engine.
pub trait ExclusiveSessionLock {
    /// Guard held for the lifetime of the mutating transaction.
    type Guard;

    /// Try to acquire the exclusive lease.
    fn acquire(&mut self) -> Result<Self::Guard, SysboostError>;
}

/// Session-ID source.  Production uses kernel-provided entropy; tests provide
/// deterministic IDs and can exercise collision handling.
pub trait SessionIdSource {
    /// Generate one candidate ID.
    fn next_id(&mut self) -> Result<SessionId, SysboostError>;
}

/// Filesystem-backed durable state store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileStateStore {
    root: PathBuf,
    policy: RuntimeStatePolicy,
}

impl FileStateStore {
    /// Construct a store under an explicitly approved root.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_policy(root, RuntimeStatePolicy::current_process())
    }

    /// Construct a store with an explicit owner/mode policy.
    pub fn with_policy(root: impl Into<PathBuf>, policy: RuntimeStatePolicy) -> Self {
        Self {
            root: root.into(),
            policy,
        }
    }

    /// Construct the production `/run/sysboost` store.
    pub fn production() -> Self {
        Self::with_policy(
            PathBuf::from(DEFAULT_STATE_ROOT),
            RuntimeStatePolicy::root_owned(),
        )
    }

    /// Borrow the configured state root for composition-root diagnostics.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn ensure_root(&self) -> Result<(), SysboostError> {
        ensure_runtime_root(&self.root, self.policy)
    }

    fn state_path(&self, session_id: SessionId) -> PathBuf {
        self.root.join(format!("{}.state", session_id.to_hex()))
    }

    fn load_path(
        &self,
        path: &Path,
        expected: Option<SessionId>,
    ) -> Result<SessionRecord, SysboostError> {
        let bytes = read_verified_file(path, self.policy, MAX_SESSION_RECORD_BYTES)?;
        let record = SessionRecord::decode(&bytes)?;
        if let Some(expected) = expected {
            if record.session.header.session_id != expected {
                return Err(SysboostError::new(
                    ErrorCode::JournalCorrupt,
                    "session state identity does not match its requested ID",
                ));
            }
        }
        Ok(record)
    }

    fn write_atomic(&self, record: &SessionRecord, replace: bool) -> Result<(), SysboostError> {
        self.ensure_root()?;
        let session_id = record.session.header.session_id;
        let target = self.state_path(session_id);
        validate_target_for_write(&target, self.policy, replace, session_id)?;
        let bytes = record.encode()?;
        let temporary = self.temporary_path(session_id);
        let mut temporary_created = false;
        let write_result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options
                .mode(self.policy.file_mode)
                .custom_flags(open_cloexec_flags() | open_nofollow_flags());
            let mut file = options.open(&temporary)?;
            temporary_created = true;
            validate_open_file(&file, self.policy, "temporary state file")
                .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            self.ensure_root()
                .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
            // Re-check the replacement target immediately before the atomic
            // rename.  The directory is private, so an unprivileged peer
            // cannot race this check; a privileged/admin replacement still
            // fails closed on the post-rename validation below.
            validate_target_for_write(&target, self.policy, replace, session_id)
                .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
            fs::rename(&temporary, &target)?;
            temporary_created = false;
            validate_regular_path(&target, self.policy, "session state file")
                .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
            sync_directory(&self.root, self.policy)?;
            Ok::<(), io::Error>(())
        })();
        if let Err(error) = write_result {
            if temporary_created {
                let _ = fs::remove_file(&temporary);
            }
            return Err(io_error(ErrorCode::DurabilityError, error).with_session(session_id));
        }
        Ok(())
    }

    fn temporary_path(&self, session_id: SessionId) -> PathBuf {
        let pid = std::process::id();
        let tick = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        self.root.join(format!(
            ".{}.state.tmp.{}.{}",
            session_id.to_hex(),
            pid,
            tick
        ))
    }
}

impl Default for FileStateStore {
    fn default() -> Self {
        Self::production()
    }
}

impl SessionStateStore for FileStateStore {
    fn create(&mut self, record: &SessionRecord) -> Result<(), SysboostError> {
        self.write_atomic(record, false)
    }

    fn replace(&mut self, record: &SessionRecord) -> Result<(), SysboostError> {
        self.write_atomic(record, true)
    }

    fn load(&self, session_id: SessionId) -> Result<SessionRecord, SysboostError> {
        self.ensure_root()?;
        self.load_path(&self.state_path(session_id), Some(session_id))
    }

    fn load_unfinished(&self) -> Result<Vec<SessionRecord>, SysboostError> {
        self.ensure_root()?;
        let entries = fs::read_dir(&self.root)
            .map_err(|error| io_error(ErrorCode::DurabilityError, error))?;
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| io_error(ErrorCode::DurabilityError, error))?;
            let file_type = entry
                .file_type()
                .map_err(|error| io_error(ErrorCode::DurabilityError, error))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(SysboostError::new(
                    ErrorCode::JournalCorrupt,
                    "runtime state contains a non-text object name",
                ));
            };
            if name == ".mutating.lock" {
                validate_entry_metadata(&entry.path(), &file_type, self.policy, "lock file")?;
                continue;
            }
            if name.starts_with('.') && name.contains(".state.tmp.") {
                if !is_valid_temporary_name(name) {
                    return Err(SysboostError::new(
                        ErrorCode::JournalCorrupt,
                        "temporary runtime state filename is malformed",
                    ));
                }
                validate_entry_metadata(
                    &entry.path(),
                    &file_type,
                    self.policy,
                    "temporary state file",
                )?;
                continue;
            }
            if !name.ends_with(".state") {
                return Err(SysboostError::new(
                    ErrorCode::JournalCorrupt,
                    "runtime state contains an unexpected filesystem object",
                ));
            }
            if !file_type.is_file() {
                return Err(SysboostError::new(
                    ErrorCode::JournalCorrupt,
                    "session state entry is not a regular file",
                ));
            }
            let hex = name.trim_end_matches(".state");
            let session_id = hex.parse::<SessionId>().map_err(|_| {
                SysboostError::new(
                    ErrorCode::JournalCorrupt,
                    "session state filename is not a valid session ID",
                )
            })?;
            let record = self.load_path(&entry.path(), Some(session_id))?;
            if !matches!(record.session.state, sysboost_core::SessionState::Restored) {
                records.push(record);
            }
        }
        records.sort_by_key(|record| record.session.header.session_id);
        Ok(records)
    }

    fn remove(&mut self, session_id: SessionId) -> Result<(), SysboostError> {
        self.ensure_root()?;
        let path = self.state_path(session_id);
        if fs::symlink_metadata(&path).is_ok() {
            validate_regular_path(&path, self.policy, "session state file")?;
        }
        match fs::remove_file(path) {
            Ok(()) => {
                sync_directory(&self.root, self.policy)
                    .map_err(|error| io_error(ErrorCode::DurabilityError, error))?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(ErrorCode::DurabilityError, error).with_session(session_id)),
        }
    }
}

/// Filesystem lock provider for `/run/sysboost/.mutating.lock`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileSessionLock {
    root: PathBuf,
    policy: RuntimeStatePolicy,
}

/// Held filesystem lock.  Dropping it releases the lease.
#[derive(Debug)]
pub struct FileSessionLockGuard {
    path: PathBuf,
    file: Option<File>,
    identity: FileIdentity,
}

impl FileSessionLock {
    /// Construct a lock provider under an explicit state root.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_policy(root, RuntimeStatePolicy::current_process())
    }

    /// Construct a lock provider with an explicit owner/mode policy.
    pub fn with_policy(root: impl Into<PathBuf>, policy: RuntimeStatePolicy) -> Self {
        Self {
            root: root.into(),
            policy,
        }
    }

    /// Construct the production lock provider.
    pub fn production() -> Self {
        Self::with_policy(
            PathBuf::from(DEFAULT_STATE_ROOT),
            RuntimeStatePolicy::root_owned(),
        )
    }

    fn ensure_root(&self) -> Result<(), SysboostError> {
        ensure_runtime_root(&self.root, self.policy)
    }
}

impl Default for FileSessionLock {
    fn default() -> Self {
        Self::production()
    }
}

impl ExclusiveSessionLock for FileSessionLock {
    type Guard = FileSessionLockGuard;

    fn acquire(&mut self) -> Result<Self::Guard, SysboostError> {
        self.ensure_root()?;
        let path = self.root.join(".mutating.lock");
        let owner = CurrentProcess.current()?;
        for _attempt in 0..2 {
            let mut created_identity = None;
            let result = (|| {
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                options
                    .mode(self.policy.file_mode)
                    .custom_flags(open_cloexec_flags() | open_nofollow_flags());
                let mut file = options.open(&path)?;
                let identity = validate_open_file(&file, self.policy, "lock file")
                    .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
                created_identity = Some(identity);
                file.write_all(&encode_lock_owner(owner))?;
                file.sync_all()?;
                sync_directory(&self.root, self.policy)?;
                Ok::<(File, FileIdentity), io::Error>((file, identity))
            })();
            match result {
                Ok((file, identity)) => {
                    return Ok(FileSessionLockGuard {
                        path,
                        file: Some(file),
                        identity,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if reclaim_stale_lock(&path, self.policy)? {
                        continue;
                    }
                    return Err(SysboostError::new(
                        ErrorCode::AuthorizationError,
                        "another mutating session owns the exclusive lock",
                    )
                    .retryable(Retryability::Retry));
                }
                Err(error) => {
                    if let Some(identity) = created_identity {
                        let _ = remove_file_if_identity(&path, identity);
                    }
                    return Err(io_error(ErrorCode::DurabilityError, error));
                }
            }
        }
        Err(SysboostError::new(
            ErrorCode::AuthorizationError,
            "another mutating session owns the exclusive lock",
        )
        .retryable(Retryability::Retry))
    }
}

impl Drop for FileSessionLockGuard {
    fn drop(&mut self) {
        let _ = self.file.take();
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_file() && FileIdentity::from_metadata(&metadata) == self.identity
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Production entropy-backed session ID source.
#[derive(Debug, Default)]
pub struct SystemSessionIdSource {
    random: Option<File>,
}

impl SystemSessionIdSource {
    /// Construct a lazy entropy source.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionIdSource for SystemSessionIdSource {
    fn next_id(&mut self) -> Result<SessionId, SysboostError> {
        if self.random.is_none() {
            self.random = Some(
                File::open("/dev/urandom")
                    .map_err(|error| io_error(ErrorCode::DurabilityError, error))?,
            );
        }
        loop {
            let mut bytes = [0_u8; 16];
            self.random
                .as_mut()
                .expect("entropy file was initialized")
                .read_exact(&mut bytes)
                .map_err(|error| io_error(ErrorCode::DurabilityError, error))?;
            if bytes != [0; 16] {
                return Ok(SessionId::from_bytes(bytes));
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    opaque: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                opaque: metadata.len(),
            }
        }
    }
}

fn ensure_runtime_root(path: &Path, policy: RuntimeStatePolicy) -> Result<(), SysboostError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_directory_metadata(&metadata, policy, "runtime state root"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| {
                SysboostError::new(
                    ErrorCode::DurabilityError,
                    "runtime state root has no trusted parent",
                )
            })?;
            let parent_metadata = fs::symlink_metadata(parent)
                .map_err(|error| io_error(ErrorCode::DurabilityError, error))?;
            if !parent_metadata.file_type().is_dir() {
                return Err(SysboostError::new(
                    ErrorCode::JournalCorrupt,
                    "runtime state root parent is not a directory",
                ));
            }
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            builder.mode(policy.directory_mode);
            match builder.create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(io_error(ErrorCode::DurabilityError, error)),
            }
            // The root directory entry itself must be durable before state or
            // lock files are created beneath it.
            File::open(parent)
                .and_then(|file| file.sync_all())
                .map_err(|error| io_error(ErrorCode::DurabilityError, error))?;
            let metadata = fs::symlink_metadata(path)
                .map_err(|error| io_error(ErrorCode::DurabilityError, error))?;
            validate_directory_metadata(&metadata, policy, "runtime state root")
        }
        Err(error) => Err(io_error(ErrorCode::DurabilityError, error)),
    }
}

fn validate_directory_metadata(
    metadata: &fs::Metadata,
    policy: RuntimeStatePolicy,
    description: &str,
) -> Result<(), SysboostError> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(SysboostError::new(
            ErrorCode::JournalCorrupt,
            format!("{description} is not a regular directory"),
        ));
    }
    #[cfg(unix)]
    {
        if metadata.uid() != policy.owner_uid || metadata.gid() != policy.owner_gid {
            return Err(SysboostError::new(
                ErrorCode::AuthorizationError,
                format!("{description} owner is not authorized"),
            ));
        }
        if metadata.mode() & 0o7777 != policy.directory_mode {
            return Err(SysboostError::new(
                ErrorCode::JournalCorrupt,
                format!("{description} permissions are not private"),
            ));
        }
    }
    Ok(())
}

fn validate_regular_path(
    path: &Path,
    policy: RuntimeStatePolicy,
    description: &str,
) -> Result<FileIdentity, SysboostError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error(ErrorCode::DurabilityError, error))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(SysboostError::new(
            ErrorCode::JournalCorrupt,
            format!("{description} is not a regular file"),
        ));
    }
    validate_regular_metadata(&metadata, policy, description)?;
    Ok(FileIdentity::from_metadata(&metadata))
}

fn validate_regular_metadata(
    metadata: &fs::Metadata,
    policy: RuntimeStatePolicy,
    description: &str,
) -> Result<(), SysboostError> {
    #[cfg(unix)]
    {
        if metadata.uid() != policy.owner_uid || metadata.gid() != policy.owner_gid {
            return Err(SysboostError::new(
                ErrorCode::AuthorizationError,
                format!("{description} owner is not authorized"),
            ));
        }
        if metadata.mode() & 0o7777 != policy.file_mode {
            return Err(SysboostError::new(
                ErrorCode::JournalCorrupt,
                format!("{description} permissions are not private"),
            ));
        }
        if metadata.nlink() != 1 {
            return Err(SysboostError::new(
                ErrorCode::JournalCorrupt,
                format!("{description} has unexpected hard links"),
            ));
        }
    }
    Ok(())
}

fn validate_open_file(
    file: &File,
    policy: RuntimeStatePolicy,
    description: &str,
) -> Result<FileIdentity, SysboostError> {
    let metadata = file
        .metadata()
        .map_err(|error| io_error(ErrorCode::DurabilityError, error))?;
    if !metadata.file_type().is_file() {
        return Err(SysboostError::new(
            ErrorCode::JournalCorrupt,
            format!("{description} is not a regular file"),
        ));
    }
    validate_regular_metadata(&metadata, policy, description)?;
    Ok(FileIdentity::from_metadata(&metadata))
}

fn validate_entry_metadata(
    path: &Path,
    file_type: &fs::FileType,
    policy: RuntimeStatePolicy,
    description: &str,
) -> Result<(), SysboostError> {
    if file_type.is_symlink() || !file_type.is_file() {
        return Err(SysboostError::new(
            ErrorCode::JournalCorrupt,
            format!("{description} is not a regular file"),
        ));
    }
    validate_regular_path(path, policy, description).map(|_| ())
}

fn is_valid_temporary_name(name: &str) -> bool {
    let Some(name) = name.strip_prefix('.') else {
        return false;
    };
    let Some((session_hex, suffix)) = name.split_once(".state.tmp.") else {
        return false;
    };
    let Some((pid, tick)) = suffix.split_once('.') else {
        return false;
    };
    session_hex.parse::<SessionId>().is_ok()
        && pid.parse::<u32>().is_ok_and(|value| value != 0)
        && tick.parse::<u128>().is_ok()
}

fn read_verified_file(
    path: &Path,
    policy: RuntimeStatePolicy,
    maximum: usize,
) -> Result<Vec<u8>, SysboostError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(open_cloexec_flags() | open_nofollow_flags());
    let file = options
        .open(path)
        .map_err(|error| io_error(ErrorCode::DurabilityError, error))?;
    validate_open_file(&file, policy, "runtime state file")?;
    let mut bytes = Vec::new();
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(ErrorCode::DurabilityError, error))?;
    if bytes.len() > maximum {
        return Err(SysboostError::new(
            ErrorCode::JournalCorrupt,
            "runtime state file exceeds its decoder bound",
        ));
    }
    Ok(bytes)
}

fn remove_file_if_identity(path: &Path, expected: FileIdentity) -> Result<bool, io::Error> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() || FileIdentity::from_metadata(&metadata) != expected {
        return Ok(false);
    }
    fs::remove_file(path)?;
    Ok(true)
}

fn validate_target_for_write(
    target: &Path,
    policy: RuntimeStatePolicy,
    replace: bool,
    session_id: SessionId,
) -> Result<(), SysboostError> {
    match fs::symlink_metadata(target) {
        Ok(_) if !replace => Err(SysboostError::new(
            ErrorCode::InvariantViolation,
            "session ID is already present in the durable state root",
        )
        .with_session(session_id)),
        Ok(_) => validate_regular_path(target, policy, "session state replacement target")
            .map(|_| ())
            .map_err(|error| error.with_session(session_id)),
        Err(error) if error.kind() == io::ErrorKind::NotFound && replace => {
            Err(SysboostError::new(
                ErrorCode::DurabilityError,
                "session state replacement target is missing",
            )
            .with_session(session_id))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(ErrorCode::DurabilityError, error).with_session(session_id)),
    }
}

fn sync_directory(path: &Path, policy: RuntimeStatePolicy) -> Result<(), io::Error> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(open_cloexec_flags() | open_nofollow_flags() | open_directory_flags());
    let file = options.open(path)?;
    validate_directory_metadata(
        &file
            .metadata()
            .map_err(|_| io::Error::from(io::ErrorKind::Other))?,
        policy,
        "runtime state root",
    )
    .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
    file.sync_all()
}

fn reclaim_stale_lock(path: &Path, policy: RuntimeStatePolicy) -> Result<bool, SysboostError> {
    let identity = validate_regular_path(path, policy, "lock file")?;
    let contents = read_verified_file(path, policy, 256)?;
    let owner = parse_lock_owner(&contents)?;
    let is_stale = match probe_process(owner.pid)? {
        Some(current) => !current.same_generation(owner),
        None => true,
    };
    if !is_stale {
        return Ok(false);
    }
    let removed = remove_file_if_identity(path, identity)
        .map_err(|error| io_error(ErrorCode::DurabilityError, error))?;
    if !removed {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        // The caller already validated the state root.  A directory sync
        // makes stale-lock reclamation durable before retrying.
        let _ = File::open(parent).and_then(|file| file.sync_all());
    }
    Ok(true)
}

fn encode_lock_owner(identity: ProcessIdentity) -> Vec<u8> {
    format!(
        "version=1\npid={}\nstart={}\nboot={}\n",
        identity.pid,
        identity.generation,
        encode_hex(&identity.boot_id),
    )
    .into_bytes()
}

fn parse_lock_owner(bytes: &[u8]) -> Result<ProcessIdentity, SysboostError> {
    let value = std::str::from_utf8(bytes).map_err(|_| {
        SysboostError::new(ErrorCode::JournalCorrupt, "lock metadata is not valid text")
    })?;
    let lines = value.lines().collect::<Vec<_>>();
    if lines.len() != 4 || lines[0] != "version=1" {
        return Err(SysboostError::new(
            ErrorCode::JournalCorrupt,
            "lock metadata format is unsupported",
        ));
    }
    let pid = parse_lock_field(lines[1], "pid")?
        .parse::<u32>()
        .map_err(|_| {
            SysboostError::new(ErrorCode::JournalCorrupt, "lock PID metadata is invalid")
        })?;
    let generation = parse_lock_field(lines[2], "start")?
        .parse::<u64>()
        .map_err(|_| {
            SysboostError::new(ErrorCode::JournalCorrupt, "lock start metadata is invalid")
        })?;
    let boot = parse_lock_field(lines[3], "boot")?;
    let boot_id = decode_hex_16(boot).ok_or_else(|| {
        SysboostError::new(ErrorCode::JournalCorrupt, "lock boot metadata is invalid")
    })?;
    ProcessIdentity::with_boot_id(pid, generation, boot_id).map_err(|_| {
        SysboostError::new(
            ErrorCode::JournalCorrupt,
            "lock metadata contains a weak process identity",
        )
    })
}

fn parse_lock_field<'a>(line: &'a str, name: &str) -> Result<&'a str, SysboostError> {
    let prefix = format!("{name}=");
    line.strip_prefix(&prefix)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            SysboostError::new(ErrorCode::JournalCorrupt, "lock metadata field is invalid")
        })
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex_16(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut output = [0_u8; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        let high = hex_value(value.as_bytes()[index * 2])?;
        let low = hex_value(value.as_bytes()[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Some(output)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn current_process_credentials() -> Option<(u32, u32)> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:")?.split_whitespace().next())?
        .parse()
        .ok()?;
    let gid = status
        .lines()
        .find_map(|line| line.strip_prefix("Gid:")?.split_whitespace().next())?
        .parse()
        .ok()?;
    Some((uid, gid))
}

#[cfg(not(target_os = "linux"))]
fn current_process_credentials() -> Option<(u32, u32)> {
    Some((0, 0))
}

#[cfg(target_os = "linux")]
const fn open_nofollow_flags() -> i32 {
    0x20000
}

#[cfg(not(target_os = "linux"))]
const fn open_nofollow_flags() -> i32 {
    0
}

#[cfg(target_os = "linux")]
const fn open_directory_flags() -> i32 {
    0x10000
}

#[cfg(not(target_os = "linux"))]
const fn open_directory_flags() -> i32 {
    0
}

#[cfg(target_os = "linux")]
const fn open_cloexec_flags() -> i32 {
    0x80000
}

#[cfg(not(target_os = "linux"))]
const fn open_cloexec_flags() -> i32 {
    0
}

fn io_error(code: ErrorCode, error: io::Error) -> SysboostError {
    let message = match error.kind() {
        io::ErrorKind::PermissionDenied => "state I/O permission was denied",
        io::ErrorKind::NotFound => "state I/O target was not found",
        io::ErrorKind::AlreadyExists => "state I/O target already exists",
        _ => "state I/O operation failed",
    };
    SysboostError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use sysboost_core::{
        CapabilityId, EqualityKind, MutationId, MutationKind, Plan, PlanId, PlannedMutation,
        StateFingerprint, TargetId, Timestamp,
    };

    fn record() -> SessionRecord {
        let kind = MutationKind::CpuGovernor {
            policy: sysboost_core::CpuPolicyId::new(0),
            governor: sysboost_core::GovernorId::new("performance").expect("valid governor"),
        };
        let mutation = PlannedMutation::new(
            MutationId::new(1),
            CapabilityId::new("cpu.policy.governor").expect("valid capability"),
            TargetId::new("cpu.policy.0").expect("valid target"),
            kind.clone(),
            kind.typed_value(),
            StateFingerprint::from_bytes([1; 32]),
            EqualityKind::ScalarExact,
            Vec::new(),
        )
        .expect("valid mutation");
        let plan = Plan::new(
            PlanId::from_bytes([1; 16]),
            [2; 32],
            [3; 32],
            [4; 32],
            vec![mutation.clone()],
        )
        .expect("valid plan");
        SessionRecord::new(
            sysboost_core::Session::new(
                SessionId::from_bytes([5; 16]),
                &plan,
                Timestamp::from_unix_millis(6),
            ),
            vec![mutation],
        )
        .expect("valid record")
    }

    #[test]
    fn file_store_replaces_atomically_and_loads_unfinished() {
        let root = std::env::temp_dir().join(format!("sysboost-state-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut store = FileStateStore::new(&root);
        let record = record();
        store.create(&record).expect("create state");
        assert_eq!(store.load_unfinished().expect("load state").len(), 1);
        let mut replaced = record.clone();
        for state in [
            sysboost_core::SessionState::Detected,
            sysboost_core::SessionState::Planned,
            sysboost_core::SessionState::Snapshotted,
            sysboost_core::SessionState::IntentDurable,
            sysboost_core::SessionState::Applying,
            sysboost_core::SessionState::Active,
            sysboost_core::SessionState::Restoring,
            sysboost_core::SessionState::Restored,
        ] {
            replaced
                .transition(state, Timestamp::from_unix_millis(7), "fixture restore")
                .expect("valid fixture transition");
        }
        store.replace(&replaced).expect("replace state");
        assert!(store.load_unfinished().expect("load state").is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn lock_contention_is_explicit() {
        let root = std::env::temp_dir().join(format!("sysboost-lock-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut first = FileSessionLock::new(&root);
        let _guard = first.acquire().expect("first lock");
        let mut second = FileSessionLock::new(&root);
        let error = second.acquire().expect_err("second lock must contend");
        assert_eq!(error.code, ErrorCode::AuthorizationError);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_lock_from_a_dead_owner_is_reclaimed_for_crash_recovery() {
        let root =
            std::env::temp_dir().join(format!("sysboost-stale-lock-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create lock fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        fs::write(
            root.join(".mutating.lock"),
            encode_lock_owner(ProcessIdentity::fixture(4294967295, 1, [1; 16])),
        )
        .expect("seed stale lock");
        fs::set_permissions(
            root.join(".mutating.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("lock mode");
        let mut lock = FileSessionLock::new(&root);
        let _guard = lock.acquire().expect("dead owner lock is reclaimed");
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn runtime_root_symlink_is_rejected_without_following_it() {
        use std::os::unix::fs::symlink;

        let suffix = format!("{}-root-symlink", std::process::id());
        let root = std::env::temp_dir().join(format!("sysboost-state-{suffix}"));
        let outside = std::env::temp_dir().join(format!("sysboost-state-outside-{suffix}"));
        let _ = fs::remove_file(&root);
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&outside).expect("outside directory");
        symlink(&outside, &root).expect("root symlink");
        let store = FileStateStore::new(&root);
        let error = store
            .load_unfinished()
            .expect_err("symlinked runtime root is not trusted");
        assert_eq!(error.code, ErrorCode::JournalCorrupt);
        let _ = fs::remove_file(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn state_symlink_unexpected_type_and_wrong_mode_are_rejected() {
        use std::os::unix::fs::symlink;

        let suffix = format!("{}-objects", std::process::id());
        let root = std::env::temp_dir().join(format!("sysboost-state-{suffix}"));
        let outside = std::env::temp_dir().join(format!("sysboost-state-file-{suffix}"));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&outside);
        fs::create_dir(&root).expect("state root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        fs::write(&outside, b"not a state record").expect("outside file");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).expect("file mode");
        let session_id = SessionId::from_bytes([0x61; 16]);
        symlink(&outside, root.join(format!("{session_id}.state"))).expect("state symlink");
        let store = FileStateStore::new(&root);
        assert_eq!(
            store
                .load_unfinished()
                .expect_err("state symlink is rejected")
                .code,
            ErrorCode::JournalCorrupt
        );
        fs::remove_file(root.join(format!("{session_id}.state"))).expect("remove symlink");
        fs::create_dir(root.join(format!("{session_id}.state"))).expect("unexpected directory");
        assert_eq!(
            store
                .load_unfinished()
                .expect_err("state directory is rejected")
                .code,
            ErrorCode::JournalCorrupt
        );
        fs::remove_dir(root.join(format!("{session_id}.state"))).expect("remove directory");
        fs::write(root.join("unexpected-object"), b"unexpected").expect("unexpected object");
        fs::set_permissions(
            root.join("unexpected-object"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("unexpected object mode");
        assert_eq!(
            store
                .load_unfinished()
                .expect_err("unexpected runtime object is rejected")
                .code,
            ErrorCode::JournalCorrupt
        );
        fs::remove_file(root.join("unexpected-object")).expect("remove unexpected object");

        let record = record();
        let mut store = FileStateStore::new(&root);
        store.create(&record).expect("create state");
        fs::set_permissions(
            root.join(format!("{}.state", record.session.header.session_id)),
            fs::Permissions::from_mode(0o640),
        )
        .expect("weaken state mode");
        assert_eq!(
            store
                .load(record.session.header.session_id)
                .expect_err("wrong state mode is rejected")
                .code,
            ErrorCode::JournalCorrupt
        );
        let _ = fs::remove_file(&outside);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn state_hardlinks_are_rejected_as_unexpected_runtime_objects() {
        let root =
            std::env::temp_dir().join(format!("sysboost-state-hardlink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut store = FileStateStore::new(&root);
        let record = record();
        store.create(&record).expect("create state");
        let alias = root.join(format!("{}.state", SessionId::from_bytes([0x62; 16])));
        fs::hard_link(
            root.join(format!("{}.state", record.session.header.session_id)),
            &alias,
        )
        .expect("create hardlink fixture");
        assert_eq!(
            store
                .load_unfinished()
                .expect_err("hardlinked state is rejected")
                .code,
            ErrorCode::JournalCorrupt
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn unexpected_runtime_state_owner_is_rejected() {
        let root =
            std::env::temp_dir().join(format!("sysboost-state-owner-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut store = FileStateStore::new(&root);
        store.create(&record()).expect("create state");
        let mut wrong = RuntimeStatePolicy::current_process();
        wrong.owner_uid = wrong.owner_uid.wrapping_add(1);
        let wrong_owner = FileStateStore::with_policy(&root, wrong);
        assert_eq!(
            wrong_owner
                .load_unfinished()
                .expect_err("unexpected state owner is rejected")
                .code,
            ErrorCode::AuthorizationError
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn live_lock_is_not_stolen_and_pid_reuse_is_reclaimed() {
        use std::os::unix::fs::symlink;

        let root =
            std::env::temp_dir().join(format!("sysboost-lock-identity-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut first = FileSessionLock::new(&root);
        let guard = first.acquire().expect("first lock");
        let mut second = FileSessionLock::new(&root);
        assert_eq!(
            second
                .acquire()
                .expect_err("live lock cannot be stolen")
                .code,
            ErrorCode::AuthorizationError
        );
        drop(guard);

        let current = CurrentProcess.current().expect("current process identity");
        fs::write(
            root.join(".mutating.lock"),
            encode_lock_owner(
                ProcessIdentity::with_boot_id(
                    current.pid,
                    current.generation.saturating_add(1),
                    current.boot_id,
                )
                .expect("reused PID fixture identity"),
            ),
        )
        .expect("seed PID reuse lock");
        fs::set_permissions(
            root.join(".mutating.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("lock mode");
        let _reclaimed = second.acquire().expect("PID reuse is stale");

        let outside = root.with_extension("outside");
        fs::write(&outside, b"outside").expect("outside file");
        let _ = fs::remove_file(root.join(".mutating.lock"));
        symlink(&outside, root.join(".mutating.lock")).expect("lock symlink");
        let error = FileSessionLock::new(&root)
            .acquire()
            .expect_err("lock symlink is not reclaimable");
        assert_eq!(error.code, ErrorCode::JournalCorrupt);
        let _ = fs::remove_file(root.join(".mutating.lock"));
        let _ = fs::remove_file(outside);
        let _ = fs::remove_dir_all(&root);
    }
}
