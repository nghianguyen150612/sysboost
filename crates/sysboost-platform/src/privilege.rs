//! Narrow controller-to-helper privilege boundary.
//!
//! The first privileged implementation is deliberately an authenticated,
//! in-process helper service.  It is the same admission boundary that a Unix
//! socket composition root can call: peer identity is supplied by the
//! transport adapter, plans are looked up by identity/digest, operation and
//! target ownership are delegated to compiled-in backends, and all mutation
//! authority remains inside [`TransactionEngine`].  No socket endpoint is
//! opened by this module, so there is no unauthenticated production listener
//! to accidentally expose.

use std::collections::BTreeMap;

use sysboost_core::{
    ErrorCode, Plan, PlanAction, PlanId, SessionId, SessionState, Stage, SysboostError,
};
use sysboost_protocol::{Request, RequestId, Response, WireCodec};

use crate::backend::MutationBackend;
use crate::clock::Clock;
use crate::process::ProcessIdentity;
use crate::state::{ExclusiveSessionLock, SessionIdSource, SessionStateStore};
use crate::transaction::TransactionEngine;

/// Opaque handle returned by a trusted helper after snapshot and durable-intent
/// preparation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionHandle {
    /// Helper-owned session identity.
    pub session_id: SessionId,
    /// Plan identity bound to the session.
    pub plan_id: PlanId,
    /// Digest of the complete approved plan.
    pub plan_digest: [u8; 32],
    /// Authenticated owner identity bound to the session.
    pub owner: ProcessIdentity,
}

/// Typed privilege broker. No method accepts a path, command, or raw value.
pub trait PrivilegeBroker {
    /// Ask the helper to revalidate a plan, snapshot it, and durably persist
    /// intent before returning a handle.
    fn prepare(&mut self, plan: &Plan) -> Result<SessionHandle, SysboostError>;

    /// Ask the helper to apply the prepared session.
    fn apply(&mut self, session: SessionHandle) -> Result<SessionState, SysboostError>;

    /// Ask the helper to restore the prepared session.
    fn restore(&mut self, session: SessionHandle) -> Result<SessionState, SysboostError>;

    /// Read helper-owned session state.
    fn status(&self, session: SessionHandle) -> Result<SessionState, SysboostError>;
}

/// Controller-side plan catalog exposed to the helper only through typed
/// plan identity lookup.  There is no method to register a path or a raw
/// privileged write.
#[derive(Clone, Debug, Default)]
pub struct ApprovedPlanCatalog {
    plans: BTreeMap<PlanId, Plan>,
}

impl ApprovedPlanCatalog {
    /// Construct an empty catalog.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one complete planner result.
    ///
    /// Registration is idempotent for the exact same plan.  Reusing a plan ID
    /// for different content is rejected, even if a caller supplies the same
    /// untrusted digest, so the helper never silently changes plan meaning.
    pub fn register(&mut self, plan: Plan) -> Result<(), SysboostError> {
        plan.validate_complete()?;
        match self.plans.get(&plan.id) {
            Some(existing) if existing == &plan => Ok(()),
            Some(_) => Err(boundary_error(
                ErrorCode::AuthorizationError,
                "plan identity is already bound to different content",
            )),
            None => {
                self.plans.insert(plan.id, plan);
                Ok(())
            }
        }
    }

    /// Return a plan only when its typed identity and digest match.
    pub fn get(&self, plan_id: PlanId, plan_digest: [u8; 32]) -> Option<&Plan> {
        self.plans
            .get(&plan_id)
            .filter(|plan| plan.plan_digest == plan_digest)
    }
}

#[derive(Clone, Copy, Debug)]
struct SessionBinding {
    handle: SessionHandle,
}

/// Authenticated helper-side service backed by the Prompt 5 transaction
/// engine.
pub struct PrivilegeService<B, S, L, G, C>
where
    B: MutationBackend,
    S: SessionStateStore,
    L: ExclusiveSessionLock,
    G: SessionIdSource,
    C: Clock,
{
    engine: TransactionEngine<B, S, L, G, C>,
    expected_peer: ProcessIdentity,
    catalog: ApprovedPlanCatalog,
    sessions: BTreeMap<SessionId, SessionBinding>,
    last_request: BTreeMap<ProcessIdentity, u64>,
}

impl<B, S, L, G, C> PrivilegeService<B, S, L, G, C>
where
    B: MutationBackend,
    S: SessionStateStore,
    L: ExclusiveSessionLock,
    G: SessionIdSource,
    C: Clock,
{
    /// Construct a helper and recover all unfinished durable sessions before
    /// accepting a new request.  An unresolved crash boundary prevents the
    /// service from being constructed as an accepting helper.
    pub fn new(
        mut engine: TransactionEngine<B, S, L, G, C>,
        expected_peer: ProcessIdentity,
    ) -> Result<Self, SysboostError> {
        if expected_peer.generation == 0 || expected_peer.boot_id == [0; 16] {
            return Err(boundary_error(
                ErrorCode::AuthorizationError,
                "helper peer policy requires a strong process identity",
            ));
        }
        engine.recover_unfinished().map_err(|error| {
            error
                .with_stage(Stage::Recovery)
                .retryable(sysboost_core::Retryability::AfterRecovery)
        })?;
        Ok(Self {
            engine,
            expected_peer,
            catalog: ApprovedPlanCatalog::new(),
            sessions: BTreeMap::new(),
            last_request: BTreeMap::new(),
        })
    }

    /// Register a plan supplied by the pure planner.  This is a composition
    /// root operation; wire callers can only request a plan already present in
    /// the catalog by ID and digest.
    pub fn register_plan(&mut self, plan: Plan) -> Result<(), SysboostError> {
        self.catalog.register(plan)
    }

    /// Process one complete protocol frame from an authenticated local peer.
    ///
    /// `None` represents a transport that failed to obtain peer credentials;
    /// it is rejected before any request can reach plan/session dispatch.
    /// This module intentionally does not derive credentials from user-supplied
    /// frame bytes.
    pub fn handle_frame(
        &mut self,
        peer: Option<ProcessIdentity>,
        frame: &[u8],
    ) -> Result<Vec<u8>, SysboostError> {
        let request = Request::decode(frame)?;
        let request_id = request.request_id();
        let peer = peer.ok_or_else(|| {
            boundary_error(
                ErrorCode::AuthorizationError,
                "authenticated local peer credentials are required",
            )
        })?;
        self.authenticate_peer(peer)?;
        self.accept_request_id(peer, request_id)?;
        let response = match self.dispatch(peer, request) {
            Ok(response) => response,
            Err(error) => Response::Rejected {
                request_id,
                code: error.code,
            },
        };
        response.encode()
    }

    /// Prepare a plan on behalf of an explicitly identified peer.
    pub fn prepare_for_peer(
        &mut self,
        peer: ProcessIdentity,
        plan: &Plan,
    ) -> Result<SessionHandle, SysboostError> {
        self.authenticate_peer(peer)?;
        self.register_plan(plan.clone())?;
        self.prepare_by_identity(peer, plan.id, plan.plan_digest)
    }

    /// Apply a handle on behalf of an explicitly identified peer.
    pub fn apply_for_peer(
        &mut self,
        peer: ProcessIdentity,
        handle: SessionHandle,
    ) -> Result<SessionState, SysboostError> {
        self.authenticate_peer(peer)?;
        self.authorize_session(peer, handle)?;
        self.engine.apply(handle.session_id)
    }

    /// Restore a handle on behalf of an explicitly identified peer.
    pub fn restore_for_peer(
        &mut self,
        peer: ProcessIdentity,
        handle: SessionHandle,
    ) -> Result<SessionState, SysboostError> {
        self.authenticate_peer(peer)?;
        self.authorize_session(peer, handle)?;
        self.engine.restore(handle.session_id)
    }

    /// Read a handle's state without creating mutation authority.
    pub fn status_for_peer(
        &self,
        peer: ProcessIdentity,
        handle: SessionHandle,
    ) -> Result<SessionState, SysboostError> {
        self.authenticate_peer(peer)?;
        self.authorize_session_ref(peer, handle)?;
        Ok(self.engine.status(handle.session_id)?.state)
    }

    fn dispatch(
        &mut self,
        peer: ProcessIdentity,
        request: Request,
    ) -> Result<Response, SysboostError> {
        match request {
            Request::Prepare {
                request_id,
                plan_id,
                plan_digest,
            } => {
                let handle = self.prepare_by_identity(peer, plan_id, plan_digest)?;
                Ok(Response::Accepted {
                    request_id,
                    session_id: handle.session_id,
                })
            }
            Request::Apply {
                request_id,
                session_id,
            } => {
                let handle = self.lookup_session(peer, session_id)?;
                let state = self.engine.apply(handle.session_id)?;
                Ok(Response::Status {
                    request_id,
                    session_id,
                    state,
                })
            }
            Request::Restore {
                request_id,
                session_id,
            } => {
                let handle = self.lookup_session(peer, session_id)?;
                let state = self.engine.restore(handle.session_id)?;
                Ok(Response::Status {
                    request_id,
                    session_id,
                    state,
                })
            }
            Request::Status {
                request_id,
                session_id,
            } => {
                let handle = self.lookup_session(peer, session_id)?;
                let state = self.engine.status(handle.session_id)?.state;
                Ok(Response::Status {
                    request_id,
                    session_id,
                    state,
                })
            }
        }
    }

    fn prepare_by_identity(
        &mut self,
        peer: ProcessIdentity,
        plan_id: PlanId,
        plan_digest: [u8; 32],
    ) -> Result<SessionHandle, SysboostError> {
        let plan = self
            .catalog
            .get(plan_id, plan_digest)
            .cloned()
            .ok_or_else(|| {
                boundary_error(
                    ErrorCode::AuthorizationError,
                    "requested plan identity or digest is not approved",
                )
            })?;
        self.validate_plan_admission(&plan)?;
        let session_id = self.engine.prepare(&plan)?;
        if let Err(error) = self.validate_snapshot_identities(session_id, &plan) {
            self.engine.abort_prepared(session_id)?;
            return Err(error);
        }
        let handle = SessionHandle {
            session_id,
            plan_id,
            plan_digest,
            owner: peer,
        };
        self.sessions.insert(session_id, SessionBinding { handle });
        Ok(handle)
    }

    fn validate_plan_admission(&self, plan: &Plan) -> Result<(), SysboostError> {
        plan.validate_complete()?;
        if plan.mutations.is_empty() {
            return Err(boundary_error(
                ErrorCode::AuthorizationError,
                "report-only or empty plans cannot enter the privileged executor",
            ));
        }
        for mutation in &plan.mutations {
            let item =
                plan.items
                    .iter()
                    .find(|item| {
                        item.action == PlanAction::Mutation
                            && item.mutation.as_ref().is_some_and(|candidate| {
                                candidate.mutation_id == mutation.mutation_id
                            })
                    })
                    .ok_or_else(|| {
                        boundary_error(
                            ErrorCode::PlanningError,
                            "executable mutation is absent from the approved plan items",
                        )
                    })?;
            let backend_owned = item
                .backend
                .as_ref()
                .is_some_and(|backend| self.engine.backend().owns_backend(backend));
            if !backend_owned {
                return Err(boundary_error(
                    ErrorCode::AuthorizationError,
                    "operation/backend ownership does not match the approved plan",
                ));
            }
            let target_identity = item.target_identity.ok_or_else(|| {
                boundary_error(
                    ErrorCode::TargetError,
                    "approved mutation has no stable target identity",
                )
            })?;
            self.engine
                .backend()
                .validate_admission(mutation, target_identity)?;
        }
        Ok(())
    }

    fn validate_snapshot_identities(
        &self,
        session_id: SessionId,
        plan: &Plan,
    ) -> Result<(), SysboostError> {
        let record = self.engine.state_store().load(session_id)?;
        for operation in &record.operations {
            let expected = plan
                .items
                .iter()
                .find(|item| {
                    item.action == PlanAction::Mutation
                        && item.mutation.as_ref().is_some_and(|mutation| {
                            mutation.mutation_id == operation.mutation.mutation_id
                        })
                })
                .and_then(|item| item.target_identity);
            let snapshot = operation.snapshot.as_ref().ok_or_else(|| {
                boundary_error(
                    ErrorCode::SnapshotError,
                    "durable intent operation has no complete snapshot",
                )
            })?;
            if expected != Some(snapshot.target_identity) {
                return Err(boundary_error(
                    ErrorCode::TargetError,
                    "snapshot target identity does not match the approved target",
                ));
            }
        }
        Ok(())
    }

    fn authenticate_peer(&self, peer: ProcessIdentity) -> Result<(), SysboostError> {
        if peer.same_generation(self.expected_peer) {
            Ok(())
        } else {
            Err(boundary_error(
                ErrorCode::AuthorizationError,
                "local peer identity is not authorized for this helper session",
            ))
        }
    }

    fn accept_request_id(
        &mut self,
        peer: ProcessIdentity,
        request_id: RequestId,
    ) -> Result<(), SysboostError> {
        if self
            .last_request
            .get(&peer)
            .is_some_and(|last| request_id.get() <= *last)
        {
            return Err(boundary_error(
                ErrorCode::TransportError,
                "duplicate or replayed request ID",
            ));
        }
        self.last_request.insert(peer, request_id.get());
        Ok(())
    }

    fn lookup_session(
        &self,
        peer: ProcessIdentity,
        session_id: SessionId,
    ) -> Result<SessionHandle, SysboostError> {
        let binding = self.sessions.get(&session_id).ok_or_else(|| {
            boundary_error(
                ErrorCode::AuthorizationError,
                "session is not known to this helper lifecycle",
            )
        })?;
        self.authorize_session_ref(peer, binding.handle)?;
        Ok(binding.handle)
    }

    fn authorize_session(
        &self,
        peer: ProcessIdentity,
        handle: SessionHandle,
    ) -> Result<(), SysboostError> {
        self.authorize_session_ref(peer, handle)
    }

    fn authorize_session_ref(
        &self,
        peer: ProcessIdentity,
        handle: SessionHandle,
    ) -> Result<(), SysboostError> {
        let known = self.sessions.get(&handle.session_id).ok_or_else(|| {
            boundary_error(
                ErrorCode::AuthorizationError,
                "session handle is not known to this helper lifecycle",
            )
        })?;
        if known.handle != handle
            || !peer.same_generation(handle.owner)
            || handle.owner != known.handle.owner
        {
            return Err(boundary_error(
                ErrorCode::AuthorizationError,
                "session handle identity, owner, or plan binding is invalid",
            ));
        }
        Ok(())
    }
}

impl<B, S, L, G, C> PrivilegeBroker for PrivilegeService<B, S, L, G, C>
where
    B: MutationBackend,
    S: SessionStateStore,
    L: ExclusiveSessionLock,
    G: SessionIdSource,
    C: Clock,
{
    fn prepare(&mut self, plan: &Plan) -> Result<SessionHandle, SysboostError> {
        let peer = self.expected_peer;
        self.prepare_for_peer(peer, plan)
    }

    fn apply(&mut self, session: SessionHandle) -> Result<SessionState, SysboostError> {
        self.apply_for_peer(self.expected_peer, session)
    }

    fn restore(&mut self, session: SessionHandle) -> Result<SessionState, SysboostError> {
        self.restore_for_peer(self.expected_peer, session)
    }

    fn status(&self, session: SessionHandle) -> Result<SessionState, SysboostError> {
        self.status_for_peer(self.expected_peer, session)
    }
}

fn boundary_error(code: ErrorCode, message: &str) -> SysboostError {
    SysboostError::new(code, message).with_stage(Stage::Transport)
}
