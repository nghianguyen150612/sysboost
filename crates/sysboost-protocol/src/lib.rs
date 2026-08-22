#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Versioned, length-bounded controller/helper message types.
//!
//! The foundation codec carries a plan identity and digest, never a raw path,
//! command, or untyped privileged value. Full typed-plan transport can be
//! added only by extending these closed messages and their tests.

use sysboost_core::{ErrorCode, PlanId, SessionId, SessionState, SysboostError};

/// First protocol version.
pub const PROTOCOL_VERSION: u16 = 1;
/// Maximum encoded frame size accepted by the boundary.
pub const MAX_FRAME_BYTES: usize = 65_536;
const MAGIC: [u8; 4] = *b"SBP1";

/// Monotonic request ID selected by the controller.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestId(u64);

impl RequestId {
    /// Construct a non-zero request ID.
    pub fn new(value: u64) -> Result<Self, SysboostError> {
        if value == 0 {
            Err(SysboostError::new(
                ErrorCode::InvalidInput,
                "request ID must be non-zero",
            ))
        } else {
            Ok(Self(value))
        }
    }

    /// Return the numeric request ID.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Typed controller-to-helper request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    /// Bind a typed plan identity/digest to a new helper session.
    Prepare {
        /// Request correlation ID.
        request_id: RequestId,
        /// Typed plan identity.
        plan_id: PlanId,
        /// Digest of the complete plan/evidence.
        plan_digest: [u8; 32],
    },
    /// Request the helper to apply the already prepared session.
    Apply {
        /// Request correlation ID.
        request_id: RequestId,
        /// Session identity.
        session_id: SessionId,
    },
    /// Request normal compare-and-restore.
    Restore {
        /// Request correlation ID.
        request_id: RequestId,
        /// Session identity.
        session_id: SessionId,
    },
    /// Read helper-owned status.
    Status {
        /// Request correlation ID.
        request_id: RequestId,
        /// Session identity.
        session_id: SessionId,
    },
}

impl Request {
    /// Return the correlation ID without inspecting the request payload.
    pub const fn request_id(&self) -> RequestId {
        match self {
            Self::Prepare { request_id, .. }
            | Self::Apply { request_id, .. }
            | Self::Restore { request_id, .. }
            | Self::Status { request_id, .. } => *request_id,
        }
    }
}

/// Typed helper-to-controller response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Response {
    /// Session prepared; snapshot/durable-intent ownership remains in helper.
    Accepted {
        /// Request correlation ID.
        request_id: RequestId,
        /// New session identity.
        session_id: SessionId,
    },
    /// Current session state.
    Status {
        /// Request correlation ID.
        request_id: RequestId,
        /// Session identity.
        session_id: SessionId,
        /// Helper-owned state.
        state: SessionState,
    },
    /// Structured rejection without raw path/command details.
    Rejected {
        /// Request correlation ID.
        request_id: RequestId,
        /// Stable core error category.
        code: ErrorCode,
    },
}

/// Explicit wire codec implemented by closed protocol messages.
pub trait WireCodec: Sized {
    /// Encode one bounded frame.
    fn encode(&self) -> Result<Vec<u8>, SysboostError>;

    /// Decode one complete frame.
    fn decode(bytes: &[u8]) -> Result<Self, SysboostError>;
}

impl WireCodec for Request {
    fn encode(&self) -> Result<Vec<u8>, SysboostError> {
        match self {
            Self::Prepare {
                request_id,
                plan_id,
                plan_digest,
            } => {
                let mut payload = Vec::with_capacity(8 + 16 + 32);
                put_u64(&mut payload, request_id.get());
                payload.extend_from_slice(plan_id.as_bytes());
                payload.extend_from_slice(plan_digest);
                frame(1, &payload)
            }
            Self::Apply {
                request_id,
                session_id,
            } => frame(2, &two_ids(*request_id, *session_id)),
            Self::Restore {
                request_id,
                session_id,
            } => frame(3, &two_ids(*request_id, *session_id)),
            Self::Status {
                request_id,
                session_id,
            } => frame(4, &two_ids(*request_id, *session_id)),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, SysboostError> {
        let (tag, payload) = unframe(bytes)?;
        let mut cursor = Cursor::new(payload);
        let request_id = RequestId::new(cursor.u64()?)?;
        let request = match tag {
            1 => {
                let plan_id = PlanId::from_bytes(cursor.array_16()?);
                let plan_digest = cursor.array_32()?;
                Self::Prepare {
                    request_id,
                    plan_id,
                    plan_digest,
                }
            }
            2 => Self::Apply {
                request_id,
                session_id: SessionId::from_bytes(cursor.array_16()?),
            },
            3 => Self::Restore {
                request_id,
                session_id: SessionId::from_bytes(cursor.array_16()?),
            },
            4 => Self::Status {
                request_id,
                session_id: SessionId::from_bytes(cursor.array_16()?),
            },
            _ => return Err(protocol_error("unknown request tag")),
        };
        cursor.finish()?;
        Ok(request)
    }
}

impl WireCodec for Response {
    fn encode(&self) -> Result<Vec<u8>, SysboostError> {
        match self {
            Self::Accepted {
                request_id,
                session_id,
            } => frame(0x81, &two_ids(*request_id, *session_id)),
            Self::Status {
                request_id,
                session_id,
                state,
            } => {
                let mut payload = two_ids(*request_id, *session_id);
                payload.push(state_tag(*state));
                frame(0x82, &payload)
            }
            Self::Rejected { request_id, code } => {
                let mut payload = Vec::with_capacity(10);
                put_u64(&mut payload, request_id.get());
                put_u16(&mut payload, error_tag(*code));
                frame(0x83, &payload)
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, SysboostError> {
        let (tag, payload) = unframe(bytes)?;
        let mut cursor = Cursor::new(payload);
        let request_id = RequestId::new(cursor.u64()?)?;
        let response = match tag {
            0x81 => Self::Accepted {
                request_id,
                session_id: SessionId::from_bytes(cursor.array_16()?),
            },
            0x82 => Self::Status {
                request_id,
                session_id: SessionId::from_bytes(cursor.array_16()?),
                state: state_from_tag(cursor.u8()?)?,
            },
            0x83 => Self::Rejected {
                request_id,
                code: error_from_tag(cursor.u16()?)?,
            },
            _ => return Err(protocol_error("unknown response tag")),
        };
        cursor.finish()?;
        Ok(response)
    }
}

fn frame(tag: u8, payload: &[u8]) -> Result<Vec<u8>, SysboostError> {
    let total = 4 + 2 + 1 + 4 + payload.len();
    if total > MAX_FRAME_BYTES {
        return Err(protocol_error("protocol frame exceeds maximum size"));
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&MAGIC);
    put_u16(&mut bytes, PROTOCOL_VERSION);
    bytes.push(tag);
    put_u32(&mut bytes, payload.len() as u32);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn unframe(bytes: &[u8]) -> Result<(u8, &[u8]), SysboostError> {
    if bytes.len() > MAX_FRAME_BYTES || bytes.len() < 11 {
        return Err(protocol_error("protocol frame length is invalid"));
    }
    if bytes[..4] != MAGIC {
        return Err(protocol_error("protocol magic is invalid"));
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != PROTOCOL_VERSION {
        return Err(protocol_error("protocol version is unsupported"));
    }
    let tag = bytes[6];
    let payload_len = u32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]) as usize;
    if payload_len != bytes.len() - 11 {
        return Err(protocol_error(
            "protocol payload length does not match frame",
        ));
    }
    Ok((tag, &bytes[11..]))
}

fn two_ids(request_id: RequestId, session_id: SessionId) -> Vec<u8> {
    let mut payload = Vec::with_capacity(24);
    put_u64(&mut payload, request_id.get());
    payload.extend_from_slice(session_id.as_bytes());
    payload
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn state_tag(state: SessionState) -> u8 {
    match state {
        SessionState::New => 0,
        SessionState::Detected => 1,
        SessionState::Planned => 2,
        SessionState::Snapshotted => 3,
        SessionState::IntentDurable => 4,
        SessionState::Applying => 5,
        SessionState::Active => 6,
        SessionState::Restoring => 7,
        SessionState::Restored => 8,
        SessionState::RollingBack => 9,
        SessionState::Degraded => 10,
        SessionState::RecoveryPending => 11,
    }
}

fn state_from_tag(tag: u8) -> Result<SessionState, SysboostError> {
    match tag {
        0 => Ok(SessionState::New),
        1 => Ok(SessionState::Detected),
        2 => Ok(SessionState::Planned),
        3 => Ok(SessionState::Snapshotted),
        4 => Ok(SessionState::IntentDurable),
        5 => Ok(SessionState::Applying),
        6 => Ok(SessionState::Active),
        7 => Ok(SessionState::Restoring),
        8 => Ok(SessionState::Restored),
        9 => Ok(SessionState::RollingBack),
        10 => Ok(SessionState::Degraded),
        11 => Ok(SessionState::RecoveryPending),
        _ => Err(protocol_error("unknown session-state tag")),
    }
}

fn error_tag(code: ErrorCode) -> u16 {
    match code {
        ErrorCode::ConfigError => 1,
        ErrorCode::CapabilityError => 2,
        ErrorCode::Unsupported => 3,
        ErrorCode::AuthorizationError => 4,
        ErrorCode::TargetError => 5,
        ErrorCode::PlanningError => 6,
        ErrorCode::SnapshotError => 7,
        ErrorCode::DurabilityError => 8,
        ErrorCode::TransportError => 9,
        ErrorCode::ApplyError => 10,
        ErrorCode::VerificationError => 11,
        ErrorCode::RestoreConflict => 12,
        ErrorCode::RestoreError => 13,
        ErrorCode::JournalCorrupt => 14,
        ErrorCode::InvariantViolation => 15,
        ErrorCode::InvalidInput => 16,
    }
}

fn error_from_tag(tag: u16) -> Result<ErrorCode, SysboostError> {
    match tag {
        1 => Ok(ErrorCode::ConfigError),
        2 => Ok(ErrorCode::CapabilityError),
        3 => Ok(ErrorCode::Unsupported),
        4 => Ok(ErrorCode::AuthorizationError),
        5 => Ok(ErrorCode::TargetError),
        6 => Ok(ErrorCode::PlanningError),
        7 => Ok(ErrorCode::SnapshotError),
        8 => Ok(ErrorCode::DurabilityError),
        9 => Ok(ErrorCode::TransportError),
        10 => Ok(ErrorCode::ApplyError),
        11 => Ok(ErrorCode::VerificationError),
        12 => Ok(ErrorCode::RestoreConflict),
        13 => Ok(ErrorCode::RestoreError),
        14 => Ok(ErrorCode::JournalCorrupt),
        15 => Ok(ErrorCode::InvariantViolation),
        16 => Ok(ErrorCode::InvalidInput),
        _ => Err(protocol_error("unknown error tag")),
    }
}

fn protocol_error(message: &str) -> SysboostError {
    SysboostError::new(ErrorCode::TransportError, message)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SysboostError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| protocol_error("protocol cursor overflow"))?;
        if end > self.bytes.len() {
            return Err(protocol_error("protocol payload is truncated"));
        }
        let result = &self.bytes[self.position..end];
        self.position = end;
        Ok(result)
    }

    fn u8(&mut self) -> Result<u8, SysboostError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SysboostError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u64(&mut self) -> Result<u64, SysboostError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn array_16(&mut self) -> Result<[u8; 16], SysboostError> {
        let bytes = self.take(16)?;
        let mut result = [0_u8; 16];
        result.copy_from_slice(bytes);
        Ok(result)
    }

    fn array_32(&mut self) -> Result<[u8; 32], SysboostError> {
        let bytes = self.take(32)?;
        let mut result = [0_u8; 32];
        result.copy_from_slice(bytes);
        Ok(result)
    }

    fn finish(&self) -> Result<(), SysboostError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(protocol_error("protocol payload contains trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_without_raw_path_fields() {
        let request = Request::Prepare {
            request_id: RequestId::new(7).unwrap(),
            plan_id: PlanId::from_bytes([1; 16]),
            plan_digest: [2; 32],
        };
        let encoded = request.encode().expect("bounded encoding");
        let decoded = Request::decode(&encoded).expect("valid frame");
        assert_eq!(decoded, request);
    }

    #[test]
    fn response_round_trips_session_state() {
        let response = Response::Status {
            request_id: RequestId::new(9).unwrap(),
            session_id: SessionId::from_bytes([3; 16]),
            state: SessionState::Degraded,
        };
        let encoded = response.encode().expect("bounded encoding");
        let decoded = Response::decode(&encoded).expect("valid frame");
        assert_eq!(decoded, response);
    }

    #[test]
    fn malformed_frame_is_rejected() {
        assert!(Request::decode(b"not-a-frame").is_err());
    }

    #[test]
    fn oversized_frame_is_rejected_at_protocol_boundary() {
        let oversized = vec![0_u8; MAX_FRAME_BYTES + 1];
        assert!(Request::decode(&oversized).is_err());
    }

    #[test]
    fn unknown_operation_or_enum_discriminant_is_rejected() {
        let mut unknown_request = vec![b'S', b'B', b'P', b'1', 0, 1, 0xff, 0, 0, 0, 8];
        unknown_request.extend_from_slice(&1_u64.to_be_bytes());
        assert_eq!(
            Request::decode(&unknown_request)
                .expect_err("unknown request operation")
                .code,
            ErrorCode::TransportError
        );

        let mut unknown_state = vec![b'S', b'B', b'P', b'1', 0, 1, 0x82, 0, 0, 0, 25];
        unknown_state.extend_from_slice(&1_u64.to_be_bytes());
        unknown_state.extend_from_slice(&[2; 16]);
        unknown_state.push(0xff);
        assert_eq!(
            Response::decode(&unknown_state)
                .expect_err("unknown session-state enum")
                .code,
            ErrorCode::TransportError
        );
    }
}
