//! Structured logging data and a deterministic in-memory sink.

use crate::ids::{BackendId, CapabilityId, MutationId, SessionId, TargetId};
use crate::time::Timestamp;

/// Structured log severity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LogLevel {
    /// Diagnostic event.
    Trace,
    /// Normal operation event.
    Info,
    /// Unexpected but recoverable condition.
    Warn,
    /// Operation or safety failure.
    Error,
}

/// JSON-compatible primitive log value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogValue {
    /// Text value.
    Text(String),
    /// Unsigned number.
    Unsigned(u64),
    /// Boolean value.
    Bool(bool),
}

/// One stable key/value field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogField {
    /// Field key.
    pub key: String,
    /// Field value.
    pub value: LogValue,
}

impl LogField {
    /// Construct a text field.
    pub fn text(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: LogValue::Text(value.into()),
        }
    }

    /// Construct an unsigned field.
    pub fn unsigned(key: impl Into<String>, value: u64) -> Self {
        Self {
            key: key.into(),
            value: LogValue::Unsigned(value),
        }
    }
}

/// Structured operation event. Raw preimage bytes are intentionally absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogEvent {
    /// Event time.
    pub timestamp: Timestamp,
    /// Severity.
    pub level: LogLevel,
    /// Component name.
    pub component: String,
    /// Session context.
    pub session_id: Option<SessionId>,
    /// Mutation context.
    pub mutation_id: Option<MutationId>,
    /// Backend context.
    pub backend_id: Option<BackendId>,
    /// Capability context.
    pub capability_id: Option<CapabilityId>,
    /// Target context.
    pub target_id: Option<TargetId>,
    /// Lifecycle stage/event name.
    pub event: String,
    /// Operation outcome.
    pub outcome: String,
    /// Stable fields.
    pub fields: Vec<LogField>,
}

impl LogEvent {
    /// Create a minimal event.
    pub fn new(
        timestamp: Timestamp,
        level: LogLevel,
        component: impl Into<String>,
        event: impl Into<String>,
        outcome: impl Into<String>,
    ) -> Self {
        Self {
            timestamp,
            level,
            component: component.into(),
            session_id: None,
            mutation_id: None,
            backend_id: None,
            capability_id: None,
            target_id: None,
            event: event.into(),
            outcome: outcome.into(),
            fields: Vec::new(),
        }
    }

    /// Add a structured field.
    pub fn with_field(mut self, field: LogField) -> Self {
        self.fields.push(field);
        self
    }
}

/// Sink abstraction used by controller/helper composition roots.
pub trait LogSink {
    /// Emit one structured event.
    fn emit(&mut self, event: LogEvent);
}

/// Deterministic sink useful in unit tests.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MemoryLogSink {
    /// Captured events.
    pub events: Vec<LogEvent>,
}

impl LogSink for MemoryLogSink {
    fn emit(&mut self, event: LogEvent) {
        self.events.push(event);
    }
}
