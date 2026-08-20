//! Structured stderr logger used by the binary bootstrap.

use std::io::{self, Write};

use sysboost_core::{LogEvent, LogLevel, LogSink, LogValue};

/// Minimal JSON logger with deterministic field ordering.
pub struct JsonLogger<W: Write> {
    writer: W,
    failed: bool,
}

impl<W: Write> JsonLogger<W> {
    /// Construct a logger around a writer.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            failed: false,
        }
    }

    /// Whether a write failed. Logging failures do not trigger a mutation.
    pub const fn failed(&self) -> bool {
        self.failed
    }
}

impl JsonLogger<io::Stderr> {
    /// Construct the production stderr logger.
    pub fn stderr() -> Self {
        Self::new(io::stderr())
    }
}

impl<W: Write> LogSink for JsonLogger<W> {
    fn emit(&mut self, event: LogEvent) {
        let line = render_json(&event);
        if writeln!(self.writer, "{line}").is_err() {
            self.failed = true;
        }
    }
}

fn render_json(event: &LogEvent) -> String {
    let mut output = String::from("{\"timestamp_ms\":");
    output.push_str(&event.timestamp.as_unix_millis().to_string());
    output.push_str(",\"level\":");
    push_string(&mut output, level_name(event.level));
    output.push_str(",\"component\":");
    push_string(&mut output, &event.component);
    output.push_str(",\"event\":");
    push_string(&mut output, &event.event);
    output.push_str(",\"outcome\":");
    push_string(&mut output, &event.outcome);
    if let Some(session_id) = event.session_id {
        output.push_str(",\"session_id\":");
        push_string(&mut output, &session_id.to_string());
    }
    if let Some(mutation_id) = event.mutation_id {
        output.push_str(",\"mutation_id\":");
        output.push_str(&mutation_id.get().to_string());
    }
    if let Some(backend_id) = &event.backend_id {
        output.push_str(",\"backend_id\":");
        push_string(&mut output, backend_id.as_str());
    }
    if let Some(capability_id) = &event.capability_id {
        output.push_str(",\"capability_id\":");
        push_string(&mut output, capability_id.as_str());
    }
    if let Some(target_id) = &event.target_id {
        output.push_str(",\"target_id\":");
        push_string(&mut output, target_id.as_str());
    }
    for field in &event.fields {
        output.push(',');
        push_string(&mut output, &field.key);
        output.push(':');
        match &field.value {
            LogValue::Text(value) => push_string(&mut output, value),
            LogValue::Unsigned(value) => output.push_str(&value.to_string()),
            LogValue::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        }
    }
    output.push('}');
    output
}

fn level_name(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Trace => "trace",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

fn push_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysboost_core::{LogEvent, Timestamp};

    #[test]
    fn logger_escapes_untrusted_text() {
        let mut bytes = Vec::new();
        let mut logger = JsonLogger::new(&mut bytes);
        logger.emit(LogEvent::new(
            Timestamp::from_unix_millis(1),
            LogLevel::Info,
            "component",
            "event",
            "ok\"\n",
        ));
        let text = String::from_utf8(bytes).expect("UTF-8 log output");
        assert!(text.contains("\\\""));
        assert!(text.contains("\\n"));
    }
}
