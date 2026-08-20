#![forbid(unsafe_code)]

//! Unprivileged controller bootstrap. Runtime planning/RPC is deferred.

use sysboost_core::{LogEvent, LogLevel, LogSink, Timestamp};
use sysboost_platform::{Clock, CurrentProcess, JsonLogger, ProcessIdentityProvider, SystemClock};

fn main() {
    let clock = SystemClock;
    let timestamp = clock
        .now()
        .unwrap_or_else(|_| Timestamp::from_unix_millis(0));
    let process = CurrentProcess
        .current()
        .map(|identity| identity.pid.to_string())
        .unwrap_or_else(|_| "unknown".to_owned());
    let mut logger = JsonLogger::stderr();
    logger.emit(
        LogEvent::new(
            timestamp,
            LogLevel::Info,
            "sysboost-controller",
            "bootstrap",
            "report_only",
        )
        .with_field(sysboost_core::LogField::text("process_id", process))
        .with_field(sysboost_core::LogField::text(
            "mutation_status",
            "not_implemented",
        )),
    );
}
