#![forbid(unsafe_code)]

//! Root-owned service bootstrap. The service does not open a socket or mutate
//! Linux state until the protocol, journal, and reviewed backend work exists.

use sysboost_core::{LogEvent, LogLevel, LogSink, Timestamp};
use sysboost_platform::{Clock, JsonLogger, SystemClock};

fn main() {
    let clock = SystemClock;
    let timestamp = clock
        .now()
        .unwrap_or_else(|_| Timestamp::from_unix_millis(0));
    let mut logger = JsonLogger::stderr();
    logger.emit(LogEvent::new(
        timestamp,
        LogLevel::Info,
        "sysboost-privd",
        "bootstrap",
        "report_only",
    ));
}
