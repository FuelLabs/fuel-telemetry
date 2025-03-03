use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use regex::Regex;
use std::{env::var, sync::LazyLock};
use sysinfo::System;
use tracing::{Event, Subscriber};
use tracing_subscriber::{
    fmt::{
        format::{FormatEvent, FormatFields, Writer},
        FmtContext, FormattedFields,
    },
    registry::LookupSpan,
};
use uuid::Uuid;

use crate::Result;

/// A `tracing` `Formatter` to format telemetry to be later consumed into InfluxDB
///
/// This `tracing` `Formatter` adds a few extra fields to the default `tracing` `Formatter`:
///
/// - `triple`: the target triple of the current system
/// - `os`: the name of the operating system
/// - `os_version`: the version of the operating system
/// - `crate`: the name of the crate
/// - `version`: the version of the crate
/// - `file`: the file where the event was generated
///
#[derive(Default)]
pub struct TelemetryFormatter {
    // Caches the system triple used for every event
    triple: String,
    // Caches the operating system name used for every event
    os: String,
    // Caches the operating system version used for every event
    os_version: String,
    // Trace-ID for the telemetry session
    trace_id: String,
}

impl TelemetryFormatter {
    /// Creates a new `TelemetryFormatter`.
    ///
    /// This `tracing` `Formatter` is to be used along with the `tracing` crate,
    /// and is used to set the `Event` format.
    ///
    /// ```rust
    /// use fuel_telemetry::TelemetryFormatter;
    ///
    /// let telemetry_formatter = TelemetryFormatter::new();
    ///
    /// tracing_subscriber::fmt::layer()
    ///     .event_format(telemetry_formatter);
    /// ```
    pub fn new() -> Self {
        // Cache the values we'll use for every event
        Self {
            os: System::name().unwrap_or("unknown".to_string()),
            os_version: System::kernel_version().unwrap_or("unknown".to_string()),
            trace_id: Uuid::new_v4().to_string(),
            triple: format!(
                "{}-{}-{}",
                match std::env::consts::ARCH {
                    arch @ ("aarch64" | "x86_64") => arch,
                    _ => "unknown",
                },
                match std::env::consts::OS {
                    "macos" => "apple",
                    _ => "unknown",
                },
                match std::env::consts::OS {
                    "macos" => "darwin",
                    "linux" => "linux-gnu",
                    _ => "unknown",
                }
            ),
        }
    }
}

impl<S, N> FormatEvent<S, N> for TelemetryFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    /// Formats an `Event`.
    ///
    /// This function formats an `Event` into a `tracing` `Writer` with the following format:
    ///
    /// <timestamp> <level> <triple>:<os>:<os-version> <crate>:<version>:<file> <trace-id> <spans> <fields>
    ///
    /// e.g:
    ///
    /// ```text
    /// 2021-08-31T14:00:00.000000Z ERROR x86_64-apple-darwin:Arch Linux:6.12.3-arch1-1 fuel-telemetry:0.1.0:fuelup/src/main.rs ddfc7485-c40f-4e3f-8203-704cccbd7475 root:span1:span2: field1="val1" "A test message"
    /// ```
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let mut wants_telemetry = false;

        // Check if the event wants telemetry enabled
        //
        // Going from leaf span to the root, we check if any of the spans have a
        // `telemetry` field set to `false`. If so, short-circuit return.
        //
        // If a `telemetry` field is set to `true`, we set the `wants_telemetry`
        // flag to `true` and then break.
        for span in ctx.event_scope().into_iter().flatten() {
            if let Some(fields) = span.extensions().get::<FormattedFields<N>>() {
                // A regex to parse the `telemetry` field from the span's fields
                static TELEMETRY_SETTING_REGEX: LazyLock<Result<Regex>> =
                    LazyLock::new(|| Ok(regex::Regex::new(r"telemetry\s*=\s*(true|false)")?));

                let telemetry_setting = TELEMETRY_SETTING_REGEX
                    .as_ref()
                    .ok()
                    .and_then(|regex| regex.captures(fields.fields.as_str()))
                    .and_then(|caps| caps.get(1))
                    .map(|m| m.as_str());

                if let Some("false") = telemetry_setting {
                    return Ok(());
                } else if let Some("true") = telemetry_setting {
                    wants_telemetry = true;
                    break;
                }
            }
        }

        if !wants_telemetry {
            return Ok(());
        }

        // Use a temporary buffer as the writer for the event, then at the end
        // we Base64 encode the buffer and write it to passed-in writer.
        let mut buffer = String::new();
        let mut tmp_writer = Writer::new(&mut buffer);

        // We deliberately use fixed .9 digit precision followed by Zulu as
        // InfluxDB seems to have a few issues with parsing timezones, offsets,
        // and nanoseconds.
        write!(
            &mut tmp_writer,
            "{} {:>5} {}:{}:{} {}:{}:{} {} ",
            Utc::now().format("%Y-%m-%dT%H:%M:%S%.9fZ"),
            event.metadata().level(),
            self.triple,
            self.os,
            self.os_version,
            var("TELEMETRY_PKG_NAME").unwrap_or("unknown".to_string()),
            var("TELEMETRY_PKG_VERSION").unwrap_or("unknown".to_string()),
            event.metadata().file().unwrap_or("unknown"),
            self.trace_id,
        )?;

        // For each span in the event, write out the span and its fields to the temporary writer
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                write!(tmp_writer, "{}", span.name())?;

                if let Some(fields) = span.extensions().get::<FormattedFields<N>>() {
                    if !fields.is_empty() {
                        // Strip the telemetry field from the outputted fields
                        static STRIP_TELEMETRY_REGEX: LazyLock<Result<Regex>> =
                            LazyLock::new(|| {
                                Ok(regex::Regex::new(r"\s*telemetry\s*=\s*(true|false)\s*")?)
                            });

                        let fields = STRIP_TELEMETRY_REGEX
                            .as_ref()
                            .map_err(|_| std::fmt::Error)?
                            .replace_all(fields.fields.as_str(), "")
                            .to_string();

                        if !fields.is_empty() {
                            write!(tmp_writer, "{{{fields}}}")?;
                        }
                    }
                };

                write!(tmp_writer, ":")?;
            }

            write!(tmp_writer, " ")?;
        }

        // Call out to the default field formatter with the temporary writer
        ctx.field_format()
            .format_fields(tmp_writer.by_ref(), event)?;

        // Base64 encode the temporary buffer before writing it to the output writer
        let encoded = STANDARD.encode(&buffer);
        writer.write_str(&encoded)?;
        writer.write_str("\n")
    }
}
