use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use regex::Regex;
use std::{env::var, path::PathBuf, sync::LazyLock};
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
    /// use tracing_subscriber::{fmt::Layer, Registry};
    ///
    /// let telemetry_formatter = TelemetryFormatter::new();
    ///
    /// let layer = tracing_subscriber::fmt::layer::<Registry>()
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

trait TelemetryFormatterAccessors {
    fn triple(&self) -> &str {
        ""
    }
    fn os(&self) -> &str {
        ""
    }
    fn os_version(&self) -> &str {
        ""
    }
    fn trace_id(&self) -> &str {
        ""
    }
}

impl TelemetryFormatterAccessors for TelemetryFormatter {
    fn triple(&self) -> &str {
        &self.triple
    }

    fn os(&self) -> &str {
        &self.os
    }

    fn os_version(&self) -> &str {
        &self.os_version
    }

    fn trace_id(&self) -> &str {
        &self.trace_id
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
        format_event_with_helpers(self, ctx, &mut writer, event, &DefaultFormatEventHelpers)
    }
}

fn format_event_with_helpers<S, N>(
    telemetry_formatter: &impl TelemetryFormatterAccessors,
    ctx: &FmtContext<'_, S, N>,
    writer: &mut Writer<'_>,
    event: &Event<'_>,
    helpers: &impl FormatEventHelpers,
) -> std::fmt::Result
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    if !helpers.wants_telemetry(ctx) {
        return Ok(());
    }

    // Use a temporary buffer as the writer for the event, then at the end
    // we Base64 encode the buffer and write it to passed-in writer.
    let mut buffer = String::new();
    let mut tmp_writer = Writer::new(&mut buffer);

    helpers.write_metadata(telemetry_formatter, &mut tmp_writer, event)?;
    helpers.write_spans(&mut tmp_writer, ctx, event)?;
    helpers.write_encoded_buffer(writer, &buffer)?;

    Ok(())
}

trait FormatEventHelpers {
    /// Check if the event wants telemetry enabled
    ///
    /// Going from leaf span to the root, we check if any of the spans have a
    /// `telemetry` field set to `false`. If so, short-circuit return.
    ///
    /// If a `telemetry` field is set to `true`, we set the `wants_telemetry`
    /// flag to `true` and then break.
    fn wants_telemetry<S, N>(&self, ctx: &FmtContext<'_, S, N>) -> bool
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
        N: for<'a> FormatFields<'a> + 'static,
    {
        for span in ctx.event_scope().into_iter().flatten() {
            if let Some(fields) = span.extensions().get::<FormattedFields<N>>() {
                // A regex to parse the `telemetry` field from the span's fields
                static TELEMETRY_SETTING_REGEX: LazyLock<Result<Regex>> =
                    LazyLock::new(|| Ok(regex::Regex::new(r"telemetry\s*=\s*(true|false)")?));

                let telemetry_setting = TELEMETRY_SETTING_REGEX
                    .as_ref()
                    .ok()
                    .and_then(|regex| regex.captures(fields.fields.as_str()))
                    .and_then(|captures| captures.get(1))
                    .map(|m| m.as_str());

                if let Some("false") = telemetry_setting {
                    return false;
                } else if let Some("true") = telemetry_setting {
                    return true;
                }
            }
        }

        false
    }

    /// Write the event metadata to the writer
    fn write_metadata(
        &self,
        telemetry_formatter_accessors: &impl TelemetryFormatterAccessors,
        writer: &mut Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        // We deliberately use fixed .9 digit precision followed by Zulu as
        // InfluxDB seems to have a few issues with parsing timezones, offsets,
        // and nanoseconds.
        write!(
            writer,
            "{} {:>5} {}:{}:{} {}:{}:{} {} ",
            Utc::now().format("%Y-%m-%dT%H:%M:%S%.9fZ"),
            event.metadata().level(),
            telemetry_formatter_accessors.triple(),
            telemetry_formatter_accessors.os(),
            telemetry_formatter_accessors.os_version(),
            var("TELEMETRY_PKG_NAME").unwrap_or("unknown".to_string()),
            var("TELEMETRY_PKG_VERSION").unwrap_or("unknown".to_string()),
            self.sanitise_file_path(event, |path| PathBuf::from(path)),
            telemetry_formatter_accessors.trace_id(),
        )?;

        Ok(())
    }

    /// Strip everything before and including src/ in the filepath
    fn sanitise_file_path<F: Fn(&str) -> PathBuf>(
        &self,
        event: &Event<'_>,
        pathbuf_from: F,
    ) -> String {
        event
            .metadata()
            .file()
            .map(|path| {
                let path = pathbuf_from(path);
                let path = path
                    .components()
                    .position(|c| c.as_os_str() == "src")
                    .map(|pos| path.components().skip(pos + 1).collect::<PathBuf>())
                    .unwrap_or(path)
                    .to_string_lossy()
                    .into_owned();

                if path.is_empty() {
                    "unknown".to_string()
                } else {
                    path
                }
            })
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Expand each span and its fields to the writer
    fn write_spans<S, N>(
        &self,
        writer: &mut Writer<'_>,
        ctx: &FmtContext<'_, S, N>,
        event: &Event<'_>,
    ) -> std::fmt::Result
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
        N: for<'a> FormatFields<'a> + 'static,
    {
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                write!(writer, "{}", span.name())?;

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
                            write!(writer, "{{{fields}}}")?;
                        }
                    }
                };

                write!(writer, ":")?;
            }

            write!(writer, " ")?;
        }

        // Call out to the default field formatter
        ctx.field_format().format_fields(writer.by_ref(), event)?;

        Ok(())
    }

    /// Base64 encode the buffer before writing it to the writer
    fn write_encoded_buffer(&self, writer: &mut Writer<'_>, buffer: &str) -> std::fmt::Result {
        if buffer.is_empty() {
            return Ok(());
        }

        let encoded = STANDARD.encode(buffer);
        writeln!(writer, "{encoded}")?;

        Ok(())
    }
}

#[derive(Default, Clone)]
struct DefaultFormatEventHelpers;
impl FormatEventHelpers for DefaultFormatEventHelpers {}

#[cfg(test)]
mod new {
    use super::*;
    use sysinfo::System;
    use uuid::Uuid;

    #[test]
    fn test_new() {
        // This test may seem like a tautology based on the definition of
        // `new()`, but at least it will help catch regressions

        let formatter = TelemetryFormatter::new();

        assert_eq!(
            formatter.os,
            System::name().unwrap_or("unknown".to_string())
        );

        assert_eq!(
            formatter.os_version,
            System::kernel_version().unwrap_or("unknown".to_string())
        );

        assert!(Uuid::parse_str(&formatter.trace_id).is_ok());

        let triple = format!(
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
        );

        assert_eq!(formatter.triple, triple);
    }
}

// Helper macro to hide the block under #[cfg(test)] but within the same scope
macro_rules! cfg_test {
    ($($item:item)*) => {
        $(
            #[cfg(test)]
            $item
        )*
    }
}

// Some of the `tracing` types generated when `Event`s are formatted have no
// public constructors, and so calling individual helper methods of
// `FormatEventHelpers` directly inside unit tests is impossible. As such, in
// order to test these methods, we essentially have to create a new `Formatter`
// type that we can then override within each unit test.
//
// ... unfortunately this also means we need to setup the whole `tracing`
// infrastructure in order to get our test `Formatter` calling test methods.
//
// This helper macro generates as much `tracing` infrastructure as possible so
// that each unit test can test its own `Formatter` implementations.
cfg_test! {
    use std::{
        io::Write,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex, OnceLock,
        },
    };
    use tracing::span;
    use tracing_appender::non_blocking::NonBlocking;
    use tracing_subscriber::{
        fmt::{format::DefaultFields, Layer},
        layer::{Context, Layer as LayerTrait},
        prelude::__tracing_subscriber_SubscriberExt,
        registry::Registry,
        util::SubscriberInitExt,
    };

    #[derive(Default, Debug)]
    struct BufferWriter {
        buffer: Arc<Mutex<String>>,
    }

    static BUFFERED_WRITER: LazyLock<BufferWriter> = LazyLock::new(BufferWriter::default);

    impl Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buffer
                .lock()
                .unwrap()
                .push_str(std::str::from_utf8(buf).unwrap());

            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl std::fmt::Write for BufferWriter {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            self.buffer.lock().unwrap().push_str(s);
            Ok(())
        }
    }

    impl Clone for BufferWriter {
        fn clone(&self) -> Self {
            BufferWriter {
                buffer: self.buffer.clone(),
            }
        }
    }

    macro_rules! generate_test_formatter {
        ($name:ident) => {
            generate_test_formatter!($name, {})
        };

        ($name:ident, { $($impl_block:tt)* }) => {
            {
                #[derive(Default, Clone)]
                struct TestFormatter<H: FormatEventHelpers> {
                    helpers: H,
                }

                impl<S, N, H: FormatEventHelpers> FormatEvent<S, N> for TestFormatter<H>
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    fn format_event(
                        &self,
                        ctx: &FmtContext<'_, S, N>,
                        mut writer: Writer<'_>,
                        event: &Event<'_>,
                    ) -> std::fmt::Result {
                        format_event_with_helpers(
                            self,
                            ctx,
                            &mut writer,
                            event,
                            &self.helpers,
                        )
                    }
                }

                impl<H: FormatEventHelpers> TelemetryFormatterAccessors for TestFormatter<H> {
                    $($impl_block)*
                }

                struct TestLayer<H: FormatEventHelpers> {
                    inner: Layer<Registry, DefaultFields, TestFormatter<H>, NonBlocking>,
                }

                impl<H: FormatEventHelpers + 'static> LayerTrait<Registry> for &'static TestLayer<H> {
                    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, Registry>) {
                        self.inner.on_event(event, ctx);
                    }

                    fn on_enter(&self, id: &span::Id, ctx: Context<'_, Registry>) {
                        self.inner.on_enter(id, ctx);
                    }

                    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, Registry>) {
                        self.inner.on_new_span(attrs, id, ctx);
                    }
                }

                let (writer, flush_guard) = tracing_appender::non_blocking(BUFFERED_WRITER.clone());

                let format_event_helpers = $name::default();
                static TEST_FORMATTER: OnceLock<TestFormatter<$name>> = OnceLock::new();
                let _ = TEST_FORMATTER.set(TestFormatter { helpers: format_event_helpers.clone() });

                let inner_layer = tracing_subscriber::fmt::layer::<Registry>()
                    .with_writer(writer.clone())
                    .with_ansi(false)
                    .event_format(TEST_FORMATTER.get().unwrap().clone());

                static TEST_LAYER: OnceLock<TestLayer<$name>> = OnceLock::new();
                let _ = TEST_LAYER.set(TestLayer{ inner: inner_layer });

                let default_guard = Registry::default()
                    .with(TEST_LAYER.get().unwrap())
                    .init();

               (flush_guard, default_guard, format_event_helpers)
            }
        };
    }
}

// To minimise complexity, we'll separate the testing of `format_event()` from
// the testing of its individual helper methods i.e. the following module mostly
// just tests that the expected code paths were taken in the event of an error,
// whereas the testing of actual logic and output of the helper methods will be
// done in the modules following this one.
#[cfg(test)]
mod format_event {
    use super::*;
    use rusty_fork::rusty_fork_test;

    rusty_fork_test! {
        #[test]
        fn no_telemetry() {
            #[derive(Default, Clone)]
            struct NoTelemetryHelpers {
                default_helpers: DefaultFormatEventHelpers,
                wants_telemetry_called: Arc<AtomicBool>,
                write_metadata_called: Arc<AtomicBool>,
            }

            impl FormatEventHelpers for NoTelemetryHelpers {
                fn wants_telemetry<S, N>(&self, _ctx: &FmtContext<'_, S, N>) -> bool
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.wants_telemetry_called.store(true, Ordering::Relaxed);
                    false
                }

                fn write_metadata(
                    &self,
                    telemetry_formatter_accessors: &impl TelemetryFormatterAccessors,
                    writer: &mut Writer<'_>,
                    event: &Event<'_>,
                ) -> std::fmt::Result {
                    self.write_metadata_called.store(true, Ordering::Relaxed);
                    self.default_helpers.write_metadata(
                        telemetry_formatter_accessors,
                        writer,
                        event,
                    )
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(NoTelemetryHelpers);

                tracing::span!(tracing::Level::ERROR, "no_telemetry").in_scope(|| {
                    tracing::error!("test message");
                });

                assert!(format_event_helpers
                    .wants_telemetry_called
                    .load(Ordering::Relaxed));

                assert!(!format_event_helpers
                    .write_metadata_called
                    .load(Ordering::Relaxed));
            }

            assert!(BUFFERED_WRITER.buffer.lock().unwrap().is_empty());
        }

        #[test]
        fn wants_telemetry() {
            #[derive(Default, Clone)]
            struct WantsTelemetryHelpers {
                default_helpers: DefaultFormatEventHelpers,
                wants_telemetry_called: Arc<AtomicBool>,
                write_metadata_called: Arc<AtomicBool>,
            }

            impl FormatEventHelpers for WantsTelemetryHelpers {
                fn wants_telemetry<S, N>(&self, _ctx: &FmtContext<'_, S, N>) -> bool
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.wants_telemetry_called.store(true, Ordering::Relaxed);
                    true
                }

                fn write_metadata(
                    &self,
                    telemetry_formatter_accessors: &impl TelemetryFormatterAccessors,
                    writer: &mut Writer<'_>,
                    event: &Event<'_>,
                ) -> std::fmt::Result {
                    self.write_metadata_called.store(true, Ordering::Relaxed);
                    self.default_helpers.write_metadata(
                        telemetry_formatter_accessors,
                        writer,
                        event,
                    )
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(WantsTelemetryHelpers);

                tracing::span!(tracing::Level::ERROR, "wants_telemetry", telemetry = true)
                    .in_scope(|| {
                        tracing::error!("test message");
                    });

                assert!(format_event_helpers
                    .wants_telemetry_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_metadata_called
                    .load(Ordering::Relaxed));
            }

            assert!(!BUFFERED_WRITER.buffer.lock().unwrap().is_empty());
        }

        #[test]
        fn write_metadata_failed() {
            #[derive(Default, Clone)]
            struct WriteMetadataFailedHelpers {
                default_helpers: DefaultFormatEventHelpers,
                wants_telemetry_called: Arc<AtomicBool>,
                write_metadata_called: Arc<AtomicBool>,
                write_spans_called: Arc<AtomicBool>,
            }

            impl FormatEventHelpers for WriteMetadataFailedHelpers {
                fn wants_telemetry<S, N>(&self, ctx: &FmtContext<'_, S, N>) -> bool
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.wants_telemetry_called.store(true, Ordering::Relaxed);
                    self.default_helpers.wants_telemetry(ctx)
                }

                fn write_metadata(
                    &self,
                    _telemetry_formatter_accessors: &impl TelemetryFormatterAccessors,
                    _writer: &mut Writer<'_>,
                    _event: &Event<'_>,
                ) -> std::fmt::Result {
                    self.write_metadata_called.store(true, Ordering::Relaxed);
                    Err(std::fmt::Error)
                }

                fn write_spans<S, N>(
                    &self,
                    writer: &mut Writer<'_>,
                    ctx: &FmtContext<'_, S, N>,
                    event: &Event<'_>,
                ) -> std::fmt::Result
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.write_spans_called.store(true, Ordering::Relaxed);
                    self.default_helpers.write_spans(writer, ctx, event)
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(WriteMetadataFailedHelpers);

                tracing::span!(
                    tracing::Level::ERROR,
                    "write_metadata_failed",
                    telemetry = true
                )
                .in_scope(|| {
                    tracing::error!("test message");
                });

                assert!(format_event_helpers
                    .wants_telemetry_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_metadata_called
                    .load(Ordering::Relaxed));

                assert!(!format_event_helpers
                    .write_spans_called
                    .load(Ordering::Relaxed));
            }

            assert!(BUFFERED_WRITER.buffer.lock().unwrap().is_empty());
        }

        #[test]
        fn write_spans_failed() {
            #[derive(Default, Clone)]
            struct WriteSpansFailedHelpers {
                default_helpers: DefaultFormatEventHelpers,
                wants_telemetry_called: Arc<AtomicBool>,
                write_metadata_called: Arc<AtomicBool>,
                write_spans_called: Arc<AtomicBool>,
                write_encoded_buffer_called: Arc<AtomicBool>,
            }

            impl FormatEventHelpers for WriteSpansFailedHelpers {
                fn wants_telemetry<S, N>(&self, ctx: &FmtContext<'_, S, N>) -> bool
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.wants_telemetry_called.store(true, Ordering::Relaxed);
                    self.default_helpers.wants_telemetry(ctx)
                }

                fn write_metadata(
                    &self,
                    telemetry_formatter_accessors: &impl TelemetryFormatterAccessors,
                    writer: &mut Writer<'_>,
                    event: &Event<'_>,
                ) -> std::fmt::Result {
                    self.write_metadata_called.store(true, Ordering::Relaxed);
                    self.default_helpers.write_metadata(
                        telemetry_formatter_accessors,
                        writer,
                        event,
                    )
                }

                fn write_spans<S, N>(
                    &self,
                    _writer: &mut Writer<'_>,
                    _ctx: &FmtContext<'_, S, N>,
                    _event: &Event<'_>,
                ) -> std::fmt::Result {
                    self.write_spans_called.store(true, Ordering::Relaxed);
                    Err(std::fmt::Error)
                }

                fn write_encoded_buffer(
                    &self,
                    writer: &mut Writer<'_>,
                    buffer: &str,
                ) -> std::fmt::Result {
                    self.write_encoded_buffer_called
                        .store(true, Ordering::Relaxed);

                    self.default_helpers.write_encoded_buffer(writer, buffer)
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(WriteSpansFailedHelpers);

                tracing::span!(
                    tracing::Level::ERROR,
                    "write_spans_failed",
                    telemetry = true
                )
                .in_scope(|| {
                    tracing::error!("test message");
                });

                assert!(format_event_helpers
                    .wants_telemetry_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_metadata_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_spans_called
                    .load(Ordering::Relaxed));

                assert!(!format_event_helpers
                    .write_encoded_buffer_called
                    .load(Ordering::Relaxed));
            }

            assert!(BUFFERED_WRITER.buffer.lock().unwrap().is_empty());
        }

        #[test]
        fn write_encoded_buffer_failed() {
            #[derive(Default, Clone)]
            struct WriteEncodedBufferFailedHelpers {
                default_helpers: DefaultFormatEventHelpers,
                wants_telemetry_called: Arc<AtomicBool>,
                write_metadata_called: Arc<AtomicBool>,
                write_spans_called: Arc<AtomicBool>,
                write_encoded_buffer_called: Arc<AtomicBool>,
            }

            impl FormatEventHelpers for WriteEncodedBufferFailedHelpers {
                fn wants_telemetry<S, N>(&self, ctx: &FmtContext<'_, S, N>) -> bool
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.wants_telemetry_called.store(true, Ordering::Relaxed);
                    self.default_helpers.wants_telemetry(ctx)
                }

                fn write_metadata(
                    &self,
                    telemetry_formatter_accessors: &impl TelemetryFormatterAccessors,
                    writer: &mut Writer<'_>,
                    event: &Event<'_>,
                ) -> std::fmt::Result {
                    self.write_metadata_called.store(true, Ordering::Relaxed);
                    self.default_helpers.write_metadata(
                        telemetry_formatter_accessors,
                        writer,
                        event,
                    )
                }

                fn write_spans<S, N>(
                    &self,
                    writer: &mut Writer<'_>,
                    ctx: &FmtContext<'_, S, N>,
                    event: &Event<'_>,
                ) -> std::fmt::Result
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.write_spans_called.store(true, Ordering::Relaxed);
                    self.default_helpers.write_spans(writer, ctx, event)
                }

                fn write_encoded_buffer(
                    &self,
                    _writer: &mut Writer<'_>,
                    _buffer: &str,
                ) -> std::fmt::Result {
                    self.write_encoded_buffer_called
                        .store(true, Ordering::Relaxed);

                    Err(std::fmt::Error)
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(WriteEncodedBufferFailedHelpers);

                tracing::span!(
                    tracing::Level::ERROR,
                    "write_encoded_buffer_failed",
                    telemetry = true
                )
                .in_scope(|| {
                    tracing::error!("test message");
                });

                assert!(format_event_helpers
                    .wants_telemetry_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_metadata_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_spans_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_encoded_buffer_called
                    .load(Ordering::Relaxed));
            }

            assert!(BUFFERED_WRITER.buffer.lock().unwrap().is_empty());
        }

        #[test]
        fn ok() {
            #[derive(Default, Clone)]
            struct OkHelpers {
                default_helpers: DefaultFormatEventHelpers,
                wants_telemetry_called: Arc<AtomicBool>,
                write_metadata_called: Arc<AtomicBool>,
                write_spans_called: Arc<AtomicBool>,
                write_encoded_buffer_called: Arc<AtomicBool>,
            }

            impl FormatEventHelpers for OkHelpers {
                fn wants_telemetry<S, N>(&self, ctx: &FmtContext<'_, S, N>) -> bool
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.wants_telemetry_called.store(true, Ordering::Relaxed);
                    self.default_helpers.wants_telemetry(ctx)
                }

                fn write_metadata(
                    &self,
                    telemetry_formatter_accessors: &impl TelemetryFormatterAccessors,
                    writer: &mut Writer<'_>,
                    event: &Event<'_>,
                ) -> std::fmt::Result {
                    self.write_metadata_called.store(true, Ordering::Relaxed);
                    self.default_helpers.write_metadata(
                        telemetry_formatter_accessors,
                        writer,
                        event,
                    )
                }

                fn write_spans<S, N>(
                    &self,
                    writer: &mut Writer<'_>,
                    ctx: &FmtContext<'_, S, N>,
                    event: &Event<'_>,
                ) -> std::fmt::Result
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.write_spans_called.store(true, Ordering::Relaxed);
                    self.default_helpers.write_spans(writer, ctx, event)
                }

                fn write_encoded_buffer(
                    &self,
                    writer: &mut Writer<'_>,
                    buffer: &str,
                ) -> std::fmt::Result {
                    self.write_encoded_buffer_called
                        .store(true, Ordering::Relaxed);

                    self.default_helpers.write_encoded_buffer(writer, buffer)
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(OkHelpers);

                tracing::span!(tracing::Level::ERROR, "ok", telemetry = true).in_scope(|| {
                    tracing::error!("test message");
                });

                assert!(format_event_helpers
                    .wants_telemetry_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_metadata_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_spans_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_encoded_buffer_called
                    .load(Ordering::Relaxed));
            }

            // Finally we can test that it was successfully written to!
            assert!(!BUFFERED_WRITER.buffer.lock().unwrap().is_empty());
        }
    }
}

#[cfg(test)]
mod wants_telemetry {
    use super::*;
    use rusty_fork::rusty_fork_test;

    rusty_fork_test! {
        #[test]
        fn no_span() {
            #[derive(Default, Clone)]
            struct NoSpanHelpers {
                default_helpers: DefaultFormatEventHelpers,
                wants_telemetry_called: Arc<AtomicBool>,
                wants_telemetry_result: Arc<OnceLock<bool>>,
                write_encoded_buffer_called: Arc<AtomicBool>,
            }

            impl FormatEventHelpers for NoSpanHelpers {
                fn wants_telemetry<S, N>(&self, ctx: &FmtContext<'_, S, N>) -> bool
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.wants_telemetry_called.store(true, Ordering::Relaxed);

                    let result = self.default_helpers.wants_telemetry(ctx);
                    self.wants_telemetry_result.set(result).unwrap();

                    result
                }

                fn write_encoded_buffer(
                    &self,
                    writer: &mut Writer<'_>,
                    buffer: &str,
                ) -> std::fmt::Result {
                    // Check if we made it all the way to the end of
                    // `format_event()`, or short-circuited
                    self.write_encoded_buffer_called
                        .store(true, Ordering::Relaxed);

                    self.default_helpers.write_encoded_buffer(writer, buffer)
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(NoSpanHelpers);

                tracing::event!(tracing::Level::ERROR, "test message");

                assert!(format_event_helpers
                    .wants_telemetry_called
                    .load(Ordering::Relaxed));

                assert!(!*format_event_helpers.wants_telemetry_result.get().unwrap());

                assert!(!format_event_helpers
                    .write_encoded_buffer_called
                    .load(Ordering::Relaxed));
            }

            assert!(BUFFERED_WRITER.buffer.lock().unwrap().is_empty());
        }

        #[test]
        fn no_telemetry_field() {
            #[derive(Default, Clone)]
            struct NoTelemetryFieldHelpers {
                default_helpers: DefaultFormatEventHelpers,
                wants_telemetry_called: Arc<AtomicBool>,
                wants_telemetry_result: Arc<OnceLock<bool>>,
                write_encoded_buffer_called: Arc<AtomicBool>,
            }

            impl FormatEventHelpers for NoTelemetryFieldHelpers {
                fn wants_telemetry<S, N>(&self, ctx: &FmtContext<'_, S, N>) -> bool
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.wants_telemetry_called.store(true, Ordering::Relaxed);

                    let result = self.default_helpers.wants_telemetry(ctx);
                    self.wants_telemetry_result.set(result).unwrap();

                    result
                }

                fn write_encoded_buffer(
                    &self,
                    writer: &mut Writer<'_>,
                    buffer: &str,
                ) -> std::fmt::Result {
                    // Check if we made it all the way to the end of
                    // `format_event()`, or short-circuited
                    self.write_encoded_buffer_called
                        .store(true, Ordering::Relaxed);

                    self.default_helpers.write_encoded_buffer(writer, buffer)
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(NoTelemetryFieldHelpers);

                tracing::span!(tracing::Level::ERROR, "no_telemetry_field").in_scope(|| {
                    tracing::span!(tracing::Level::ERROR, "no_telemetry_field_child").in_scope(|| {
                        tracing::span!(tracing::Level::ERROR, "no_telemetry_field_grandchild").in_scope(|| {
                            tracing::span!(tracing::Level::ERROR, "no_telemetry_field_great_grandchild").in_scope(|| {
                                tracing::error!("test message");
                            });
                        });
                    });
                });

                assert!(format_event_helpers
                    .wants_telemetry_called
                    .load(Ordering::Relaxed));

                assert!(!*format_event_helpers.wants_telemetry_result.get().unwrap());

                assert!(!format_event_helpers
                    .write_encoded_buffer_called
                    .load(Ordering::Relaxed));
            }

            assert!(BUFFERED_WRITER.buffer.lock().unwrap().is_empty());
        }

        #[test]
        fn telemetry_field_false() {
            #[derive(Default, Clone)]
            struct TelemetryFieldFalseHelpers {
                default_helpers: DefaultFormatEventHelpers,
                wants_telemetry_called: Arc<AtomicBool>,
                wants_telemetry_result: Arc<OnceLock<bool>>,
                write_encoded_buffer_called: Arc<AtomicBool>,
            }

            impl FormatEventHelpers for TelemetryFieldFalseHelpers {
                fn wants_telemetry<S, N>(&self, ctx: &FmtContext<'_, S, N>) -> bool
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.wants_telemetry_called.store(true, Ordering::Relaxed);

                    let result = self.default_helpers.wants_telemetry(ctx);
                    self.wants_telemetry_result.set(result).unwrap();

                    result
                }

                fn write_encoded_buffer(
                    &self,
                    writer: &mut Writer<'_>,
                    buffer: &str,
                ) -> std::fmt::Result {
                    // Check if we made it all the way to the end of
                    // `format_event()`, or short-circuited
                    self.write_encoded_buffer_called
                        .store(true, Ordering::Relaxed);

                    self.default_helpers.write_encoded_buffer(writer, buffer)
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(TelemetryFieldFalseHelpers);

                tracing::span!(tracing::Level::ERROR, "telemetry_field_false",).in_scope(|| {
                    tracing::span!(tracing::Level::ERROR, "telemetry_field_false_child").in_scope(|| {
                        tracing::span!(tracing::Level::ERROR, "telemetry_field_false_grandchild", telemetry = false).in_scope(|| {
                            tracing::span!(tracing::Level::ERROR, "telemetry_field_false_great_grandchild").in_scope(|| {
                                tracing::error!("test message");
                            });
                        });
                    });
                });

                assert!(format_event_helpers
                    .wants_telemetry_called
                    .load(Ordering::Relaxed));

                assert!(!*format_event_helpers.wants_telemetry_result.get().unwrap());

                assert!(!format_event_helpers
                    .write_encoded_buffer_called
                    .load(Ordering::Relaxed));
            }

            assert!(BUFFERED_WRITER.buffer.lock().unwrap().is_empty());
        }

        #[test]
        fn telemetry_field_true() {
            #[derive(Default, Clone)]
            struct TelemetryFieldTrueHelpers {
                default_helpers: DefaultFormatEventHelpers,
                wants_telemetry_called: Arc<AtomicBool>,
                wants_telemetry_result: Arc<OnceLock<bool>>,
                write_encoded_buffer_called: Arc<AtomicBool>,
            }

            impl FormatEventHelpers for TelemetryFieldTrueHelpers {
                fn wants_telemetry<S, N>(&self, ctx: &FmtContext<'_, S, N>) -> bool
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.wants_telemetry_called.store(true, Ordering::Relaxed);

                    let result = self.default_helpers.wants_telemetry(ctx);
                    self.wants_telemetry_result.set(result).unwrap();

                    result
                }

                fn write_encoded_buffer(
                    &self,
                    writer: &mut Writer<'_>,
                    buffer: &str,
                ) -> std::fmt::Result {
                    // Veryfying we made it all the way to the end of `format_event()`
                    self.write_encoded_buffer_called
                        .store(true, Ordering::Relaxed);

                    self.default_helpers.write_encoded_buffer(writer, buffer)
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(TelemetryFieldTrueHelpers, {
                        fn triple(&self) -> &str {
                            "TRIPLE"
                        }

                        fn os(&self) -> &str {
                            "OS"
                        }

                        fn os_version(&self) -> &str {
                            "OS_VERSION"
                        }

                        fn trace_id(&self) -> &str {
                            "TRACE_ID"
                        }
                    });

                tracing::span!(tracing::Level::ERROR, "telemetry_field_true", telemetry = true).in_scope(|| {
                    tracing::span!(tracing::Level::ERROR, "telemetry_field_true_child").in_scope(|| {
                        tracing::span!(tracing::Level::ERROR, "telemetry_field_true_grandchild", telemetry = true).in_scope(|| {
                            tracing::span!(tracing::Level::ERROR, "telemetry_field_true_great_grandchild").in_scope(|| {
                                tracing::error!("test message");
                            });
                        });
                    });
                });

                assert!(format_event_helpers
                    .wants_telemetry_called
                    .load(Ordering::Relaxed));

                assert!(*format_event_helpers.wants_telemetry_result.get().unwrap());

                assert!(format_event_helpers
                    .write_encoded_buffer_called
                    .load(Ordering::Relaxed));
            }

            assert!(!BUFFERED_WRITER.buffer.lock().unwrap().is_empty());

            let mut buffer = BUFFERED_WRITER.buffer.lock().unwrap().clone();
            buffer.pop();

            assert!(String::from_utf8(STANDARD.decode(buffer).unwrap())
                .unwrap()
                .ends_with("TRACE_ID telemetry_field_true:telemetry_field_true_child:telemetry_field_true_grandchild:telemetry_field_true_great_grandchild: test message"));
        }
    }
}

#[cfg(test)]
mod write_metadata {
    use super::*;
    use regex::Regex;
    use rusty_fork::rusty_fork_test;
    use std::env::set_var;

    rusty_fork_test! {
        #[test]
        fn write_failed() {
            #[derive(Default)]
            struct WriteFailedWriter;

            impl std::fmt::Write for WriteFailedWriter {
                fn write_str(&mut self, _s: &str) -> std::fmt::Result {
                    Err(std::fmt::Error)
                }
            }

            #[derive(Default, Clone)]
            struct WriteFailedHelpers {
                default_helpers: DefaultFormatEventHelpers,
                write_metadata_called: Arc<AtomicBool>,
                write_metadata_result: Arc<OnceLock<std::fmt::Result>>,
            }

            impl FormatEventHelpers for WriteFailedHelpers {
                fn write_metadata(
                    &self,
                    telemetry_formatter_accessors: &impl TelemetryFormatterAccessors,
                    _writer: &mut Writer<'_>,
                    event: &Event<'_>,
                ) -> std::fmt::Result {
                    self.write_metadata_called.store(true, Ordering::Relaxed);

                    let mut binding = WriteFailedWriter;
                    let mut writer = Writer::new(&mut binding);

                    let result = self.default_helpers.write_metadata(
                        telemetry_formatter_accessors,
                        &mut writer,
                        event,
                    );

                    self.write_metadata_result.set(result).unwrap();

                    result
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(WriteFailedHelpers);

                tracing::span!(tracing::Level::ERROR, "write_failed", telemetry = true).in_scope(|| {
                    tracing::error!("test message");
                });

                assert!(format_event_helpers
                    .write_metadata_called
                    .load(Ordering::Relaxed));

                assert_eq!(
                    format_event_helpers
                        .write_metadata_result
                        .get()
                        .unwrap()
                        .err(),
                    Some(std::fmt::Error)
                );
            }

            assert!(BUFFERED_WRITER.buffer.lock().unwrap().is_empty());
        }

        #[test]
        fn values_unset() {
            #[derive(Default, Clone)]
            struct VarUnsetHelpers {
                default_helpers: DefaultFormatEventHelpers,
                write_metadata_called: Arc<AtomicBool>,
                write_metadata_result: Arc<OnceLock<std::fmt::Result>>,
                write_metadata_buffer: Arc<OnceLock<String>>,
            }

            impl FormatEventHelpers for VarUnsetHelpers {
                fn write_metadata(
                    &self,
                    telemetry_formatter_accessors: &impl TelemetryFormatterAccessors,
                    writer: &mut Writer<'_>,
                    event: &Event<'_>,
                ) -> std::fmt::Result {
                    self.write_metadata_called.store(true, Ordering::Relaxed);

                    let mut buffer_writer = BufferWriter::default();
                    let mut buffer_writer_writer = Writer::new(&mut buffer_writer);

                    let result = self.default_helpers.write_metadata(
                        telemetry_formatter_accessors,
                        &mut buffer_writer_writer,
                        event,
                    );

                    self.write_metadata_result.set(result).unwrap();

                    self.write_metadata_buffer
                        .set(buffer_writer.buffer.lock().unwrap().clone())
                        .unwrap();

                    writer
                        .write_str(buffer_writer.buffer.lock().unwrap().as_str())
                        .unwrap();

                    result
                }
            }

            let write_metadata_regex = Regex::new(
                r"(?x)
                \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z \s*
                ERROR                                       \s*
                TRIPLE:OS:OS_VERSION                        \s*
                unknown:unknown:telemetry_formatter.rs      \s*
                TRACE_ID                                    \s*
            ",
            )
            .unwrap();

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(VarUnsetHelpers, {
                        fn triple(&self) -> &str {
                            "TRIPLE"
                        }

                        fn os(&self) -> &str {
                            "OS"
                        }

                        fn os_version(&self) -> &str {
                            "OS_VERSION"
                        }

                        fn trace_id(&self) -> &str {
                            "TRACE_ID"
                        }
                    });

                tracing::span!(tracing::Level::ERROR, "var_unset", telemetry = true).in_scope(|| {
                    tracing::error!("test message");
                });

                assert!(format_event_helpers
                    .write_metadata_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_metadata_result
                    .get()
                    .unwrap()
                    .is_ok());

                assert!(write_metadata_regex
                    .is_match(format_event_helpers.write_metadata_buffer.get().unwrap()));
            }

            assert!(!BUFFERED_WRITER.buffer.lock().unwrap().is_empty());

            let mut buffer: String = BUFFERED_WRITER.buffer.lock().unwrap().clone();
            buffer.pop();

            assert!(write_metadata_regex.is_match(
                String::from_utf8(STANDARD.decode(buffer).unwrap())
                    .unwrap()
                    .as_str()
            ));
        }

        #[test]
        fn values_set() {
            #[derive(Default, Clone)]
            struct ValuesSetHelpers {
                default_helpers: DefaultFormatEventHelpers,
                write_metadata_called: Arc<AtomicBool>,
                write_metadata_result: Arc<OnceLock<std::fmt::Result>>,
                write_metadata_buffer: Arc<OnceLock<String>>,
            }

            impl FormatEventHelpers for ValuesSetHelpers {
                fn write_metadata(
                    &self,
                    telemetry_formatter_accessors: &impl TelemetryFormatterAccessors,
                    writer: &mut Writer<'_>,
                    event: &Event<'_>,
                ) -> std::fmt::Result {
                    self.write_metadata_called.store(true, Ordering::Relaxed);

                    let mut buffer_writer = BufferWriter::default();
                    let mut buffer_writer_writer = Writer::new(&mut buffer_writer);

                    let result = self.default_helpers.write_metadata(
                        telemetry_formatter_accessors,
                        &mut buffer_writer_writer,
                        event,
                    );

                    self.write_metadata_result.set(result).unwrap();

                    self.write_metadata_buffer
                        .set(buffer_writer.buffer.lock().unwrap().clone())
                        .unwrap();

                    writer
                        .write_str(buffer_writer.buffer.lock().unwrap().as_str())
                        .unwrap();

                    result
                }
            }

            set_var("TELEMETRY_PKG_NAME", "telemetry-formatter");
            set_var("TELEMETRY_PKG_VERSION", "0.1.0");

            let write_metadata_regex = Regex::new(
                r"(?x)
                \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z       \s*
                ERROR                                             \s*
                aarch64-apple-darwin:Darwin:23.6.0                \s*
                telemetry-formatter:0.1.0:telemetry_formatter.rs  \s*
                \w{8}-\w{4}-\w{4}-\w{4}-\w{12}                    \s*
            ",
            )
            .unwrap();

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(ValuesSetHelpers, {
                        fn triple(&self) -> &str {
                            "aarch64-apple-darwin"
                        }

                        fn os(&self) -> &str {
                            "Darwin"
                        }

                        fn os_version(&self) -> &str {
                            "23.6.0"
                        }

                        fn trace_id(&self) -> &str {
                            static TRACE_ID: LazyLock<String> =
                                LazyLock::new(|| Uuid::new_v4().to_string());
                            TRACE_ID.as_str()
                        }
                    });

                tracing::span!(tracing::Level::ERROR, "var_unset", telemetry = true).in_scope(|| {
                    tracing::error!("test message");
                });

                assert!(format_event_helpers
                    .write_metadata_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_metadata_result
                    .get()
                    .unwrap()
                    .is_ok());

                assert!(write_metadata_regex
                    .is_match(format_event_helpers.write_metadata_buffer.get().unwrap()));
            }

            assert!(!BUFFERED_WRITER.buffer.lock().unwrap().is_empty());

            let mut buffer: String = BUFFERED_WRITER.buffer.lock().unwrap().clone();
            buffer.pop();

            assert!(write_metadata_regex.is_match(
                String::from_utf8(STANDARD.decode(buffer).unwrap())
                    .unwrap()
                    .as_str()
            ));
        }
    }
}

#[cfg(test)]
mod sanitise_file_path {
    use super::*;
    use rusty_fork::rusty_fork_test;
    use std::default::Default;

    rusty_fork_test! {
        #[test]
        fn no_path() {
            #[derive(Default, Clone)]
            struct NoPathHelpers {
                default_helpers: DefaultFormatEventHelpers,
                pathbuf_from_called: Arc<AtomicBool>,
                sanitised_file_path_results: Arc<OnceLock<String>>,
            }

            fn pathbuf_from(no_path_helpers: &NoPathHelpers, _path: &str) -> PathBuf {
                no_path_helpers
                    .pathbuf_from_called
                    .store(true, Ordering::Relaxed);

                PathBuf::from("")
            }

            impl FormatEventHelpers for NoPathHelpers {
                fn sanitise_file_path<F: Fn(&str) -> PathBuf>(
                    &self,
                    event: &Event<'_>,
                    _pathbuf_from: F,
                ) -> String {
                    let result = self
                        .default_helpers
                        .sanitise_file_path(event, |path| pathbuf_from(self, path));

                    self.sanitised_file_path_results
                        .set(result.clone())
                        .unwrap();

                    result
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(NoPathHelpers, {
                        fn triple(&self) -> &str {
                            "TRIPLE"
                        }

                        fn os(&self) -> &str {
                            "OS"
                        }

                        fn os_version(&self) -> &str {
                            "OS_VERSION"
                        }

                        fn trace_id(&self) -> &str {
                            "TRACE_ID"
                        }
                    });

                tracing::span!(tracing::Level::ERROR, "no_path", telemetry = true).in_scope(|| {
                    tracing::error!("test message");
                });

                assert!(format_event_helpers
                    .pathbuf_from_called
                    .load(Ordering::Relaxed));

                assert_eq!(
                    format_event_helpers
                        .sanitised_file_path_results
                        .get()
                        .unwrap(),
                    "unknown"
                );
            }

            assert!(!BUFFERED_WRITER.buffer.lock().unwrap().is_empty());

            let mut buffer: String = BUFFERED_WRITER.buffer.lock().unwrap().clone();
            buffer.pop();

            assert!(String::from_utf8(STANDARD.decode(buffer).unwrap())
                .unwrap()
                .contains("TRIPLE:OS:OS_VERSION unknown:unknown:unknown TRACE_ID"));
        }

        #[test]
        fn has_src() {
            #[derive(Default, Clone)]
            struct HasSrcHelpers {
                default_helpers: DefaultFormatEventHelpers,
                pathbuf_from_called: Arc<AtomicBool>,
                sanitised_file_path_results: Arc<OnceLock<String>>,
            }

            fn pathbuf_from(has_src_helpers: &HasSrcHelpers, _path: &str) -> PathBuf {
                has_src_helpers
                    .pathbuf_from_called
                    .store(true, Ordering::Relaxed);

                PathBuf::from("/a/b/c/src/d/e/f/g")
            }

            impl FormatEventHelpers for HasSrcHelpers {
                fn sanitise_file_path<F: Fn(&str) -> PathBuf>(
                    &self,
                    event: &Event<'_>,
                    _pathbuf_from: F,
                ) -> String {
                    let result = self
                        .default_helpers
                        .sanitise_file_path(event, |path| pathbuf_from(self, path));

                    self.sanitised_file_path_results
                        .set(result.clone())
                        .unwrap();

                    result
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(HasSrcHelpers, {
                        fn triple(&self) -> &str {
                            "TRIPLE"
                        }

                        fn os(&self) -> &str {
                            "OS"
                        }

                        fn os_version(&self) -> &str {
                            "OS_VERSION"
                        }

                        fn trace_id(&self) -> &str {
                            "TRACE_ID"
                        }
                    });

                tracing::span!(tracing::Level::ERROR, "has_src", telemetry = true).in_scope(|| {
                    tracing::error!("test message");
                });

                assert!(format_event_helpers
                    .pathbuf_from_called
                    .load(Ordering::Relaxed));

                assert_eq!(
                    format_event_helpers
                        .sanitised_file_path_results
                        .get()
                        .unwrap(),
                    "d/e/f/g"
                );
            }

            assert!(!BUFFERED_WRITER.buffer.lock().unwrap().is_empty());

            let mut buffer: String = BUFFERED_WRITER.buffer.lock().unwrap().clone();
            buffer.pop();

            assert!(String::from_utf8(STANDARD.decode(buffer).unwrap())
                .unwrap()
                .contains("TRIPLE:OS:OS_VERSION unknown:unknown:d/e/f/g TRACE_ID"));
        }

        #[test]
        fn no_src() {
            #[derive(Default, Clone)]
            struct NoSrcHelpers {
                default_helpers: DefaultFormatEventHelpers,
                pathbuf_from_called: Arc<AtomicBool>,
                sanitised_file_path_results: Arc<OnceLock<String>>,
            }

            fn pathbuf_from(no_src_helpers: &NoSrcHelpers, _path: &str) -> PathBuf {
                no_src_helpers
                    .pathbuf_from_called
                    .store(true, Ordering::Relaxed);

                PathBuf::from("/a/b/c/d/e/f/g")
            }

            impl FormatEventHelpers for NoSrcHelpers {
                fn sanitise_file_path<F: Fn(&str) -> PathBuf>(
                    &self,
                    event: &Event<'_>,
                    _pathbuf_from: F,
                ) -> String {
                    let result = self
                        .default_helpers
                        .sanitise_file_path(event, |path| pathbuf_from(self, path));

                    self.sanitised_file_path_results
                        .set(result.clone())
                        .unwrap();

                    result
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(NoSrcHelpers, {
                        fn triple(&self) -> &str {
                            "TRIPLE"
                        }

                        fn os(&self) -> &str {
                            "OS"
                        }

                        fn os_version(&self) -> &str {
                            "OS_VERSION"
                        }

                        fn trace_id(&self) -> &str {
                            "TRACE_ID"
                        }
                    });

                tracing::span!(tracing::Level::ERROR, "no_src", telemetry = true).in_scope(|| {
                    tracing::error!("test message");
                });

                assert!(format_event_helpers
                    .pathbuf_from_called
                    .load(Ordering::Relaxed));

                assert_eq!(
                    format_event_helpers
                        .sanitised_file_path_results
                        .get()
                        .unwrap(),
                    "/a/b/c/d/e/f/g"
                );
            }

            assert!(!BUFFERED_WRITER.buffer.lock().unwrap().is_empty());

            let mut buffer: String = BUFFERED_WRITER.buffer.lock().unwrap().clone();
            buffer.pop();

            assert!(String::from_utf8(STANDARD.decode(buffer).unwrap())
                .unwrap()
                .contains("TRIPLE:OS:OS_VERSION unknown:unknown:/a/b/c/d/e/f/g TRACE_ID"));
        }
    }
}

#[cfg(test)]
mod write_spans {
    use super::*;
    use rusty_fork::rusty_fork_test;

    rusty_fork_test! {
        #[test]
        fn no_spans() {
            #[derive(Default, Clone)]
            struct NoSpansHelpers {
                default_helpers: DefaultFormatEventHelpers,
                write_spans_called: Arc<AtomicBool>,
            }

            impl FormatEventHelpers for NoSpansHelpers {
                fn write_spans<S, N>(
                    &self,
                    writer: &mut Writer<'_>,
                    ctx: &FmtContext<'_, S, N>,
                    event: &Event<'_>,
                ) -> std::fmt::Result
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.write_spans_called.store(true, Ordering::Relaxed);
                    self.default_helpers.write_spans(writer, ctx, event)
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(NoSpansHelpers);

                tracing::event!(tracing::Level::ERROR, "test message");

                assert!(!format_event_helpers
                    .write_spans_called
                    .load(Ordering::Relaxed));
            }

            assert!(BUFFERED_WRITER.buffer.lock().unwrap().is_empty());
        }

        #[test]
        fn empty_span_names() {
            #[derive(Default, Clone)]
            struct EmptySpanNamesHelpers {
                default_helpers: DefaultFormatEventHelpers,
                write_spans_called: Arc<AtomicBool>,
                write_spans_result: Arc<OnceLock<std::fmt::Result>>,
                write_spans_buffer: Arc<OnceLock<String>>,
            }

            impl FormatEventHelpers for EmptySpanNamesHelpers {
                fn write_spans<S, N>(
                    &self,
                    writer: &mut Writer<'_>,
                    ctx: &FmtContext<'_, S, N>,
                    event: &Event<'_>,
                ) -> std::fmt::Result
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.write_spans_called.store(true, Ordering::Relaxed);

                    let mut buffer_writer = BufferWriter::default();
                    let mut buffer_writer_writer = Writer::new(&mut buffer_writer);

                    let result =
                        self.default_helpers
                            .write_spans(&mut buffer_writer_writer, ctx, event);

                    self.write_spans_result.set(result).unwrap();

                    self.write_spans_buffer
                        .set(buffer_writer.buffer.lock().unwrap().clone())
                        .unwrap();

                    writer
                        .write_str(buffer_writer.buffer.lock().unwrap().as_str())
                        .unwrap();

                    result
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(EmptySpanNamesHelpers);

                tracing::span!(tracing::Level::ERROR, "").in_scope(|| {
                    tracing::span!(tracing::Level::ERROR, "").in_scope(|| {
                        tracing::span!(tracing::Level::ERROR, "", telemetry = true).in_scope(|| {
                            tracing::span!(tracing::Level::ERROR, "").in_scope(|| {
                                tracing::error!("test message");
                            });
                        });
                    });
                });

                assert!(format_event_helpers
                    .write_spans_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_spans_result
                    .get()
                    .unwrap()
                    .is_ok());

                assert_eq!(
                    format_event_helpers.write_spans_buffer.get().unwrap(),
                    ":::: test message"
                );
            }

            assert!(!BUFFERED_WRITER.buffer.lock().unwrap().is_empty());

            let mut buffer: String = BUFFERED_WRITER.buffer.lock().unwrap().clone();
            buffer.pop();

            assert!(String::from_utf8(STANDARD.decode(buffer).unwrap())
                .unwrap()
                .ends_with(":::: test message"));
        }

        #[test]
        fn empty_fields() {
            #[derive(Default, Clone)]
            struct EmptyFieldsHelpers {
                default_helpers: DefaultFormatEventHelpers,
                write_spans_called: Arc<AtomicBool>,
                write_spans_result: Arc<OnceLock<std::fmt::Result>>,
                write_spans_buffer: Arc<OnceLock<String>>,
            }

            impl FormatEventHelpers for EmptyFieldsHelpers {
                fn write_spans<S, N>(
                    &self,
                    writer: &mut Writer<'_>,
                    ctx: &FmtContext<'_, S, N>,
                    event: &Event<'_>,
                ) -> std::fmt::Result
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.write_spans_called.store(true, Ordering::Relaxed);

                    let mut buffer_writer = BufferWriter::default();
                    let mut buffer_writer_writer = Writer::new(&mut buffer_writer);

                    let result =
                        self.default_helpers
                            .write_spans(&mut buffer_writer_writer, ctx, event);

                    self.write_spans_result.set(result).unwrap();

                    self.write_spans_buffer
                        .set(buffer_writer.buffer.lock().unwrap().clone())
                        .unwrap();

                    writer
                        .write_str(buffer_writer.buffer.lock().unwrap().as_str())
                        .unwrap();

                    result
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(EmptyFieldsHelpers);

                tracing::span!(tracing::Level::ERROR, "empty_fields").in_scope(|| {
                    tracing::span!(tracing::Level::ERROR, "empty_fields_child").in_scope(|| {
                        tracing::span!(tracing::Level::ERROR, "empty_fields_grandchild", telemetry = true).in_scope(|| {
                            tracing::span!(tracing::Level::ERROR, "empty_fields_great_grandchild").in_scope(|| {
                                tracing::error!("test message");
                            });
                        });
                    });
                });

                assert!(format_event_helpers
                    .write_spans_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_spans_result
                    .get()
                    .unwrap()
                    .is_ok());

                assert_eq!(
                    format_event_helpers
                        .write_spans_buffer
                        .get()
                        .unwrap(),
                    "empty_fields:empty_fields_child:empty_fields_grandchild:empty_fields_great_grandchild: test message"
                );
            }

            assert!(!BUFFERED_WRITER.buffer.lock().unwrap().is_empty());

            let mut buffer: String = BUFFERED_WRITER.buffer.lock().unwrap().clone();
            buffer.pop();

            assert!(String::from_utf8(STANDARD.decode(buffer).unwrap())
                .unwrap()
                .ends_with("empty_fields:empty_fields_child:empty_fields_grandchild:empty_fields_great_grandchild: test message"));
        }

        #[test]
        fn has_fields() {
            #[derive(Default, Clone)]
            struct HasFieldsHelpers {
                default_helpers: DefaultFormatEventHelpers,
                write_spans_called: Arc<AtomicBool>,
                write_spans_result: Arc<OnceLock<std::fmt::Result>>,
                write_spans_buffer: Arc<OnceLock<String>>,
            }

            impl FormatEventHelpers for HasFieldsHelpers {
                fn write_spans<S, N>(
                    &self,
                    writer: &mut Writer<'_>,
                    ctx: &FmtContext<'_, S, N>,
                    event: &Event<'_>,
                ) -> std::fmt::Result
                where
                    S: Subscriber + for<'a> LookupSpan<'a>,
                    N: for<'a> FormatFields<'a> + 'static,
                {
                    self.write_spans_called.store(true, Ordering::Relaxed);

                    let mut buffer_writer = BufferWriter::default();
                    let mut buffer_writer_writer = Writer::new(&mut buffer_writer);

                    let result =
                        self.default_helpers
                            .write_spans(&mut buffer_writer_writer, ctx, event);

                    self.write_spans_result.set(result).unwrap();

                    self.write_spans_buffer
                        .set(buffer_writer.buffer.lock().unwrap().clone())
                        .unwrap();

                    writer
                        .write_str(buffer_writer.buffer.lock().unwrap().as_str())
                        .unwrap();

                    result
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(HasFieldsHelpers);

                tracing::span!(tracing::Level::ERROR, "has_fields").in_scope(|| {
                    tracing::span!(tracing::Level::ERROR, "has_fields_child", name1 = "value1").in_scope(|| {
                        tracing::span!(tracing::Level::ERROR, "has_fields_grandchild", telemetry = true, name2 = "value2").in_scope(|| {
                            tracing::span!(tracing::Level::ERROR, "has_fields_great_grandchild", name3 = "value3").in_scope(|| {
                                tracing::error!("test message");
                            });
                        });
                    });
                });

                assert!(format_event_helpers
                    .write_spans_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_spans_result
                    .get()
                    .unwrap()
                    .is_ok());

                assert_eq!(
                    format_event_helpers.write_spans_buffer.get().unwrap(),
                    r#"has_fields:has_fields_child{name1="value1"}:has_fields_grandchild{name2="value2"}:has_fields_great_grandchild{name3="value3"}: test message"#
                );
            }

            assert!(!BUFFERED_WRITER.buffer.lock().unwrap().is_empty());

            let mut buffer: String = BUFFERED_WRITER.buffer.lock().unwrap().clone();
            buffer.pop();

            assert!(String::from_utf8(STANDARD.decode(buffer).unwrap())
                .unwrap()
                .ends_with(r#"has_fields:has_fields_child{name1="value1"}:has_fields_grandchild{name2="value2"}:has_fields_great_grandchild{name3="value3"}: test message"#));
        }
    }
}

#[cfg(test)]
mod write_encoded_buffer {
    use super::*;
    use rusty_fork::rusty_fork_test;

    rusty_fork_test! {
        #[test]
        fn write_str_failed() {
            #[derive(Default)]
            struct WriteFailedWriter;

            impl std::fmt::Write for WriteFailedWriter {
                fn write_str(&mut self, _s: &str) -> std::fmt::Result {
                    Err(std::fmt::Error)
                }
            }

            #[derive(Default, Clone)]
            struct WriteStrFailedHelpers {
                default_helpers: DefaultFormatEventHelpers,
                write_encoded_buffer_called: Arc<AtomicBool>,
                write_encoded_buffer_result: Arc<OnceLock<std::fmt::Result>>,
            }

            impl FormatEventHelpers for WriteStrFailedHelpers {
                fn write_encoded_buffer(
                    &self,
                    _writer: &mut Writer<'_>,
                    buffer: &str,
                ) -> std::fmt::Result {
                    self.write_encoded_buffer_called
                        .store(true, Ordering::Relaxed);

                    let mut binding = WriteFailedWriter;
                    let mut writer = Writer::new(&mut binding);

                    let result = self
                        .default_helpers
                        .write_encoded_buffer(&mut writer, buffer);

                    self.write_encoded_buffer_result.set(result).unwrap();

                    result
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(WriteStrFailedHelpers);

                tracing::span!(tracing::Level::ERROR, "write_str_failed", telemetry = true)
                    .in_scope(|| {
                        tracing::error!("test message");
                    });

                assert!(format_event_helpers
                    .write_encoded_buffer_called
                    .load(Ordering::Relaxed));

                assert_eq!(
                    format_event_helpers
                        .write_encoded_buffer_result
                        .get()
                        .unwrap()
                        .err(),
                    Some(std::fmt::Error)
                );
            }

            assert!(BUFFERED_WRITER.buffer.lock().unwrap().is_empty());
        }

        #[test]
        fn empty_writer_empty_buffer() {
            #[derive(Default, Clone)]
            struct EmptyWriterEmptyBufferHelpers {
                default_helpers: DefaultFormatEventHelpers,
                write_encoded_buffer_called: Arc<AtomicBool>,
                write_encoded_buffer_result: Arc<OnceLock<std::fmt::Result>>,
            }

            impl FormatEventHelpers for EmptyWriterEmptyBufferHelpers {
                fn write_encoded_buffer(
                    &self,
                    writer: &mut Writer<'_>,
                    buffer: &str,
                ) -> std::fmt::Result {
                    self.write_encoded_buffer_called
                        .store(true, Ordering::Relaxed);

                    let result = self.default_helpers.write_encoded_buffer(writer, buffer);
                    self.write_encoded_buffer_result.set(result).unwrap();

                    result
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(EmptyWriterEmptyBufferHelpers);

                tracing::span!(
                    tracing::Level::ERROR,
                    "empty_writer_empty_buffer",
                    telemetry = true
                )
                .in_scope(|| {
                    tracing::error!("");
                });

                assert!(format_event_helpers
                    .write_encoded_buffer_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_encoded_buffer_result
                    .get()
                    .unwrap()
                    .is_ok());
            }

            assert!(!BUFFERED_WRITER.buffer.lock().unwrap().is_empty());

            let mut buffer: String = BUFFERED_WRITER.buffer.lock().unwrap().clone();
            buffer.pop();

            assert!(String::from_utf8(STANDARD.decode(buffer).unwrap())
                .unwrap()
                .ends_with("empty_writer_empty_buffer: "));
        }

        #[test]
        fn empty_writer() {
            #[derive(Default, Clone)]
            struct EmptyWriterHelpers {
                default_helpers: DefaultFormatEventHelpers,
                write_encoded_buffer_called: Arc<AtomicBool>,
                write_encoded_buffer_result: Arc<OnceLock<std::fmt::Result>>,
            }

            impl FormatEventHelpers for EmptyWriterHelpers {
                fn write_encoded_buffer(
                    &self,
                    writer: &mut Writer<'_>,
                    buffer: &str,
                ) -> std::fmt::Result {
                    self.write_encoded_buffer_called
                        .store(true, Ordering::Relaxed);

                    let result = self.default_helpers.write_encoded_buffer(writer, buffer);
                    self.write_encoded_buffer_result.set(result).unwrap();

                    result
                }
            }

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(EmptyWriterHelpers);

                tracing::span!(tracing::Level::ERROR, "empty_writer", telemetry = true).in_scope(|| {
                    tracing::error!("test message");
                });

                assert!(format_event_helpers
                    .write_encoded_buffer_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_encoded_buffer_result
                    .get()
                    .unwrap()
                    .is_ok());
            }

            assert!(!BUFFERED_WRITER.buffer.lock().unwrap().is_empty());

            let mut buffer: String = BUFFERED_WRITER.buffer.lock().unwrap().clone();
            buffer.pop();

            assert!(String::from_utf8(STANDARD.decode(buffer).unwrap())
                .unwrap()
                .contains("empty_writer: test message"));
        }

        #[test]
        fn empty_buffer() {
            #[derive(Default, Clone)]
            struct EmptyBufferHelpers {
                default_helpers: DefaultFormatEventHelpers,
                write_encoded_buffer_called: Arc<AtomicBool>,
                write_encoded_buffer_result: Arc<OnceLock<std::fmt::Result>>,
            }

            impl FormatEventHelpers for EmptyBufferHelpers {
                fn write_encoded_buffer(
                    &self,
                    writer: &mut Writer<'_>,
                    buffer: &str,
                ) -> std::fmt::Result {
                    self.write_encoded_buffer_called
                        .store(true, Ordering::Relaxed);

                    let result = self.default_helpers.write_encoded_buffer(writer, buffer);
                    self.write_encoded_buffer_result.set(result).unwrap();

                    result
                }
            }

            BUFFERED_WRITER
                .buffer
                .lock()
                .unwrap()
                .push_str("ZW1wdHlfYnVmZmVy\n");

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(EmptyBufferHelpers);

                tracing::span!(tracing::Level::ERROR, "empty_buffer", telemetry = true).in_scope(|| {
                    tracing::error!("");
                });

                assert!(format_event_helpers
                    .write_encoded_buffer_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_encoded_buffer_result
                    .get()
                    .unwrap()
                    .is_ok());
            }

            assert!(!BUFFERED_WRITER.buffer.lock().unwrap().is_empty());

            let mut buffer: String = BUFFERED_WRITER.buffer.lock().unwrap().clone();
            buffer.pop();

            let lines = buffer.split("\n").collect::<Vec<&str>>();
            assert_eq!(lines.len(), 2);
            assert_eq!(lines[0], "ZW1wdHlfYnVmZmVy");

            assert!(String::from_utf8(STANDARD.decode(lines[1]).unwrap())
                .unwrap()
                .ends_with("empty_buffer: "));
        }

        #[test]
        fn ok() {
            #[derive(Default, Clone)]
            struct OkHelpers {
                default_helpers: DefaultFormatEventHelpers,
                write_encoded_buffer_called: Arc<AtomicBool>,
                write_encoded_buffer_result: Arc<OnceLock<std::fmt::Result>>,
            }

            impl FormatEventHelpers for OkHelpers {
                fn write_encoded_buffer(
                    &self,
                    writer: &mut Writer<'_>,
                    buffer: &str,
                ) -> std::fmt::Result {
                    self.write_encoded_buffer_called
                        .store(true, Ordering::Relaxed);

                    let result = self.default_helpers.write_encoded_buffer(writer, buffer);
                    self.write_encoded_buffer_result.set(result).unwrap();

                    result
                }
            }

            BUFFERED_WRITER.buffer.lock().unwrap().push_str("b2s=\n");

            {
                let (_flush_guard, _default_guard, format_event_helpers) =
                    generate_test_formatter!(OkHelpers);

                tracing::span!(tracing::Level::ERROR, "ok", telemetry = true).in_scope(|| {
                    tracing::error!("test message");
                });

                assert!(format_event_helpers
                    .write_encoded_buffer_called
                    .load(Ordering::Relaxed));

                assert!(format_event_helpers
                    .write_encoded_buffer_result
                    .get()
                    .unwrap()
                    .is_ok());
            }

            assert!(!BUFFERED_WRITER.buffer.lock().unwrap().is_empty());

            let mut buffer: String = BUFFERED_WRITER.buffer.lock().unwrap().clone();
            buffer.pop();

            let lines = buffer.split("\n").collect::<Vec<&str>>();
            assert_eq!(lines.len(), 2);
            assert_eq!(lines[0], "b2s=");

            assert!(String::from_utf8(STANDARD.decode(lines[1]).unwrap())
                .unwrap()
                .contains("ok: test message"));
        }
    }
}
