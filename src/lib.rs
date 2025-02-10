pub mod errors;
pub mod file_watcher;

use crate::errors::TelemetryError;

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use dirs::home_dir;
use regex::Regex;
use std::{
    env::{var, var_os},
    fs::create_dir_all,
    path::PathBuf,
    sync::LazyLock,
};
use sysinfo::System;
use tracing::{Event, Subscriber};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::{
    fmt::{
        format::{DefaultFields, FormatEvent, FormatFields, Writer},
        FmtContext, FormattedFields, Layer,
    },
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
    Registry,
};

pub type Result<T> = std::result::Result<T, TelemetryError>;

/// Re-export tracing macros for convenience
///
/// This module re-exports the following macros from the `tracing` crate:
///
/// - `debug!`
/// - `error!`
/// - `event!`
/// - `info!`
/// - `span!`
/// - `trace!`
/// - `warn!`
/// - `Level`
pub use tracing::{debug, error, event, info, span, trace, warn, Level};

//
// Crate static configuration
//

pub struct TelemetryConfig {
    fuelup_tmp: String,
    fuelup_log: String,
}

pub fn telemetry_config() -> Result<&'static TelemetryConfig> {
    pub static TELEMETRY_CONFIG: LazyLock<Result<TelemetryConfig>> = LazyLock::new(|| {
        let fuelup_home_env = EnvSetting {
            name: "FUELUP_HOME",
            default: ".fuelup",
        };

        let fuelup_tmp_env = EnvSetting {
            name: "FUELUP_TMP",
            default: "tmp",
        };

        let fuelup_log_env = EnvSetting {
            name: "FUELUP_LOG",
            default: "log",
        };

        let fuelup_home = var_os(fuelup_home_env.name)
            .map(PathBuf::from)
            .or_else(|| home_dir().map(|dir| dir.join(fuelup_home_env.default)))
            .ok_or(TelemetryError::UnreachableHomeDir)?
            .into_os_string()
            .into_string()
            .map_err(|e| TelemetryError::InvalidHomeDir(e.to_string_lossy().into()))?;

        let fuelup_tmp = var_os(fuelup_tmp_env.name)
            .unwrap_or_else(|| {
                PathBuf::from(fuelup_home.clone())
                    .join(fuelup_tmp_env.default)
                    .into_os_string()
            })
            .into_string()
            .map_err(|e| TelemetryError::InvalidTmpDir(e.to_string_lossy().into()))?;

        let fuelup_log = var_os(fuelup_log_env.name)
            .unwrap_or_else(|| {
                PathBuf::from(fuelup_home.clone())
                    .join(fuelup_log_env.default)
                    .into_os_string()
            })
            .into_string()
            .map_err(|e| TelemetryError::InvalidLogDir(e.to_string_lossy().into()))?;

        create_dir_all(&fuelup_tmp)?;
        create_dir_all(&fuelup_log)?;

        Ok(TelemetryConfig {
            fuelup_tmp,
            fuelup_log,
        })
    });

    TELEMETRY_CONFIG
        .as_ref()
        .map_err(|e| TelemetryError::InvalidConfig(e.to_string()))
}

pub struct EnvSetting {
    name: &'static str,
    default: &'static str,
}

impl EnvSetting {
    pub fn new(name: &'static str, default: &'static str) -> Self {
        Self { name, default }
    }

    pub fn get(&self) -> String {
        var(self.name).unwrap_or_else(|_| self.default.to_string())
    }
}

//
// TelemetryLayer
//

/// A `tracing` `Layer` to generate telemetry to be later consumed into InfluxDB
///
/// This `tracing` `Layer` formats telemetry and stores the output in a known
/// location ($FUEL_HOME/tmp/<crate>.telemetry), ready for ingestion by an
/// InfluxDB collector.
pub struct TelemetryLayer {
    inner: Layer<Registry, DefaultFields, TelemetryFormatter, NonBlocking>,
}

impl TelemetryLayer {
    /// Creates a new `TelemetryLayer`.
    ///
    /// This `tracing` `Layer` is to be used along with the `tracing` crate, and
    /// composess with other `Layer`s to create a subscriber.
    ///
    /// Returns a `TelemetryLayer` and a drop guard. Here, the drop guard will
    /// flush any remaining telemetry to the file.
    ///
    /// ```rust
    /// use forc_tracing::{TelemetryLayer, info};
    ///
    /// let (telemetry_layer, _guard) = TelemetryLayer::new().unwrap();
    /// tracing_subscriber::registry().with(telemetry_layer).init();
    ///
    /// info!("Hello from telemetry");
    /// ```
    pub fn new() -> Result<(Self, WorkerGuard)> {
        let (writer, guard) = {
            if var("FUELUP_NO_TELEMETRY").is_ok() {
                tracing_appender::non_blocking(std::io::sink())
            } else {
                tracing_appender::non_blocking(tracing_appender::rolling::hourly(
                    PathBuf::from(telemetry_config()?.fuelup_tmp.clone()),
                    format!("{}.telemetry", env!("CARGO_CRATE_NAME")),
                ))
            }
        };

        let inner = tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .with_ansi(false)
            .event_format(TelemetryFormatter::new());

        Ok((Self { inner }, guard))
    }

    /// Sets the `TelemetryLayer` as the global default subscriber.
    ///
    /// This function sets the `TelemetryLayer` as the global default subscriber
    /// for all tracing events within the thread.
    ///
    /// Note: this should only be used within binaries so that there are no
    /// layer-subscriber conflicts between dependency libraries.
    ///
    /// ```rust
    /// use forc_tracing::{TelemetryLayer, info};
    ///
    /// let (telemetry_layer, _guard) = TelemetryLayer::new().unwrap();
    /// telemetry_layer.set_global_default();
    ///
    /// info!("Hello from forc_telemetry");
    /// ```
    pub fn set_global_default(self) {
        tracing_subscriber::registry().with(self.inner).init();
    }

    /// Create a `TelemetryLayer` and sets it as the global default subscriber.
    ///
    /// A convenience function to do the create and set within a single step.
    ///
    /// ```rust
    /// use forc_tracing::TelemetryLayer;
    ///
    /// let _guard = TelemetryLayer::new_global_default().unwrap();
    /// ```
    pub fn new_global_default() -> Result<WorkerGuard> {
        let (layer, guard) = Self::new()?;
        layer.set_global_default();
        Ok(guard)
    }

    pub fn new_global_default_with_filewatcher() -> Result<WorkerGuard> {
        let (layer, guard) = Self::new()?;
        layer.set_global_default();
        let file_watcher = file_watcher::FileWatcher::new()?;
        file_watcher.start()?;
        Ok(guard)
    }
}

//
// TelemetryFormatter
//

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
struct TelemetryFormatter {
    triple: String,
    os: String,
    os_version: String,
}

impl TelemetryFormatter {
    /// Creates a new `TelemetryFormatter`.
    ///
    /// This `tracing` `Formatter` is to be used along with the `tracing` crate,
    /// and is used to set the `Event` format.
    ///
    /// ```rust
    /// use forc_tracing::TelemetryFormatter;
    ///
    /// let telemetry_formatter = TelemetryFormatter::new();
    ///
    /// tracing_subscriber::fmt::layer()
    ///     .event_format(telemetry_formatter);
    /// ```
    pub fn new() -> Self {
        Self {
            os: System::name().unwrap_or_default(),
            os_version: System::kernel_version().unwrap_or_default(),
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
    /// <timestamp> <level> <triple>:<os>:<os-version> <crate>:<version>:<file> <spans> <fields>
    ///
    /// e.g:
    ///
    /// ```text
    /// 2021-08-31T14:00:00.000000Z ERROR x86_64-apple-darwin:Arch Linux:6.12.3-arch1-1 forc-tracing:0.1.0:fuelup/src/main.rs root:span1:span2: field1="val1" "A test message"
    /// ```
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let mut wants_telemetry = false;

        for span in ctx.event_scope().into_iter().flatten() {
            if let Some(fields) = span.extensions().get::<FormattedFields<N>>() {
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

        let mut buffer = String::new();
        let mut tmp_writer = Writer::new(&mut buffer);

        write!(
            &mut tmp_writer,
            "{} {:>5} {}:{}:{} {}:{}:{} ",
            Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ"),
            event.metadata().level(),
            self.triple,
            self.os,
            self.os_version,
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            event.metadata().file().unwrap_or("unknown"),
        )?;

        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                write!(tmp_writer, "{}", span.name())?;

                if let Some(fields) = span.extensions().get::<FormattedFields<N>>() {
                    if !fields.is_empty() {
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

        ctx.field_format()
            .format_fields(tmp_writer.by_ref(), event)?;

        let encoded = STANDARD.encode(&buffer);
        writer.write_str(&encoded)?;
        writer.write_str("\n")
    }
}
