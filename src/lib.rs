pub mod errors;
pub mod file_watcher;
pub mod systeminfo_watcher;

use crate::errors::TelemetryError;

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use dirs::home_dir;
use nix::{
    errno::Errno,
    fcntl::{Flock, FlockArg},
    sys::stat,
    unistd::{chdir, close, dup2, fork, setsid, sysconf, SysconfVar},
};
use regex::Regex;
use std::{
    env::{var, var_os},
    fs::{create_dir_all, File, OpenOptions},
    io::{stderr, stdout, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::exit,
    sync::LazyLock,
};
use sysinfo::System;
use tracing::{
    span::{Entered, Id, Record},
    Event, Span, Subscriber,
};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::layer::Context;
use tracing_subscriber::{
    fmt::{
        format::{DefaultFields, FormatEvent, FormatFields, Writer},
        FmtContext, FormattedFields, Layer,
    },
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
    Layer as LayerTrait, Registry,
};

pub type Result<T> = std::result::Result<T, TelemetryError>;

/// Define a prelude to minimise a simple API
///
/// Exports the following names:
///
/// - `telemetry_init`
/// - `TelemetryLayer`
///
/// - `trace!`
/// - `debug!`
/// - `info!`
/// - `warn!`
/// - `error!`
///
/// - `event!`
/// - `span!`
/// - `Level`
pub mod prelude {
    pub use crate::{
        debug, error, event, info, span, telemetry_init, trace, warn, Level, TelemetryLayer,
    };
}

/// Convenience function to do everything needed for telemetry in one step
///
/// This function does the following:
/// - Creates a new `TelemetryLayer` `tracing` `Layer`
/// - Sets it as the global default `tracing` `Subscriber`
/// - Creates the root `span` called "main"
/// - Enters the "main" `span`
/// - Create a `FileWatcher` and starts it
///
/// Warning: this function should only be called in applications and not within
/// libraries as it sets the global default subscriber, clobbering any set by
/// the application.
///
/// ```rust
/// use fuel_telemetry::prelude::*;
///
/// telemetry_init()?;
/// ```
pub fn telemetry_init() -> Result<()> {
    static TELEMETRY_INIT: LazyLock<Result<(WorkerGuard, Span)>> = LazyLock::new(|| {
        let guard = TelemetryLayer::new_global_default_with_filewatcher()?;
        let main_span = span!(Level::ERROR, "main", telemetry = true);
        Ok((guard, main_span))
    });

    static TELEMETRY_MAIN_GUARD: LazyLock<Result<Entered>> = LazyLock::new(|| {
        let (_, main_span) = TELEMETRY_INIT.as_ref()?;
        Ok(main_span.enter())
    });

    TELEMETRY_MAIN_GUARD.as_ref()?;

    Ok(())
}

/// Re-export tracing macros for convenience
///
/// This module re-exports the following macros from the `tracing` crate:
///
/// - `trace!`
/// - `info!`
/// - `debug!`
/// - `warn!`
/// - `error!`
///
/// - `event!`
/// - `span!`
/// - `Level`
pub use tracing::{debug, error, event, info, span, trace, warn, Level};

//
// Crate static configuration
//

/// Telemetry's global configuration
///
/// This struct contains the configuration for telemetry, to be used here and
/// within its underlying modules.
pub struct TelemetryConfig {
    // The path to the fuelup tmp directory
    fuelup_tmp: String,
    // The path to the fuelup log directory
    fuelup_log: String,
}

/// Get the global telemetry configuration
///
/// This function returns the global `'static` telemetry configuration.
///
/// ```rust
/// use fuel_telemetry::telemetry_config;
///
/// let telemetry_config = telemetry_config()?;
/// ```
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

        // Tries to set the fuelup home directory from the environment, falling
        // back to the $HOME/.fuelup
        let fuelup_home = var_os(fuelup_home_env.name)
            .map(PathBuf::from)
            .or_else(|| home_dir().map(|dir| dir.join(fuelup_home_env.default)))
            .ok_or(TelemetryError::UnreachableHomeDir)?
            .into_os_string()
            .into_string()
            .map_err(|e| TelemetryError::InvalidHomeDir(e.to_string_lossy().into()))?;

        // Tries to set the fuelup tmp directory from the environment, falling
        // back to $FUELUP_HOME/tmp
        let fuelup_tmp = var_os(fuelup_tmp_env.name)
            .unwrap_or_else(|| {
                PathBuf::from(fuelup_home.clone())
                    .join(fuelup_tmp_env.default)
                    .into_os_string()
            })
            .into_string()
            .map_err(|e| TelemetryError::InvalidTmpDir(e.to_string_lossy().into()))?;

        // Tries to set the fuelup log directory from the environment, falling
        // back to $FUELUP_HOME/log
        let fuelup_log = var_os(fuelup_log_env.name)
            .unwrap_or_else(|| {
                PathBuf::from(fuelup_home.clone())
                    .join(fuelup_log_env.default)
                    .into_os_string()
            })
            .into_string()
            .map_err(|e| TelemetryError::InvalidLogDir(e.to_string_lossy().into()))?;

        // Create the fuelup tmp and log directories if they don't exist
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

/// A helper struct to get environment variables with a default value
pub struct EnvSetting {
    /// The name of the environment variable
    name: &'static str,
    /// The default value of the environment variable
    default: &'static str,
}

impl EnvSetting {
    /// Creates a new `EnvSetting`
    ///
    /// This function creates a new `EnvSetting` with the given name and default value.
    ///
    /// ```rust
    /// use fuel_telemetry::EnvSetting;
    ///
    /// let env_setting = EnvSetting::new("FUELUP_HOME", ".fuelup");
    /// ```
    pub fn new(name: &'static str, default: &'static str) -> Self {
        Self { name, default }
    }

    /// Gets the environment variable with a default value
    ///
    /// This function gets the environment variable with a default value.
    ///
    /// ```rust
    /// use fuel_telemetry::EnvSetting;
    ///
    /// let env_setting = EnvSetting::new("FUELUP_HOME", ".fuelup");
    /// let fuelup_home = env_setting.get();
    /// ```
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
    /// Create a new `TelemetryLayer`.
    ///
    /// This `tracing` `Layer` is to be used along with the `tracing` crate, and
    /// composess with other `Layer`s to create a subscriber.
    ///
    /// Returns a `TelemetryLayer` and a drop guard. Here, the drop guard will
    /// flush any remaining telemetry to the file.
    ///
    /// Warning: this function does not create a `FileWatcher` and so although
    /// telemetry files will be written to disk when `telemetry=true` for a
    /// span, they will not be sent to InfluxDB
    ///
    /// ```rust
    /// use fuel_telemetry::TelemetryLayer;
    /// use tracing_subscriber::prelude::*;
    ///
    /// let (telemetry_layer, _guard) = TelemetryLayer::new().unwrap();
    /// tracing_subscriber::registry().with(telemetry_layer).init();
    ///
    /// info!("Hello from telemetry");
    /// ```
    pub fn new() -> Result<(Self, WorkerGuard)> {
        let (writer, guard) = {
            if var("FUELUP_NO_TELEMETRY").is_ok() {
                // If telemetry is disabled, discards all output
                tracing_appender::non_blocking(std::io::sink())
            } else {
                // If telemetry is enabled, telemetry will be written to a file
                // that is rotated hourly with the filename format:
                // "$FUELUP_TMP/<crate|bucket>.telemetry.YYYY-MM-DD-HH"
                //
                // Also, the bucket name can't be set within `telemetry_config()` as
                // we need to be able to set it dynamically by Watchers
                tracing_appender::non_blocking(tracing_appender::rolling::hourly(
                    PathBuf::from(telemetry_config()?.fuelup_tmp.clone()),
                    format!(
                        "{}.telemetry",
                        var("INFLUXDB_BUCKET").unwrap_or(env!("CARGO_CRATE_NAME").to_string())
                    ),
                ))
            }
        };

        // We need to disable ANSI codes as it breaks InfluxDB parsing
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
    /// Warning: this function should only be called in applications and not
    /// within libraries as it will clobber any set by the application.
    ///
    /// ```rust
    /// use fuel_telemetry::TelemetryLayer;
    ///
    /// let (telemetry_layer, _guard) = TelemetryLayer::new().unwrap();
    /// telemetry_layer.set_global_default();
    /// ```
    pub fn set_global_default(self) {
        tracing_subscriber::registry().with(self.inner).init();
    }

    /// A convenience function to do `new()` followed by creating and starting a
    /// `FileWatcher` within a single step.
    ///
    /// ```rust
    /// use fuel_telemetry::TelemetryLayer;
    /// use tracing_subscriber::prelude::*;
    ///
    /// let (telemetry_layer, _guard) = TelemetryLayer::new_with_filewatcher()?;
    /// tracing_subscriber::registry().with(telemetry_layer).init();
    /// ```
    pub fn new_with_filewatcher() -> Result<(Self, WorkerGuard)> {
        // Warning: We need to create the `FileWatcher` before the `TelemetryLayer`
        // as there is a race condition in the thread runtime of `tracing` and
        // the tokio runtime of `Reqwest`. Swapping order of the two could lead to
        // possible deadlocks.
        let mut file_watcher = file_watcher::FileWatcher::new()?;
        file_watcher.start()?;

        let (layer, guard) = Self::new()?;
        Ok((layer, guard))
    }

    /// A convenience function to do `new()` and `set_global_default()` within a
    /// single step.
    ///
    /// Warning: this function should only be called in applications and not
    /// within libraries as it will clobber any set by the application.
    ///
    /// Warning: this function does not create a `FileWatcher` and so although
    /// telemetry files will be written to disk, they will not be sent to
    /// InfluxDB
    ///
    /// ```rust
    /// use fuel_telemetry::TelemetryLayer;
    ///
    /// let _guard = TelemetryLayer::new_global_default().unwrap();
    /// ```
    pub fn new_global_default() -> Result<WorkerGuard> {
        let (layer, guard) = Self::new()?;
        layer.set_global_default();
        Ok(guard)
    }

    /// A convenience function to do `new_global_default()` followed by creating
    /// and starting a `FileWatcher` within a single step.
    ///
    /// Warning: this function should only be called in applications and not
    /// within libraries as it will clobber any set by the application.
    ///
    /// ```rust
    /// use fuel_telemetry::TelemetryLayer;
    ///
    /// let _guard = TelemetryLayer::new_global_default_with_filewatcher()?;
    /// ```
    pub fn new_global_default_with_filewatcher() -> Result<WorkerGuard> {
        // Warning: We need to create the `FileWatcher` before the `TelemetryLayer`
        // as there is a race condition in the thread runtime of `tracing` and
        // the tokio runtime of `Reqwest`. Swapping order of the two could lead to
        // possible deadlocks.
        let mut file_watcher = file_watcher::FileWatcher::new()?;
        file_watcher.start()?;

        let guard = Self::new_global_default()?;
        Ok(guard)
    }
}

// Implement the `Layer` trait for `TelemetryLayer`
//
// Here we simply proxy calls to the inner layer.
impl LayerTrait<Registry> for TelemetryLayer {
    fn on_close(&self, id: Id, ctx: Context<'_, Registry>) {
        self.inner.on_close(id, ctx);
    }

    fn on_enter(&self, id: &span::Id, ctx: Context<'_, Registry>) {
        self.inner.on_enter(id, ctx);
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, Registry>) {
        self.inner.on_event(event, ctx);
    }

    fn on_exit(&self, id: &span::Id, ctx: Context<'_, Registry>) {
        self.inner.on_exit(id, ctx);
    }

    fn on_id_change(&self, old: &span::Id, new: &span::Id, ctx: Context<'_, Registry>) {
        self.inner.on_id_change(old, new, ctx);
    }

    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, Registry>) {
        self.inner.on_new_span(attrs, id, ctx);
    }

    fn on_follows_from(&self, span: &span::Id, follows: &span::Id, ctx: Context<'_, Registry>) {
        self.inner.on_follows_from(span, follows, ctx);
    }

    fn on_record(&self, span: &Id, values: &Record<'_>, ctx: Context<'_, Registry>) {
        self.inner.on_record(span, values, ctx);
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
    // Caches the system triple used for every event
    triple: String,
    // Caches the operating system name used for every event
    os: String,
    // Caches the operating system version used for every event
    os_version: String,
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
    /// 2021-08-31T14:00:00.000000Z ERROR x86_64-apple-darwin:Arch Linux:6.12.3-arch1-1 fuel-telemetry:0.1.0:fuelup/src/main.rs root:span1:span2: field1="val1" "A test message"
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
            "{} {:>5} {}:{}:{} {}:{}:{} ",
            Utc::now().format("%Y-%m-%dT%H:%M:%S%.9fZ"),
            event.metadata().level(),
            self.triple,
            self.os,
            self.os_version,
            var("INFLUXDB_BUCKET").unwrap_or(env!("CARGO_CRATE_NAME").to_string()),
            env!("CARGO_PKG_VERSION"),
            event.metadata().file().unwrap_or("unknown"),
        )?;

        // For each span in the event, write out the span its fields to the temporary writer
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

/// Enforce a singleton to ensure we are the only `FileWatcher` running and
/// submitting telemetry to InfluxDB
fn enforce_singleton(filename: &Path) -> Result<Flock<File>> {
    let lockfile = OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename)?;

    let lock = match Flock::lock(lockfile.try_clone()?, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => lock,
        Err((_, Errno::EWOULDBLOCK)) => {
            // Silently exit as another running `FileWatcher` was found
            exit(0);
        }
        Err((_, e)) => return Err(TelemetryError::from(e)),
    };

    Ok(lock)
}

/// Daemonise the current process
///
/// This function forks and has the parent immediately return. The forked off
/// child then follows the common "double-fork" method of daemonising.
fn daemonise(log_filename: &PathBuf) -> Result<bool> {
    stdout().flush()?;
    stderr().flush()?;

    // Return if we are the parent
    if unsafe { fork()? }.is_parent() {
        return Ok(true);
    };

    // To prevent us from becoming a zombie when we die, we fork then kill the
    // parent so that we are immediately inherited by init/systemd. Doing so, we
    // are guaranteed to be reaped on exit.
    //
    // Also, doing this guarantees that we are not the group leader, which is
    // required to create a new session (i.e setsid() will fail otherwise)
    if unsafe { fork()? }.is_parent() {
        exit(0);
    }

    // Creating a new session means we won't receive signals to the original
    // group or session (e.g. hitting CTRL-C to break a command pipeline)
    setsid()?;

    // As session leader, we now fork then follow the child again to guarantee
    // we cannot re-acquire a terminal
    if unsafe { fork()? }.is_parent() {
        exit(0);
    }

    // Setup stdio to write errors to the logfile while discarding any IO to
    // the controlling terminal
    setup_stdio(
        Path::new(&telemetry_config()?.fuelup_tmp)
            .join(log_filename)
            .to_str()
            .ok_or(TelemetryError::InvalidLogFile(
                telemetry_config()?.fuelup_tmp.clone(),
                log_filename.clone(),
            ))?,
    )?;

    // The current working directory needs to be set to root so that we don't
    // prevent any unmounting of the filesystem leading up to the directory we
    // started in
    chdir("/")?;

    // We close all file descriptors since any currently opened were inherited
    // from the parent process which we don't care about. Not doing so leaks
    // open file descriptors which could lead to exhaustion.

    // Skip the first three because we deal with stdio later. Here, 1024 is a
    // safe value i.e MIN(Legacy Linux, MacOS)
    let max_fd = sysconf(SysconfVar::OPEN_MAX)?.unwrap_or(1024) as i32;

    for fd in 3..=max_fd {
        match close(fd) {
            Ok(()) | Err(Errno::EBADF) => {}
            Err(e) => return Err(TelemetryError::from(e)),
        }
    }

    // Clear the umask so that files we create aren't too permission-restricive
    stat::umask(stat::Mode::empty());

    Ok(false)
}

/// Setup stdio for the `FileWatcher`
///
/// This function redirects stderr to its logfile while discarding any IO to the
/// controlling terminal.
pub(crate) fn setup_stdio(log_filename: &str) -> Result<()> {
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_filename)?;

    // Redirect stderr to the logfile
    dup2(log_file.as_raw_fd(), 2)?;

    // Get a filehandle to /dev/null
    let dev_null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;

    // Redirect stdin, stdout to /dev/null
    dup2(dev_null.as_raw_fd(), 0)?;
    dup2(dev_null.as_raw_fd(), 1)?;

    Ok(())
}