pub mod errors;
pub mod file_watcher;
pub mod systeminfo_watcher;
pub mod telemetry_formatter;
pub mod telemetry_layer;

pub use errors::TelemetryError;
pub use macros::{new, new_with_watchers, new_with_watchers_and_init};
pub use telemetry_layer::TelemetryLayer;
pub use tracing::{debug, error, event, info, span, trace, warn, Level};

pub mod prelude {
    pub use crate::{
        debug, debug_telemetry, error, error_telemetry, event, info, info_telemetry, span,
        span_telemetry, trace, trace_telemetry, warn, warn_telemetry, Level, TelemetryLayer,
    };
}

// Re-export tracing so proc_macros can use them
pub use tracing as __reexport_tracing;
pub use tracing_appender::non_blocking::WorkerGuard as __reexport_WorkerGuard;
pub use tracing_subscriber as __reexport_tracing_subscriber;
pub use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt as __reexport_tracing_subscriber_SubscriberExt;
pub use tracing_subscriber::util::SubscriberInitExt as __reexport_tracing_subscriber_SubscriberInitExt;

use dirs::home_dir;
use nix::{
    errno::Errno,
    fcntl::{Flock, FlockArg},
    sys::stat,
    unistd::{chdir, close, dup2, fork, setsid, sysconf, SysconfVar},
};
use std::{
    env::{var, var_os},
    fs::{create_dir_all, File, OpenOptions},
    io::{stderr, stdout, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::exit,
    sync::LazyLock,
};

// Result type for the crate
pub type Result<T> = std::result::Result<T, TelemetryError>;

//
// Crate static configuration
//

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

//
// Macros
//

/// Enters a temporary `Span` with telemetry enabled, then generates an `Event`
///
/// Note: The `Span` name is currently hardcoded to "auto" as `tracing::span!`
/// requires the name to be `const` as internally it is evaluated as a static,
/// however getting the caller's function name in statics is experimental.
#[macro_export]
macro_rules! span_telemetry {
    ($level:expr, $($arg:tt)*) => {
        fuel_telemetry::__reexport_tracing::span!($level, "auto", telemetry = true).in_scope(|| {
            fuel_telemetry::__reexport_tracing::event!($level, $($arg)*)
        })
    }
}

#[macro_export]
macro_rules! error_telemetry {
    ($($arg:tt)*) => {{
        span_telemetry!(fuel_telemetry::__reexport_tracing::Level::ERROR, $($arg)*);
    }}
}

#[macro_export]
macro_rules! warn_telemetry {
    ($($arg:tt)*) => {{
        span_telemetry!(fuel_telemetry::__reexport_tracing::Level::WARN, $($arg)*);
    }}
}

#[macro_export]
macro_rules! info_telemetry {
    ($($arg:tt)*) => {{
        span_telemetry!(fuel_telemetry::__reexport_tracing::Level::INFO, $($arg)*);
    }}
}

#[macro_export]
macro_rules! debug_telemetry {
    ($($arg:tt)*) => {{
        span_telemetry!(fuel_telemetry::__reexport_tracing::Level::DEBUG, $($arg)*);
    }}
}

#[macro_export]
macro_rules! trace_telemetry {
    ($($arg:tt)*) => {{
        span_telemetry!(fuel_telemetry::__reexport_tracing::Level::TRACE, $($arg)*);
    }}
}

/// Enforce a singleton by taking an advisory lock on a file
///
/// This function takes an advisory lock on a file, and if another process has
/// already locked the file, it will exit the current process.
pub(crate) fn enforce_singleton(filename: &Path) -> Result<Flock<File>> {
    let lockfile = OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename)?;

    let lock = match Flock::lock(lockfile.try_clone()?, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => lock,
        Err((_, Errno::EWOULDBLOCK)) => {
            // Silently exit as another process has already locked the file
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
pub(crate) fn daemonise(log_filename: &PathBuf) -> Result<bool> {
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

/// Setup stdio for the process
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
