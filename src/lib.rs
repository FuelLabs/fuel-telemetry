pub mod errors;
pub mod file_watcher;
pub mod systeminfo_watcher;
pub mod telemetry_formatter;
pub mod telemetry_layer;

pub use errors::{into_fatal, into_recoverable, TelemetryError, WatcherError};
pub use macros::{new, new_with_watchers, new_with_watchers_and_init};
pub use telemetry_formatter::TelemetryFormatter;
pub use telemetry_layer::TelemetryLayer;
pub use tracing::{debug, error, event, info, span, trace, warn, Level};
pub use tracing_appender::non_blocking::WorkerGuard;

pub mod prelude {
    pub use crate::{
        debug, debug_telemetry, error, error_telemetry, event, info, info_telemetry, span,
        span_telemetry, trace, trace_telemetry, warn, warn_telemetry, Level, TelemetryLayer,
    };
}

// Re-export tracing so proc_macros can use them
pub use tracing as __reexport_tracing;
pub use tracing_subscriber as __reexport_tracing_subscriber;
pub use tracing_subscriber::filter::EnvFilter as __reexport_EnvFilter;
pub use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt as __reexport_tracing_subscriber_SubscriberExt;
pub use tracing_subscriber::util::SubscriberInitExt as __reexport_SubscriberInitExt;
pub use tracing_subscriber::Layer as __reexport_Layer;

use dirs::home_dir;
use libc::{c_int, c_long};
use nix::{
    errno::Errno,
    fcntl::{Flock, FlockArg},
    sys::stat,
    unistd::{chdir, close, dup2, fork, setsid, sysconf, ForkResult, Pid, SysconfVar},
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

// Result type from Watchers
pub type WatcherResult<T> = std::result::Result<T, WatcherError>;

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
/// let telemetry_config = telemetry_config();
/// ```
pub fn telemetry_config() -> Result<&'static TelemetryConfig> {
    // Note: because we are using LazyLock, we cannot mock this function
    // using helpers as they cannot be evaluated as non-const.
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
// Convenience Macros
//

/// Enter a temporary `Span`, then generates an `Event` with telemetry enabled
///
/// Note: The `Span` name is currently hardcoded to "auto" as `tracing::span!`
/// requires the name to be `const` as internally it is evaluated as a static,
/// however getting the caller's function name in statics is experimental.
///
/// ```rust
/// use fuel_telemetry::prelude::*;
///
/// span_telemetry!(Level::INFO, "This event will be sent to InfluxDB");
/// ```
#[macro_export]
macro_rules! span_telemetry {
    ($level:expr, $($arg:tt)*) => {
        fuel_telemetry::__reexport_tracing::span!($level, "auto", telemetry = true).in_scope(|| {
            fuel_telemetry::__reexport_tracing::event!($level, $($arg)*)
        })
    }
}

/// Generate an `ERROR` telemetry `Event`
///
/// ```rust
/// use fuel_telemetry::prelude::*;
///
/// error_telemetry!("This error event will be sent to InfluxDB");
/// ```
#[macro_export]
macro_rules! error_telemetry {
    ($($arg:tt)*) => {{
        span_telemetry!(fuel_telemetry::__reexport_tracing::Level::ERROR, $($arg)*);
    }}
}

/// Generate a `WARN` telemetry `Event`
///
/// ```rust
/// use fuel_telemetry::prelude::*;
///
/// warn_telemetry!("This warn event will be sent to InfluxDB");
/// ```
#[macro_export]
macro_rules! warn_telemetry {
    ($($arg:tt)*) => {{
        span_telemetry!(fuel_telemetry::__reexport_tracing::Level::WARN, $($arg)*);
    }}
}

/// Generate an `INFO` telemetry `Event`
///
/// ```rust
/// use fuel_telemetry::prelude::*;
///
/// info_telemetry!("This info event will be sent to InfluxDB");
/// ```
#[macro_export]
macro_rules! info_telemetry {
    ($($arg:tt)*) => {{
        span_telemetry!(fuel_telemetry::__reexport_tracing::Level::INFO, $($arg)*);
    }}
}

/// Generate a `DEBUG` telemetry `Event`
///
/// ```rust
/// use fuel_telemetry::prelude::*;
///
/// debug_telemetry!("This debug event will be sent to InfluxDB");
/// ```
#[macro_export]
macro_rules! debug_telemetry {
    ($($arg:tt)*) => {{
        span_telemetry!(fuel_telemetry::__reexport_tracing::Level::DEBUG, $($arg)*);
    }}
}

/// Generate a `TRACE` telemetry `Event`
///
/// ```rust
/// use fuel_telemetry::prelude::*;
///
/// trace_telemetry!("This trace event will be sent to InfluxDB");
/// ```
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
    enforce_singleton_with_lock_fn(filename, |file| {
        Flock::lock(file, FlockArg::LockExclusiveNonblock)
    })
}

#[doc(hidden)]
pub(crate) fn enforce_singleton_with_lock_fn<F>(filename: &Path, lock_fn: F) -> Result<Flock<File>>
where
    F: FnOnce(File) -> std::result::Result<Flock<File>, (File, Errno)>,
{
    let lockfile = OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename)?;

    let lock = match lock_fn(lockfile) {
        Ok(lock) => lock,
        Err((_, Errno::EWOULDBLOCK)) => {
            // Silently exit as another process has already locked the file
            exit(0);
        }
        Err((_, e)) => return Err(TelemetryError::from(e)),
    };

    Ok(lock)
}

pub(crate) trait DaemoniseHelpers {
    fn flush<T: Write + std::os::fd::AsRawFd>(
        &mut self,
        stream: &mut T,
    ) -> std::result::Result<(), std::io::Error> {
        stream.flush()
    }

    fn fork(&mut self) -> nix::Result<ForkResult> {
        unsafe { fork() }
    }

    fn setsid(&self) -> nix::Result<Pid> {
        setsid()
    }

    fn setup_stdio(&self, log_filename: &str) -> std::result::Result<(), TelemetryError> {
        setup_stdio(log_filename)
    }

    fn telemetry_config(&mut self) -> Result<&'static TelemetryConfig> {
        telemetry_config()
    }

    fn chdir(&self, path: &Path) -> nix::Result<()> {
        chdir(path)
    }

    fn sysconf(&self, var: SysconfVar) -> nix::Result<Option<c_long>> {
        sysconf(var)
    }

    fn close(&self, fd: c_int) -> nix::Result<()> {
        close(fd)
    }
}

struct DefaultDaemoniseHelpers;
impl DaemoniseHelpers for DefaultDaemoniseHelpers {}

/// Daemonise the current process
///
/// This function forks and has the parent immediately return. The forked off
/// child then follows the common "double-fork" method of daemonising.
pub(crate) fn daemonise(log_filename: &PathBuf) -> WatcherResult<bool> {
    let mut helpers = DefaultDaemoniseHelpers;
    daemonise_with_helpers(log_filename, &mut helpers)
}

pub(crate) fn daemonise_with_helpers<H: DaemoniseHelpers>(
    log_filename: &PathBuf,
    helpers: &mut H,
) -> WatcherResult<bool> {
    // All errors before the first fork() are recoverable from the caller,
    // meaning that the error occured within the same process and should be
    // ignored by the caller so that it can continue

    helpers.flush(&mut stdout()).map_err(into_recoverable)?;
    helpers.flush(&mut stderr()).map_err(into_recoverable)?;

    // Return if we are the parent
    if helpers.fork().map_err(into_recoverable)?.is_parent() {
        return Ok(true);
    };

    // From here on, we are no longer the original process, so the caller should
    // treat errors as fatal. This means that on error the process should exit
    // immediately as there should not be two identical flows of execution

    // To prevent us from becoming a zombie when we die, we fork then kill the
    // parent so that we are immediately inherited by init/systemd. Doing so, we
    // are guaranteed to be reaped on exit.
    //
    // Also, doing this guarantees that we are not the group leader, which is
    // required to create a new session (i.e setsid() will fail otherwise)
    if helpers.fork().map_err(into_fatal)?.is_parent() {
        exit(0);
    }

    // Creating a new session means we won't receive signals to the original
    // group or session (e.g. hitting CTRL-C to break a command pipeline)
    helpers.setsid().map_err(into_fatal)?;

    // As session leader, we now fork then follow the child again to guarantee
    // we cannot re-acquire a terminal
    if helpers.fork().map_err(into_fatal)?.is_parent() {
        exit(0);
    }

    // Setup stdio to write errors to the logfile while discarding any IO to
    // the controlling terminal
    let fuelup_tmp = helpers
        .telemetry_config()
        .map_err(into_fatal)?
        .fuelup_tmp
        .clone();

    helpers.setup_stdio(
        Path::new(&fuelup_tmp)
            .join(log_filename)
            .to_str()
            .ok_or(TelemetryError::InvalidLogFile(
                fuelup_tmp.clone(),
                log_filename.clone(),
            ))
            .map_err(into_fatal)?,
    )?;

    // The current working directory needs to be set to root so that we don't
    // prevent any unmounting of the filesystem leading up to the directory we
    // started in
    helpers.chdir(Path::new("/")).map_err(into_fatal)?;

    // We close all file descriptors since any currently opened were inherited
    // from the parent process which we don't care about. Not doing so leaks
    // open file descriptors which could lead to exhaustion.

    // Skip the first three because we deal with stdio later. Here, 1024 is a
    // safe value i.e MIN(Legacy Linux, MacOS)
    let max_fd = helpers
        .sysconf(SysconfVar::OPEN_MAX)
        .map_err(into_fatal)?
        .unwrap_or(1024) as i32;

    for fd in 3..=max_fd {
        match helpers.close(fd) {
            Ok(()) | Err(Errno::EBADF) => {}
            Err(e) => Err(into_fatal(e))?,
        }
    }

    // Clear the umask so that files we create aren't too permission-restricive
    stat::umask(stat::Mode::empty());

    Ok(false)
}

struct DefaultSetupStdioHelpers;
impl SetupStdioHelpers for DefaultSetupStdioHelpers {}

trait SetupStdioHelpers {
    fn create_append(&self, log_filename: &str) -> std::result::Result<File, std::io::Error> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_filename)
    }

    fn dup2(&mut self, fd: c_int, fd2: c_int) -> std::result::Result<c_int, nix::errno::Errno> {
        dup2(fd, fd2)
    }

    fn read_write(&self, path: &str) -> std::result::Result<File, std::io::Error> {
        OpenOptions::new().read(true).write(true).open(path)
    }
}

/// Setup stdio for the process
///
/// This function redirects stderr to its logfile while discarding any IO to the
/// controlling terminal.
pub(crate) fn setup_stdio(log_filename: &str) -> std::result::Result<(), TelemetryError> {
    let mut helpers = DefaultSetupStdioHelpers;
    setup_stdio_with_helpers(log_filename, &mut helpers)
}

pub(crate) fn setup_stdio_with_helpers<S: SetupStdioHelpers>(
    log_filename: &str,
    helpers: &mut S,
) -> std::result::Result<(), TelemetryError> {
    let log_file = helpers.create_append(log_filename)?;

    // Redirect stderr to the logfile
    helpers.dup2(log_file.as_raw_fd(), 2)?;

    // Get a filehandle to /dev/null
    let dev_null = helpers.read_write("/dev/null")?;

    // Redirect stdin, stdout to /dev/null
    helpers.dup2(dev_null.as_raw_fd(), 0)?;
    helpers.dup2(dev_null.as_raw_fd(), 1)?;

    Ok(())
}

#[cfg(test)]
fn setup_fuelup_home() {
    std::env::set_var("FUELUP_HOME", std::env::temp_dir().to_str().unwrap());
}

#[cfg(test)]
mod env_setting {
    use super::*;
    use std::env::set_var;

    #[test]
    fn unset() {
        let env_setting = EnvSetting::new("does_not_exist", "default_value");
        assert_eq!(env_setting.get(), "default_value");
    }

    #[test]
    fn set() {
        set_var("existing_variable", "existing_value");

        let env_setting = EnvSetting::new("existing_variable", "default_value");
        assert_eq!(env_setting.get(), "existing_value");
    }
}

#[cfg(test)]
mod telemetry_config {
    use super::*;
    use rusty_fork::rusty_fork_test;
    use std::env::set_var;
    use std::path::Path;
    use tempfile::tempdir;

    rusty_fork_test! {
        #[test]
        fn fuelup_all_unset() {
            let telemetry_config = telemetry_config().unwrap();

            let fuelup_home = home_dir().unwrap();
            assert_eq!(telemetry_config.fuelup_tmp, fuelup_home.join(".fuelup/tmp").to_str().unwrap());
            assert_eq!(telemetry_config.fuelup_log, fuelup_home.join(".fuelup/log").to_str().unwrap());

            assert!(Path::new(&telemetry_config.fuelup_tmp).is_dir());
            assert!(Path::new(&telemetry_config.fuelup_log).is_dir());
        }

        #[test]
        fn fuelup_home_set() {
            let tmpdir = tempdir().unwrap();
            set_var("FUELUP_HOME", tmpdir.path().to_str().unwrap());

            let telemetry_config = telemetry_config().unwrap();

            assert_eq!(telemetry_config.fuelup_tmp, tmpdir.path().join("tmp").to_str().unwrap());
            assert_eq!(telemetry_config.fuelup_log, tmpdir.path().join("log").to_str().unwrap());

            assert!(Path::new(&telemetry_config.fuelup_tmp).is_dir());
            assert!(Path::new(&telemetry_config.fuelup_log).is_dir());
        }

        #[test]
        fn fuelup_tmp_set() {
            let tmpdir = tempdir().unwrap();
            set_var("FUELUP_TMP", tmpdir.path().to_str().unwrap());

            let telemetry_config = telemetry_config().unwrap();

            assert_eq!(telemetry_config.fuelup_tmp, tmpdir.path().to_str().unwrap());
            assert_eq!(telemetry_config.fuelup_log, home_dir().unwrap().join(".fuelup/log").to_str().unwrap());

            assert!(Path::new(&telemetry_config.fuelup_tmp).is_dir());
            assert!(Path::new(&telemetry_config.fuelup_log).is_dir());
        }

        #[test]
        fn fuelup_log_set() {
            let tmpdir = tempdir().unwrap();
            set_var("FUELUP_LOG", tmpdir.path().to_str().unwrap());

            let telemetry_config = telemetry_config().unwrap();

            assert_eq!(telemetry_config.fuelup_tmp, home_dir().unwrap().join(".fuelup/tmp").to_str().unwrap());
            assert_eq!(telemetry_config.fuelup_log, tmpdir.path().to_str().unwrap());

            assert!(Path::new(&telemetry_config.fuelup_tmp).is_dir());
            assert!(Path::new(&telemetry_config.fuelup_log).is_dir());
        }
    }
}

#[cfg(test)]
mod enforce_singleton {
    use super::*;
    use rusty_fork::rusty_fork_test;
    use std::env::{current_exe, set_var, var};
    use std::process::Command;
    use tempfile::tempdir;

    rusty_fork_test! {
        #[test]
        fn invalid_filename() {
            let result = enforce_singleton(Path::new("/"));
            assert!(matches!(result, Err(TelemetryError::IO(_))));
        }

        #[test]
        fn flock_ewouldblock() {
            let tmpdir = tempdir().unwrap();
            set_var("FUELUP_HOME", tmpdir.path().to_str().unwrap());

            // Take the lock for the parent and child
            let result = enforce_singleton(&Path::new(&telemetry_config().unwrap().fuelup_tmp).join("test.lock"));

            if var("RECURSION").unwrap_or_default() != "true" {
                // Testing the first time calling `enforce_singleton()`
                assert!(result.is_ok());

                let result = Command::new(current_exe().unwrap())
                    .env("FUELUP_HOME", tmpdir.path().to_str().unwrap())
                    .env("RECURSION", "true")
                    .arg("--test")
                    .arg("enforce_singleton::flock_ewouldblock")
                    .arg("--")
                    .arg("--nocapture")
                    .status()
                    .unwrap();

                // Testing the second time calling `enforce_singleton()` (i.e.from the child)
                assert!(result.success());
            }
        }

        #[test]
        fn flock_other_error() {
            setup_fuelup_home();

            let path = Path::new(&telemetry_config().unwrap().fuelup_tmp).join("test.lock");

            let result = enforce_singleton_with_lock_fn(&path, |file| {
                Err((file, Errno::EOWNERDEAD))
            });

            assert!(result.is_err());
        }
    }
}

#[cfg(test)]
mod daemonise {
    use super::*;
    use nix::{
        errno::Errno,
        sys::wait::{waitpid, WaitStatus},
        unistd::ForkResult,
    };
    use rusty_fork::rusty_fork_test;
    use std::io::{Error, ErrorKind, Result, Write};

    rusty_fork_test! {
        #[test]
        fn stdout_flush_failed() {
            setup_fuelup_home();

            struct StdoutFlushFailed;

            impl DaemoniseHelpers for StdoutFlushFailed {
                fn flush<T: Write + std::os::fd::AsRawFd>(&mut self, stream: &mut T) -> Result<()> {
                    assert_eq!(stream.as_raw_fd(), 1);
                    Err(Error::new(ErrorKind::Other, "Error flushing stdout"))
                }
            }

            let result = daemonise_with_helpers(&PathBuf::from("test.log"), &mut StdoutFlushFailed);
            assert!(matches!(result, Err(WatcherError::Recoverable(_))));
        }

        #[test]
        fn stderr_flush_failed() {
            setup_fuelup_home();

            #[derive(Default)]
            struct StderrFlushFailed {
                call_counter: usize,
            }

            impl DaemoniseHelpers for StderrFlushFailed {
                fn flush<T: Write + std::os::fd::AsRawFd>(& mut self, stream: &mut T) -> Result<()> {
                    self.call_counter += 1;

                    if self.call_counter == 1 {
                        Ok(())
                    } else {
                        assert_eq!(stream.as_raw_fd(), 2);
                        Err(Error::new(ErrorKind::Other, "Error flushing stderr"))
                    }
                }
            }

            let result = daemonise_with_helpers(&PathBuf::from("test.log"), &mut StderrFlushFailed::default());
            assert!(matches!(result, Err(WatcherError::Recoverable(_))));
        }

        #[test]
        fn first_fork_failed() {
            setup_fuelup_home();

            struct FirstForkFailed;

            impl DaemoniseHelpers for FirstForkFailed {
                fn fork(&mut self) -> nix::Result<ForkResult> {
                    Err(Errno::EOWNERDEAD)
                }
            }

            let result = daemonise_with_helpers(&PathBuf::from("test.log"), &mut FirstForkFailed);
            assert!(matches!(result, Err(WatcherError::Recoverable(_))));
        }

        #[test]
        fn first_fork_is_parent() {
            setup_fuelup_home();

            struct FirstForkIsParent;

            impl DaemoniseHelpers for FirstForkIsParent {
                fn fork(&mut self) -> nix::Result<ForkResult> {
                    Ok(ForkResult::Parent { child: Pid::from_raw(1) })
                }
            }

            let result = daemonise_with_helpers(&PathBuf::from("test.log"), &mut FirstForkIsParent);
            assert!(matches!(result, Ok(true)));
        }

        #[test]
        fn second_fork_failed() {
            setup_fuelup_home();

            #[derive(Default)]
            struct SecondForkFailed {
                call_counter: usize,
            }

            impl DaemoniseHelpers for SecondForkFailed {
                fn fork(&mut self) -> nix::Result<ForkResult> {
                    self.call_counter += 1;

                    if self.call_counter == 2 {
                        Err(Errno::EOWNERDEAD)
                    } else {
                        Ok(ForkResult::Child)
                    }
                }
            }

            let result = daemonise_with_helpers(&PathBuf::from("test.log"), &mut SecondForkFailed::default());
            assert!(matches!(result, Err(WatcherError::Fatal(_))));
        }

        #[test]
        fn second_fork_is_parent() {
            setup_fuelup_home();

            #[derive(Default)]
            struct SecondForkIsParent {
                call_counter: usize,
            }

            impl DaemoniseHelpers for SecondForkIsParent {
                fn fork(&mut self) -> nix::Result<ForkResult> {
                    self.call_counter += 1;

                    if self.call_counter == 2 {
                        Ok(ForkResult::Parent { child: Pid::from_raw(1) })
                    } else {
                        Ok(ForkResult::Child)
                    }
                }
            }

            // We ourselves fork so that we can `waitpid` on the function
            match unsafe { fork() }.unwrap() {
                ForkResult::Parent { child } => {
                    match waitpid(child, None).unwrap() {
                        WaitStatus::Exited(_, code) => {
                            assert_eq!(code, 0);
                        }
                        _ => panic!("Child did not exit normally"),
                    }
                }
                ForkResult::Child => {
                    let _ = daemonise_with_helpers(&PathBuf::from("test.log"), &mut SecondForkIsParent::default());

                    // Fallback status code
                    exit(99);
                }
            }
        }

        #[test]
        fn setsid_failed() {
            setup_fuelup_home();

            struct SetsidFailed;

            impl DaemoniseHelpers for SetsidFailed {
                fn setsid(&self) -> nix::Result<Pid> {
                    Err(Errno::EOWNERDEAD)
                }

                // Need to become the child so we don't return as the parent
                fn fork(&mut self) -> nix::Result<ForkResult> {
                    Ok(ForkResult::Child)
                }
            }

            let result = daemonise_with_helpers(&PathBuf::from("test.log"), &mut SetsidFailed);
            assert!(matches!(result, Err(WatcherError::Fatal(_))));
        }

        #[test]
        fn third_fork_failed() {
            setup_fuelup_home();

            #[derive(Default)]
            struct ThirdForkFailed {
                call_counter: usize,
            }

            impl DaemoniseHelpers for ThirdForkFailed {
                fn fork(&mut self) -> nix::Result<ForkResult> {
                    self.call_counter += 1;

                    if self.call_counter == 3 {
                        Err(Errno::EOWNERDEAD)
                    } else {
                        Ok(ForkResult::Child)
                    }
                }
            }

            let result = daemonise_with_helpers(&PathBuf::from("test.log"), &mut ThirdForkFailed::default());
            assert!(matches!(result, Err(WatcherError::Fatal(_))));
        }

        #[test]
        fn third_fork_is_parent() {
            setup_fuelup_home();

            #[derive(Default)]
            struct ThirdForkIsParent {
                call_counter: usize,
            }

            impl DaemoniseHelpers for ThirdForkIsParent {
                fn fork(&mut self) -> nix::Result<ForkResult> {
                    self.call_counter += 1;

                    if self.call_counter == 3 {
                        Ok(ForkResult::Parent { child: Pid::from_raw(1) })
                    } else {
                        Ok(ForkResult::Child)
                    }
                }
            }

            // We ourselves fork so that we can `waitpid` on the function
            match unsafe { fork() }.unwrap() {
                ForkResult::Parent { child } => {
                    match waitpid(child, None).unwrap() {
                        WaitStatus::Exited(_, code) => {
                            assert_eq!(code, 0);
                        }
                        _ => panic!("Child did not exit normally"),
                    }
                }
                ForkResult::Child => {
                    let _ = daemonise_with_helpers(&PathBuf::from("test.log"), &mut ThirdForkIsParent::default());

                    // Fallback status code
                    exit(99);
                }
            }
        }

        #[test]
        fn setup_stdio_failed() {
            struct SetupStdioFailed;

            impl DaemoniseHelpers for SetupStdioFailed {
                fn setup_stdio(&self, _log_filename: &str) -> std::result::Result<(), TelemetryError> {
                    Err(TelemetryError::IO("Error setting up stdio".to_string()))
                }

                // Need to become the child so we don't return as the parent
                fn fork(&mut self) -> nix::Result<ForkResult> {
                    Ok(ForkResult::Child)
                }
            }


            let result = daemonise_with_helpers(&PathBuf::from("test.log"), &mut SetupStdioFailed);
            assert!(matches!(result, Err(WatcherError::Fatal(_))));
        }

        #[test]
        fn first_telemetry_config_failed() {
            setup_fuelup_home();

            struct FirstTelemetryConfigFailed;

            impl DaemoniseHelpers for FirstTelemetryConfigFailed {
                fn telemetry_config(&mut self) -> std::result::Result<&'static TelemetryConfig, errors::TelemetryError> {
                    Err(TelemetryError::InvalidConfig("Error getting telemetry config".to_string()))
                }

                // Need to become the child so we don't return as the parent
                fn fork(&mut self) -> nix::Result<ForkResult> {
                    Ok(ForkResult::Child)
                }
            }

            let result = daemonise_with_helpers(&PathBuf::from("test.log"), &mut FirstTelemetryConfigFailed);
            assert!(matches!(result, Err(WatcherError::Fatal(_))));
        }

        #[test]
        fn join_failed() {
            setup_fuelup_home();

            struct JoinFailed;

            impl DaemoniseHelpers for JoinFailed {
                fn telemetry_config(&mut self) -> std::result::Result<&'static TelemetryConfig, errors::TelemetryError> {
                    pub static _TELEMETRY_CONFIG: LazyLock<Result<TelemetryConfig>> = LazyLock::new(|| {
                        Ok(TelemetryConfig {
                            // Use invalid UTF-8 to trigger the error
                            fuelup_tmp: unsafe { String::from_utf8_unchecked(vec![0xFF]) },
                            fuelup_log: "".to_string(),
                        })
                    });

                    _TELEMETRY_CONFIG.as_ref().map_err(|_|
                        TelemetryError::InvalidConfig("Error getting telemetry config".to_string()))
                }

                // Need to become the child so we don't return as the parent
                fn fork(&mut self) -> nix::Result<ForkResult> {
                    Ok(ForkResult::Child)
                }
            }

            let result = daemonise_with_helpers(&PathBuf::from("test.log"), &mut JoinFailed);
            assert!(matches!(result, Err(WatcherError::Fatal(TelemetryError::InvalidLogFile(_, _)))));
        }

        #[test]
        fn chdir_failed() {
            setup_fuelup_home();

            struct ChdirFailed;

            impl DaemoniseHelpers for ChdirFailed {
                fn chdir(&self, _path: &Path) -> nix::Result<()> {
                    Err(Errno::EOWNERDEAD)
                }

                // Need to become the child so we don't return as the parent
                fn fork(&mut self) -> nix::Result<ForkResult> {
                    Ok(ForkResult::Child)
                }
            }

            let result = daemonise_with_helpers(&PathBuf::from("test.log"), &mut ChdirFailed);
            assert!(matches!(result, Err(WatcherError::Fatal(_))));
        }

        #[test]
        fn sysconf_failed() {
            setup_fuelup_home();

            struct SysconfFailed;

            impl DaemoniseHelpers for SysconfFailed {
                fn sysconf(&self, _var: SysconfVar) -> nix::Result<Option<c_long>> {
                    Err(Errno::EOWNERDEAD)
                }

                // Need to become the child so we don't return as the parent
                fn fork(&mut self) -> nix::Result<ForkResult> {
                    Ok(ForkResult::Child)
                }
            }

            let result = daemonise_with_helpers(&PathBuf::from("test.log"), &mut SysconfFailed);
            assert!(matches!(result, Err(WatcherError::Fatal(_))));
        }

        #[test]
        fn close_failed_with_ebadf() {
            struct CloseFailed;

            impl DaemoniseHelpers for CloseFailed {
                fn close(&self, _fd: c_int) -> nix::Result<()> {
                    Err(Errno::EBADF)
                }

                // Need to become the child so we don't return as the parent
                fn fork(&mut self) -> nix::Result<ForkResult> {
                    Ok(ForkResult::Child)
                }
            }

            let result = daemonise_with_helpers(&PathBuf::from("test.log"), &mut CloseFailed);
            assert!(matches!(result, Ok(false)));
        }

        #[test]
        fn close_failed_with_other_error() {
            setup_fuelup_home();

            struct CloseFailed;

            impl DaemoniseHelpers for CloseFailed {
                fn close(&self, _fd: c_int) -> nix::Result<()> {
                    Err(Errno::EOWNERDEAD)
                }

                // Need to become the child so we don't return as the parent
                fn fork(&mut self) -> nix::Result<ForkResult> {
                    Ok(ForkResult::Child)
                }
            }

            let result = daemonise_with_helpers(&PathBuf::from("test.log"), &mut CloseFailed);
            assert!(matches!(result, Err(WatcherError::Fatal(_))));
        }

        #[test]
        fn ok() {
            setup_fuelup_home();

            struct AOk;

            impl DaemoniseHelpers for AOk {
                fn fork(&mut self) -> nix::Result<ForkResult> {
                    Ok(ForkResult::Child)
                }
            }

            let result = daemonise_with_helpers(&PathBuf::from("test.log"), &mut AOk);
            assert!(matches!(result, Ok(false)));
        }
    }
}

#[cfg(test)]
mod setup_stdio {
    use super::*;
    use rusty_fork::rusty_fork_test;

    rusty_fork_test! {
        #[test]
        fn create_append_failed() {
            setup_fuelup_home();

            struct CreateAppendFailed;

            impl SetupStdioHelpers for CreateAppendFailed {
                fn create_append(
                    &self,
                    _log_filename: &str,
                ) -> std::result::Result<File, std::io::Error> {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Error creating append",
                    ))
                }
            }

            let result = setup_stdio_with_helpers(&format!("{}/test.log",
                telemetry_config().unwrap().fuelup_log), &mut CreateAppendFailed);
            assert!(matches!(result, Err(TelemetryError::IO(_))));
        }

        #[test]
        fn first_dup2_failed() {
            setup_fuelup_home();

            struct FirstDup2Failed;

            impl SetupStdioHelpers for FirstDup2Failed {
                fn dup2(
                    &mut self,
                    _fd: c_int,
                    fd2: c_int,
                ) -> std::result::Result<c_int, nix::errno::Errno> {
                    assert_eq!(fd2, 2);
                    Err(nix::errno::Errno::EOWNERDEAD)
                }
            }

            let result = setup_stdio_with_helpers(&format!("{}/test.log",
                telemetry_config().unwrap().fuelup_log), &mut FirstDup2Failed);
            assert!(matches!(result, Err(TelemetryError::Nix(_))));
        }

        #[test]
        fn read_write_failed() {
            setup_fuelup_home();

            struct ReadWriteFailed;

            impl SetupStdioHelpers for ReadWriteFailed {
                fn read_write(&self, _path: &str) -> std::result::Result<File, std::io::Error> {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Error reading write",
                    ))
                }
            }

            let result = setup_stdio_with_helpers(&format!("{}/test.log",
                telemetry_config().unwrap().fuelup_log), &mut ReadWriteFailed);
            assert!(matches!(result, Err(TelemetryError::IO(_))));
        }

        #[test]
        fn second_dup2_failed() {
            setup_fuelup_home();

            #[derive(Default)]
            struct SecondDup2Failed {
                call_counter: usize,
            }

            impl SetupStdioHelpers for SecondDup2Failed {
                fn dup2(
                    &mut self,
                    _fd: c_int,
                    fd2: c_int,
                ) -> std::result::Result<c_int, nix::errno::Errno> {
                    self.call_counter += 1;

                    if self.call_counter == 2 {
                        assert_eq!(fd2, 0);
                        Err(nix::errno::Errno::EOWNERDEAD)
                    } else {
                        Ok(0)
                    }
                }
            }

            let result = setup_stdio_with_helpers(&format!("{}/test.log",
                telemetry_config().unwrap().fuelup_log), &mut SecondDup2Failed::default());
            assert!(matches!(result, Err(TelemetryError::Nix(_))));
        }

        #[test]
        fn third_dup2_failed() {
            setup_fuelup_home();

            #[derive(Default)]
            struct ThirdDup2Failed {
                call_counter: usize,
            }

            impl SetupStdioHelpers for ThirdDup2Failed {
                fn dup2(
                    &mut self,
                    _fd: c_int,
                    fd2: c_int,
                ) -> std::result::Result<c_int, nix::errno::Errno> {
                    self.call_counter += 1;

                    if self.call_counter == 3 {
                        assert_eq!(fd2, 1);
                        Err(nix::errno::Errno::EOWNERDEAD)
                    } else {
                        Ok(0)
                    }
                }
            }

            let result = setup_stdio_with_helpers(&format!("{}/test.log",
                telemetry_config().unwrap().fuelup_log), &mut ThirdDup2Failed::default());
            assert!(matches!(result, Err(TelemetryError::Nix(_))));
        }

        #[test]
        fn ok() {
            setup_fuelup_home();

            let result = setup_stdio_with_helpers(&format!("{}/test.log",
                telemetry_config().unwrap().fuelup_log), &mut DefaultSetupStdioHelpers);
            assert!(matches!(result, Ok(())));
        }
    }
}
