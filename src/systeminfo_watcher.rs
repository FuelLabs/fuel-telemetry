use crate::{
    self as fuel_telemetry, daemonise, enforce_singleton, info, into_recoverable, span,
    telemetry_config, telemetry_formatter, EnvSetting, Level, Result, TelemetryError,
    WatcherResult,
};

use nix::{
    fcntl::{Flock, FlockArg},
    sys::{
        signal::{kill, Signal::SIGKILL},
        stat::fstat,
    },
    time::ClockId,
    unistd::{getpid, Pid},
};
use std::{
    env::{set_var, var},
    fs::{File, OpenOptions},
    io::Write,
    os::fd::{AsRawFd, RawFd},
    path::{Path, PathBuf},
    process::exit,
    sync::{
        atomic::{AtomicBool, AtomicI32, Ordering},
        LazyLock,
    },
    time::Duration,
};
use sysinfo::{MemoryRefreshKind, System};
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

const PROCESS_NAME: &str = "telemetry-systeminfo-watcher";
const TELEMETRY_PKG_NAME: &str = "systeminfo_watcher";

#[derive(Debug, Clone)]
struct SystemInfoWatcherConfig {
    // The path to its lockfile
    lockfile: PathBuf,
    // The path to its logfile
    logfile: PathBuf,
    // The timeout for the cloud provider metadata request
    metadata_timeout: u64,
    // The path to its touchfile
    touchfile: PathBuf,
    // The number of seconds to wait between collecting metrics
    interval: u64,
}

fn config() -> Result<&'static SystemInfoWatcherConfig> {
    static SYSTEMINFO_WATCHER_CONFIG: LazyLock<Result<SystemInfoWatcherConfig>> =
        LazyLock::new(|| {
            let get_env = |key, default| EnvSetting::new(key, default).get();

            Ok(SystemInfoWatcherConfig {
                // 60*60*24*30 = 2592000 (30 days)
                interval: get_env("SYSTEMINFO_WATCHER_INTERVAL", "2592000").parse()?,
                metadata_timeout: get_env("METADATA_TIMEOUT", "3").parse()?,
                lockfile: Path::new(&telemetry_config()?.fuelup_tmp)
                    .join(format!("{}.lock", PROCESS_NAME)),
                logfile: Path::new(&telemetry_config()?.fuelup_log)
                    .join(format!("{}.log", PROCESS_NAME)),
                touchfile: Path::new(&telemetry_config()?.fuelup_tmp)
                    .join(format!("{}.touch", PROCESS_NAME)),
            })
        });

    SYSTEMINFO_WATCHER_CONFIG
        .as_ref()
        .map_err(|e| TelemetryError::InvalidConfig(e.to_string()))
}

// Although there's no need to keep the state of this watcher, keep it consistent
// with the other watchers

#[derive(Default)]
pub struct SystemInfoWatcher;

// Prevent recursive calls to start()
static STARTED: AtomicBool = AtomicBool::new(false);

/// The PID of the currently running `SystemInfoWatcher` daemon
pub static PID: AtomicI32 = AtomicI32::new(0);

impl SystemInfoWatcher {
    pub fn new() -> Self {
        Self
    }

    pub fn start(&mut self) -> WatcherResult<()> {
        self.start_with_helpers(&DefaultStartHelpers)
    }

    fn start_with_helpers(&mut self, helpers: &impl StartHelpers) -> WatcherResult<()> {
        if var("FUELUP_NO_TELEMETRY").is_ok() {
            // If telemetry is disabled, immediately return
            return Ok(());
        }

        let logfile = &config().map_err(into_recoverable)?.logfile;

        if STARTED.load(Ordering::Relaxed) {
            return Ok(());
        } else {
            STARTED.store(true, Ordering::Relaxed);
        }

        // Even though we won't be hanging around long, we still daemonise
        // so that we don't get in the way of the calling process
        match helpers.daemonise(logfile) {
            Ok(Some(pid)) => {
                // We are the parent, so record the PID then immediately return
                PID.store(pid.as_raw(), Ordering::Relaxed);
                return Ok(());
            }
            Err(e) => {
                // Couldn't daemonise, so clear globals before returning the error
                STARTED.store(false, Ordering::Relaxed);
                PID.store(0, Ordering::Relaxed);
                return Err(e);
            }
            Ok(None) => {
                // We are the child process, so continue as the `SystemInfoWatcher`...
                PID.store(getpid().as_raw(), Ordering::Relaxed);
            }
        }

        // From here on, we are no longer the original process, so the caller should
        // treat errors as fatal. This means that on error the process should exit
        // immediately as there should not be two identical flows of execution

        // As we record system metrics via a `TelemetryLayer`, we will need our
        // own `tracing` `Subscriber` as the orginial `Subscriber` lives in a
        // thread within a different process space as we've since daemonised.
        //
        // Warning: We need to create the `TelemetryLayer` after daemonising
        // as there is a race condition in the thread runtime of `tracing` and
        // the tokio runtime of `Reqwest`. Swapping order of the two could lead to
        // possible deadlocks.
        //
        // Also, we need to set the bucket name as the SystemInfoWatcher is
        // system-wide rather than being crate/process specific
        set_var("TELEMETRY_PKG_NAME", TELEMETRY_PKG_NAME);
        let (telemetry_layer, _guard) = helpers.new_fuel_telemetry()?;
        tracing_subscriber::registry().with(telemetry_layer).init();

        // Enforce a singleton to ensure we are the only process submitting
        // telemetry to InfluxDB
        let _lock = helpers.enforce_singleton(&config()?.lockfile)?;

        // Check if it's time to collect metrics
        helpers.poll_systeminfo(self)?;

        helpers.exit(0)
    }

    /// Kill the `SystemInfoWatcher` daemon if one is running
    pub fn kill() -> Result<bool> {
        let pid = PID.load(Ordering::Relaxed);

        if pid > 0 {
            kill(Pid::from_raw(pid), SIGKILL)?;
            PID.store(0, Ordering::Relaxed);
            return Ok(true);
        }

        Ok(false)
    }

    fn poll_systeminfo(&self) -> Result<()> {
        self.poll_systeminfo_with_helpers(&mut DefaultPollSysteminfoHelpers)
    }

    fn poll_systeminfo_with_helpers(&self, helpers: &mut impl PollSysteminfoHelpers) -> Result<()> {
        // If the lockfile is not found, create it and continue. Otherwise,
        // check its modification time and return if it's too recent
        let touchfile_lock = if !config()?.touchfile.exists() {
            helpers.create_and_lock_touchfile(&config()?.touchfile)?
        } else {
            let locked_file = helpers.open_and_lock_touchfile(&config()?.touchfile)?;
            let now = helpers.now()?;

            if now.tv_sec()
                < helpers.fstat(locked_file.as_raw_fd())?.st_mtime + config()?.interval as i64
            {
                // We must have collected metrics recently, so return
                return Ok(());
            }

            locked_file
        };

        let mut sysinfo = System::new();
        //
        // CPU metrics
        //

        // Need to refresh twice with a delay in between so that there ar enough
        // data points for "cpu_usage"
        sysinfo.refresh_cpu_usage();
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        sysinfo.refresh_cpu_usage();

        let cpus = sysinfo.cpus();
        let cpu_count = cpus.len();
        let cpu_brand = cpus
            .first()
            .map_or_else(String::default, |cpu| cpu.brand().into());

        //
        // Memory and OS metrics
        //

        sysinfo.refresh_memory_specifics(MemoryRefreshKind::nothing().with_ram());

        let total_memory = sysinfo.total_memory();
        let free_memory = sysinfo.used_memory();
        let load_average = System::load_average();

        //
        // Build the line protocol and write to disk
        //

        #[allow(clippy::cast_precision_loss)]
        // These values are just informational, so we can take a precision loss
        let free_memory_percentage = (free_memory as f64) / (total_memory as f64);

        // Detect if we're not running on bare metal
        let ci = detect_ci();
        let vm = helpers.detect_vm()?;

        let span = span!(Level::INFO, "poll_systeminfo", telemetry = true);
        let _guard = span.enter();

        info!(
            cpu_arch = System::cpu_arch(),
            cpu_brand = cpu_brand,
            cpu_count = cpu_count,
            global_cpu_usage = (sysinfo.global_cpu_usage() as f64 * 100.0).trunc() / 100.0,
            total_memory = total_memory,
            free_memory = free_memory,
            free_memory_percentage = (free_memory_percentage * 100.0).trunc() / 100.0,
            os_long_name = System::long_os_version().unwrap_or_default(),
            kernel_version = System::kernel_version().unwrap_or_default(),
            uptime = System::uptime(),
            vm = vm,
            ci = ci,
            load_average_1m = (load_average.one * 100.0).trunc() / 100.0,
            load_average_5m = (load_average.five * 100.0).trunc() / 100.0,
            load_average_15m = (load_average.fifteen * 100.0).trunc() / 100.0,
        );

        // Update the touchfile's modification time by truncating it
        helpers.set_len(&touchfile_lock, 0)?;
        helpers.sync_all(&touchfile_lock)?;

        Ok(())
    }

    /// Last resort logging of errors, only to be used by the caller when there
    /// is no other way to report an error.
    pub fn log_error(message: &str) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config()?.logfile)?;

        Ok(writeln!(file, "{}", message)?)
    }
}

trait StartHelpers {
    fn daemonise(&self, logfile: &PathBuf) -> WatcherResult<Option<Pid>> {
        daemonise(logfile)
    }

    #[allow(clippy::type_complexity)]
    fn new_fuel_telemetry(
        &self,
    ) -> Result<(
        tracing_subscriber::filter::Filtered<
            tracing_subscriber::fmt::Layer<
                tracing_subscriber::Registry,
                tracing_subscriber::fmt::format::DefaultFields,
                telemetry_formatter::TelemetryFormatter,
                tracing_appender::non_blocking::NonBlocking,
            >,
            tracing_subscriber::EnvFilter,
            tracing_subscriber::Registry,
        >,
        tracing_appender::non_blocking::WorkerGuard,
    )> {
        fuel_telemetry::new!()
    }

    fn enforce_singleton(&self, lockfile_path: &Path) -> Result<Flock<File>> {
        enforce_singleton(lockfile_path)
    }

    fn poll_systeminfo(&self, systeminfo_watcher: &SystemInfoWatcher) -> Result<()> {
        systeminfo_watcher.poll_systeminfo()
    }

    fn exit(&self, code: i32) -> ! {
        exit(code)
    }
}

struct DefaultStartHelpers;
impl StartHelpers for DefaultStartHelpers {}

trait PollSysteminfoHelpers {
    fn create_and_lock_touchfile(&self, touchfile: &Path) -> Result<Flock<File>> {
        Ok(Flock::lock(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(touchfile)?,
            FlockArg::LockExclusiveNonblock,
        )
        .map_err(|(_, e)| e)?)
    }

    fn open_and_lock_touchfile(&self, touchfile: &Path) -> Result<Flock<File>> {
        Ok(Flock::lock(
            OpenOptions::new()
                .create(false)
                .append(true)
                .open(touchfile)?,
            FlockArg::LockExclusiveNonblock,
        )
        .map_err(|(_, e)| e)?)
    }

    fn now(&self) -> nix::Result<nix::sys::time::TimeSpec> {
        ClockId::CLOCK_REALTIME.now()
    }

    fn fstat(&self, fd: RawFd) -> nix::Result<libc::stat> {
        fstat(fd)
    }

    fn detect_vm(&self) -> Result<&'static str> {
        detect_vm()
    }

    fn set_len(&self, flock: &Flock<File>, len: u64) -> std::io::Result<()> {
        flock.set_len(len)
    }

    fn sync_all(&self, flock: &Flock<File>) -> std::io::Result<()> {
        flock.sync_all()
    }
}

struct DefaultPollSysteminfoHelpers;
impl PollSysteminfoHelpers for DefaultPollSysteminfoHelpers {}

fn detect_ci() -> &'static str {
    // Check if we are running in any type of CI
    let ci_environments = [
        ("GITHUB_ACTIONS", "GitHub Actions"),
        ("GITLAB_CI", "GitLab CI"),
        ("CODEBUILD_BUILD_NUMBER", "AWS CodePipeline"),
        ("CLOUD_RUN_JOB", "Google Cloud Build"),
        ("TF_BUILD", "Azure Pipelines"),
        ("CIRCLECI", "CircleCI"),
        ("TEAMCITY_VERSION", "TeamCity"),
        ("BITBUCKET_BUILD_NUMBER", "BitBucket Pipelines"),
        ("TRAVIS", "Travis CI"),
        ("JENKINS_URL", "Jenkins"),
    ];

    for (env_var, ci_name) in ci_environments {
        if var(env_var).is_ok() {
            return ci_name;
        }
    }
    ""
}

fn detect_vm() -> Result<&'static str> {
    // Check if we are running in a container
    let container_environments = [
        ("/.dockerenv", "Docker"),
        ("/.lxc-private", "LXD"),
        ("/.lxc", "LXD"),
        ("/.podman-private", "Podman"),
    ];

    for (env_var, container_name) in container_environments {
        if Path::new(env_var).exists() {
            return Ok(container_name);
        }
    }

    // Check if we are running in AWS Lambda
    if var("LAMBDA_TASK_ROOT").is_ok() {
        return Ok("AWS Lambda");
    }

    // Check for a cloud provider
    //
    // These are static values and are not configurable. If they change, the
    // structure of the call may need to change as has happened in the past
    let cloud_checks = [
        (
            "http://metadata.google.internal/computeMetadata/v1/instance/id",
            vec![("Metadata-Flavor", "Google")],
            "GCP GCE",
        ),
        (
            "http://169.254.169.254/latest/api/token",
            vec![("X-aws-ec2-metadata-token-ttl-seconds", "21600")],
            "AWS EC2",
        ),
        (
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            vec![("Metadata", "true")],
            "Azure",
        ),
    ];

    let client = reqwest::blocking::Client::new();
    let timeout = Duration::from_secs(config()?.metadata_timeout);

    for (url, headers, provider) in cloud_checks {
        let mut request = client.get(url).timeout(timeout);

        for (key, value) in headers {
            request = request.header(key, value);
        }

        if request.send().is_ok_and(|r| r.status().is_success()) {
            return Ok(provider);
        }
    }

    //  Check for a VM vendor
    let vm_vendors = ["QEMU", "VMware", "VirtualBox", "Hyper-V", "KVM"];
    let vendor_files = ["bios_vendor", "sys_vendor", "product_name"];

    for file in vendor_files {
        if let Ok(contents) = std::fs::read_to_string(format!("/sys/class/dmi/id/{}", file)) {
            for vendor in vm_vendors {
                if contents.contains(vendor) {
                    return Ok(vendor);
                }
            }
        }
    }

    Ok("")
}

#[cfg(test)]
mod config {
    use super::*;
    use crate::setup_fuelup_home;
    use dirs::home_dir;
    use rusty_fork::rusty_fork_test;
    use std::env::var;
    use std::path::Path;

    rusty_fork_test! {
        #[test]
        fn all_unset() {
            let config = config().unwrap();

            assert_eq!(config.interval, 2592000);
            assert_eq!(config.metadata_timeout, 3);

            assert_eq!(
                config.lockfile,
                Path::new(
                    &home_dir()
                        .unwrap()
                        .join(format!(".fuelup/tmp/{}.lock", PROCESS_NAME))
                )
            );

            assert_eq!(
                config.logfile,
                Path::new(
                    &home_dir()
                        .unwrap()
                        .join(format!(".fuelup/log/{}.log", PROCESS_NAME))
                )
            );

            assert_eq!(
                config.touchfile,
                Path::new(
                    &home_dir()
                        .unwrap()
                        .join(format!(".fuelup/tmp/{}.touch", PROCESS_NAME))
                )
            );
        }

        #[test]
        fn systeminfo_watcher_interval_set() {
            set_var("SYSTEMINFO_WATCHER_INTERVAL", "2222");

            let config = config().unwrap();
            assert_eq!(config.interval, 2222);
        }

        #[test]
        fn systeminfo_watcher_interval_invalid() {
            set_var("SYSTEMINFO_WATCHER_INTERVAL", "invalid interval");

            assert_eq!(
                config().err(),
                Some(TelemetryError::InvalidConfig(
                    TelemetryError::Parse("invalid digit found in string".to_string()).into()
                ))
            );
        }

        #[test]
        fn metadata_timeout_set() {
            set_var("METADATA_TIMEOUT", "2222");

            let config = config().unwrap();
            assert_eq!(config.metadata_timeout, 2222);
        }

        #[test]
        fn metadata_timeout_invalid() {
            set_var("METADATA_TIMEOUT", "invalid");

            assert_eq!(
                config().err(),
                Some(TelemetryError::InvalidConfig(
                    TelemetryError::Parse("invalid digit found in string".to_string()).into()
                ))
            );
        }

        #[test]
        fn all_set() {
            setup_fuelup_home();
            let fuelup_home = var("FUELUP_HOME").unwrap();

            set_var("SYSTEMINFO_WATCHER_INTERVAL", "2222");
            set_var("METADATA_TIMEOUT", "3333");

            let config = config().unwrap();

            assert_eq!(config.interval, 2222);
            assert_eq!(config.metadata_timeout, 3333);

            assert_eq!(
                config.lockfile,
                Path::new(&format!(
                    "{}/tmp/{}.lock",
                    &fuelup_home, PROCESS_NAME
                ))
            );

            assert_eq!(
                config.logfile,
                Path::new(&format!(
                    "{}/log/{}.log",
                    &fuelup_home, PROCESS_NAME
                ))
            );

            assert_eq!(
                config.touchfile,
                Path::new(&format!(
                    "{}/tmp/{}.touch",
                    &fuelup_home, PROCESS_NAME
                ))
            );
        }
    }
}

#[cfg(test)]
mod start {
    use super::*;
    use crate::{into_recoverable, setup_fuelup_home, WatcherError};
    use nix::sys::signal::kill;
    use rusty_fork::rusty_fork_test;
    use std::{fs::File, thread::sleep, time::Duration};

    rusty_fork_test! {
        #[test]
        fn opted_out_is_true() {
            setup_fuelup_home();

            set_var("FUELUP_NO_TELEMETRY", "true");

            let mut systeminfo_watcher = SystemInfoWatcher::new();
            let result = systeminfo_watcher.start();

            // Make sure it didn't continue and init values
            assert!(result.is_ok());
            assert!(!STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 0);
        }

        #[test]
        fn opted_out_is_empty() {
            setup_fuelup_home();

            // Even though it's empty, we only care if it's set
            set_var("FUELUP_NO_TELEMETRY", "");

            let mut systeminfo_watcher = SystemInfoWatcher::new();
            let result = systeminfo_watcher.start();

            // Make sure it didn't continue and init values
            assert!(result.is_ok());
            assert!(!STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 0);
        }

        #[test]
        fn already_started() {
            setup_fuelup_home();

            STARTED.store(true, Ordering::Relaxed);
            PID.store(1, Ordering::Relaxed);

            let mut systeminfo_watcher = SystemInfoWatcher::new();
            let result = systeminfo_watcher.start();

            // Make sure it didn't continue and init values
            assert!(result.is_ok());
            assert!(STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 1);

            // Try to start it again to test re-entrance
            let result = systeminfo_watcher.start();

            assert!(result.is_ok());
            assert!(STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 1);
        }

        #[test]
        fn daemonise_failed() {
            setup_fuelup_home();

            struct DaemoniseFailed;

            impl StartHelpers for DaemoniseFailed {
                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<Pid>> {
                    Err(into_recoverable(TelemetryError::Mock))
                }
            }

            let mut systeminfo_watcher = SystemInfoWatcher::new();
            let result = systeminfo_watcher.start_with_helpers(&DaemoniseFailed);

            assert_eq!(result, Err(WatcherError::Recoverable(TelemetryError::Mock)));
            assert!(!STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 0);
        }

        #[test]
        fn daemonise_is_parent() {
            setup_fuelup_home();

            struct DaemoniseIsParent;

            impl StartHelpers for DaemoniseIsParent {
                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<Pid>> {
                    Ok(Some(Pid::from_raw(2222)))
                }
            }

            let mut systeminfo_watcher = SystemInfoWatcher::new();
            let result = systeminfo_watcher.start_with_helpers(&DaemoniseIsParent);

            assert_eq!(result, Ok(()));
            assert!(STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 2222);
        }

        #[test]
        fn new_fuel_telemetry_failed() {
            setup_fuelup_home();

            struct NewFuelTelemetryFailed;

            impl StartHelpers for NewFuelTelemetryFailed {
                fn new_fuel_telemetry(
                    &self,
                ) -> Result<(
                    tracing_subscriber::filter::Filtered<
                        tracing_subscriber::fmt::Layer<
                            tracing_subscriber::Registry,
                            tracing_subscriber::fmt::format::DefaultFields,
                            telemetry_formatter::TelemetryFormatter,
                            tracing_appender::non_blocking::NonBlocking,
                        >,
                        tracing_subscriber::EnvFilter,
                        tracing_subscriber::Registry,
                    >,
                    tracing_appender::non_blocking::WorkerGuard,
                )> {
                    Err(TelemetryError::Mock)
                }

                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<Pid>> {
                    Ok(None)
                }
            }

            let mut systeminfo_watcher = SystemInfoWatcher::new();
            let result = systeminfo_watcher.start_with_helpers(&NewFuelTelemetryFailed);

            assert_eq!(result, Err(WatcherError::Fatal(TelemetryError::Mock)));
        }

        #[test]
        fn enforce_singleton_failed() {
            setup_fuelup_home();

            struct EnforceSingletonFailed;

            impl StartHelpers for EnforceSingletonFailed {
                fn enforce_singleton(&self, _lockfile_path: &Path) -> Result<Flock<File>> {
                    Err(TelemetryError::Mock)
                }

                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<Pid>> {
                    Ok(None)
                }
            }

            let mut systeminfo_watcher = SystemInfoWatcher::new();
            let result = systeminfo_watcher.start_with_helpers(&EnforceSingletonFailed);

            assert_eq!(result, Err(WatcherError::Fatal(TelemetryError::Mock)));
        }

        #[test]
        fn poll_systeminfo_failed() {
            setup_fuelup_home();

            struct PollSysteminfoFailed;

            impl StartHelpers for PollSysteminfoFailed {
                fn poll_systeminfo(&self, _systeminfo_watcher: &SystemInfoWatcher) -> Result<()> {
                    Err(TelemetryError::Mock)
                }

                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<Pid>> {
                    Ok(None)
                }
            }

            let mut systeminfo_watcher = SystemInfoWatcher::new();
            let result = systeminfo_watcher.start_with_helpers(&PollSysteminfoFailed);

            assert_eq!(result, Err(WatcherError::Fatal(TelemetryError::Mock)));
        }

        #[test]
        fn ok() {
            setup_fuelup_home();

            let mut systeminfo_watcher = SystemInfoWatcher::new();
            let result = systeminfo_watcher.start();
            let pid = PID.load(Ordering::Relaxed);

            assert_eq!(result, Ok(()));
            assert!(STARTED.load(Ordering::Relaxed));
            assert!(pid > 0);

            // SysInfoWatcher takes a few seconds to complete, so wait long
            // enough to be run within Github Actions
            for _ in 0..30 {
                if kill(Pid::from_raw(pid), None).is_ok() {
                    sleep(Duration::from_secs(1))
                } else {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod kill {
    use super::*;
    use nix::{
        sys::{
            signal::Signal,
            wait::{waitpid, WaitPidFlag, WaitStatus},
        },
        unistd::{fork, ForkResult},
    };
    use rusty_fork::rusty_fork_test;
    use std::thread::sleep;

    rusty_fork_test! {
        #[test]
        fn kill_nobody() {
            crate::systeminfo_watcher::PID.store(0, Ordering::Relaxed);
            assert!(!SystemInfoWatcher::kill().unwrap());
        }

        #[test]
        fn kill_systeminfo_watcher() {
            let mut kill_called = false;

            match unsafe { fork() }.unwrap() {
                ForkResult::Parent { child } => {
                    loop {
                        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                            Ok(WaitStatus::StillAlive) => {
                                if !kill_called {
                                    // Since we're not daemonising, we have to set the PID manually
                                    crate::systeminfo_watcher::PID
                                        .store(child.as_raw(), Ordering::Relaxed);
                                    assert!(SystemInfoWatcher::kill().unwrap());

                                    kill_called = true;
                                    continue;
                                }
                            }
                            Ok(WaitStatus::Signaled(child_pid, signal, _)) => {
                                assert_eq!(child_pid, child);
                                assert_eq!(signal, Signal::SIGKILL);
                                break;
                            }
                            _ => panic!("Child process terminated unexpectedly"),
                        }
                    }
                }
                ForkResult::Child => loop {
                    sleep(Duration::from_secs(10));
                },
            }
        }
    }
}

#[cfg(test)]
mod poll_systeminfo {
    use super::*;
    use crate::setup_fuelup_home;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use rusty_fork::rusty_fork_test;
    use std::{
        io::{BufRead, BufReader},
        time::SystemTime,
    };
    use sysinfo::System;

    rusty_fork_test! {
        #[test]
        fn create_locked_touchfile_failed() {
            setup_fuelup_home();

            struct CreateLockedTouchfileFailed;

            impl PollSysteminfoHelpers for CreateLockedTouchfileFailed {
                fn create_and_lock_touchfile(&self, _touchfile: &Path) -> Result<Flock<File>> {
                    Err(TelemetryError::Mock)
                }
            }

            let systeminfo_watcher = SystemInfoWatcher::new();
            let result =
                systeminfo_watcher.poll_systeminfo_with_helpers(&mut CreateLockedTouchfileFailed);

            assert_eq!(result, Err(TelemetryError::Mock));
        }

        #[test]
        fn open_and_lock_touchfile_failed() {
            setup_fuelup_home();

            OpenOptions::new()
                .create(true)
                .append(true)
                .open(Path::new(&config().unwrap().touchfile))
                .unwrap();

            struct OpenAndLockTouchfileFailed;

            impl PollSysteminfoHelpers for OpenAndLockTouchfileFailed {
                fn open_and_lock_touchfile(&self, _touchfile: &Path) -> Result<Flock<File>> {
                    Err(TelemetryError::Mock)
                }
            }

            let systeminfo_watcher = SystemInfoWatcher::new();
            let result =
                systeminfo_watcher.poll_systeminfo_with_helpers(&mut OpenAndLockTouchfileFailed);

            assert_eq!(result, Err(TelemetryError::Mock));
        }

        #[test]
        fn now_failed() {
            setup_fuelup_home();

            OpenOptions::new()
                .create(true)
                .append(true)
                .open(Path::new(&config().unwrap().touchfile))
                .unwrap();

            struct NowFailed;

            impl PollSysteminfoHelpers for NowFailed {
                fn now(&self) -> nix::Result<nix::sys::time::TimeSpec> {
                    Err(nix::errno::Errno::EOWNERDEAD)
                }
            }

            let systeminfo_watcher = SystemInfoWatcher::new();
            let result = systeminfo_watcher.poll_systeminfo_with_helpers(&mut NowFailed);

            assert_eq!(
                result,
                Err(TelemetryError::Nix(
                    nix::errno::Errno::EOWNERDEAD.to_string()
                ))
            );
        }

        #[test]
        fn fstat_failed() {
            setup_fuelup_home();

            struct FstatFailed;

            OpenOptions::new()
                .create(true)
                .append(true)
                .open(Path::new(&config().unwrap().touchfile))
                .unwrap();

            impl PollSysteminfoHelpers for FstatFailed {
                fn fstat(&self, _fd: RawFd) -> nix::Result<libc::stat> {
                    Err(nix::errno::Errno::EOWNERDEAD)
                }
            }

            let systeminfo_watcher = SystemInfoWatcher::new();
            let result = systeminfo_watcher.poll_systeminfo_with_helpers(&mut FstatFailed);

            assert_eq!(
                result,
                Err(TelemetryError::Nix(
                    nix::errno::Errno::EOWNERDEAD.to_string()
                ))
            );
        }

        #[test]
        fn recently_polled() {
            setup_fuelup_home();

            OpenOptions::new()
                .create(true)
                .append(true)
                .open(Path::new(&config().unwrap().touchfile))
                .unwrap();

            let systeminfo_watcher = SystemInfoWatcher::new();
            let result = systeminfo_watcher.poll_systeminfo();

            assert_eq!(result, Ok(()));
        }

        #[test]
        fn detect_vm_failed() {
            setup_fuelup_home();

            let touchfile = OpenOptions::new()
                .create(true)
                .append(true)
                .open(Path::new(&config().unwrap().touchfile))
                .unwrap();

            touchfile
                .set_modified(
                    SystemTime::now() - Duration::from_secs(config().unwrap().interval as u64),
                )
                .unwrap();

            struct DetectVmFailed;

            impl PollSysteminfoHelpers for DetectVmFailed {
                fn detect_vm(&self) -> Result<&'static str> {
                    Err(TelemetryError::Mock)
                }
            }

            let systeminfo_watcher = SystemInfoWatcher::new();
            let result = systeminfo_watcher.poll_systeminfo_with_helpers(&mut DetectVmFailed);

            assert_eq!(result, Err(TelemetryError::Mock));
        }

        #[test]
        fn set_len_failed() {
            setup_fuelup_home();

            let touchfile = OpenOptions::new()
                .create(true)
                .append(true)
                .open(Path::new(&config().unwrap().touchfile))
                .unwrap();

            touchfile
                .set_modified(
                    SystemTime::now() - Duration::from_secs(config().unwrap().interval as u64),
                )
                .unwrap();

            struct SetLenFailed;

            impl PollSysteminfoHelpers for SetLenFailed {
                fn set_len(&self, _flock: &Flock<File>, _len: u64) -> std::io::Result<()> {
                    Err(std::io::Error::new(std::io::ErrorKind::Other, "Mock error"))
                }
            }

            let systeminfo_watcher = SystemInfoWatcher::new();
            let result = systeminfo_watcher.poll_systeminfo_with_helpers(&mut SetLenFailed);

            assert_eq!(result, Err(TelemetryError::IO("Mock error".to_string())));
        }

        #[test]
        fn sync_all_failed() {
            setup_fuelup_home();

            let touchfile = OpenOptions::new()
                .create(true)
                .append(true)
                .open(Path::new(&config().unwrap().touchfile))
                .unwrap();

            touchfile
                .set_modified(
                    SystemTime::now() - Duration::from_secs(config().unwrap().interval as u64),
                )
                .unwrap();

            struct SyncAllFailed;

            impl PollSysteminfoHelpers for SyncAllFailed {
                fn sync_all(&self, _flock: &Flock<File>) -> std::io::Result<()> {
                    Err(std::io::Error::new(std::io::ErrorKind::Other, "Mock error"))
                }
            }

            let systeminfo_watcher = SystemInfoWatcher::new();
            let result = systeminfo_watcher.poll_systeminfo_with_helpers(&mut SyncAllFailed);

            assert_eq!(result, Err(TelemetryError::IO("Mock error".to_string())));
        }

        #[test]
        fn ok() {
            setup_fuelup_home();

            let touchfile = OpenOptions::new()
                .create(true)
                .append(true)
                .open(Path::new(&config().unwrap().touchfile))
                .unwrap();

            let old_modified =
                SystemTime::now() - Duration::from_secs(config().unwrap().interval * 2);

            touchfile.set_modified(old_modified).unwrap();

            let systeminfo_watcher = SystemInfoWatcher::new();

            // Create a telemetry layer so we the telemetry file is written to
            set_var("TELEMETRY_PKG_NAME", "systeminfo_watcher");
            let (telemetry_layer, _guard) = crate::new!().unwrap();
            tracing_subscriber::registry().with(telemetry_layer).init();

            let result = systeminfo_watcher.poll_systeminfo();
            drop(_guard);

            assert_eq!(result, Ok(()));
            assert!(old_modified < touchfile.metadata().unwrap().modified().unwrap());

            // Test some fields were written to the telemetry file

            let telemetry_file =
                std::fs::read_dir(Path::new(&telemetry_config().unwrap().fuelup_tmp))
                    .unwrap()
                    .find(|file| {
                        file.as_ref()
                            .unwrap()
                            .path()
                            .to_str()
                            .unwrap()
                            .contains("systeminfo_watcher.telemetry.")
                    });

            assert!(telemetry_file.is_some());

            let body = {
                let mut body = Vec::new();

                let lines =
                    BufReader::new(File::open(telemetry_file.unwrap().unwrap().path()).unwrap())
                        .lines()
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .unwrap();

                for base64_line in lines {
                    let decoded_line = STANDARD.decode(&base64_line).unwrap();
                    let line = String::from_utf8(decoded_line).unwrap();

                    body.push(line);
                }

                body.join("\n")
            };

            let mut sysinfo = System::new();

            sysinfo.refresh_cpu_usage();
            std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
            sysinfo.refresh_cpu_usage();

            let cpus = sysinfo.cpus();
            let cpu_brand = cpus
                .first()
                .map_or_else(String::default, |cpu| cpu.brand().into());

            assert!(body.contains(&format!("cpu_arch=\"{}\"", System::cpu_arch())));
            assert!(body.contains(&format!("cpu_count={}", cpus.len())));
            assert!(body.contains(&format!("cpu_brand=\"{}\"", cpu_brand)));

            assert!(body.contains(&format!(
                "os_long_name=\"{}\"",
                System::long_os_version().unwrap_or_default()
            )));

            assert!(body.contains(&format!(
                "kernel_version=\"{}\"",
                System::kernel_version().unwrap_or_default()
            )));
        }
    }
}
