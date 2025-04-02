use crate::{
    self as fuel_telemetry, daemonise,
    errors::{into_recoverable, TelemetryError},
    get_process_name, info_telemetry, span_telemetry, telemetry_config, telemetry_formatter,
    EnvSetting, Result, WatcherResult,
};
use nix::{
    sys::signal::kill,
    unistd::{getpid, Pid as NixPid},
};
use std::{
    env::{set_var, var},
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    process::exit,
    sync::{
        atomic::{AtomicBool, AtomicI32, Ordering},
        LazyLock,
    },
    thread::sleep,
    time::{Duration, Instant},
};
use sysinfo::{Pid as SysinfoPid, ProcessRefreshKind, ProcessesToUpdate, System};
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

//
// Module config
//

const PROCESS_NAME: &str = "telemetry-process-watcher";
const PROCESSWATCHER_CHECK_INTERVAL: &str = "1";
const PROCESSWATCHER_MEASURE_INTERVAL: &str = "60";
const TELEMETRY_PKG_NAME: &str = "process_watcher";

struct ProcessWatcherConfig {
    // The path to its logfile
    logfile: PathBuf,
    // The interval between checking if the process is still alive (in seconds)
    check_interval: Duration,
    // The interval between measuring process metrics (in seconds)
    measure_interval: Duration,
}

fn config() -> Result<&'static ProcessWatcherConfig> {
    static PROCESS_WATCHER_CONFIG: LazyLock<Result<ProcessWatcherConfig>> = LazyLock::new(|| {
        let get_env = |key, default| EnvSetting::new(key, default).get();

        let check_interval = get_env(
            "PROCESSWATCHER_CHECK_INTERVAL",
            PROCESSWATCHER_CHECK_INTERVAL,
        )
        .parse()
        .map(Duration::from_secs)?;

        let measure_interval = get_env(
            "PROCESSWATCHER_MEASURE_INTERVAL",
            PROCESSWATCHER_MEASURE_INTERVAL,
        )
        .parse()
        .map(Duration::from_secs)?;

        Ok(ProcessWatcherConfig {
            check_interval,
            measure_interval,
            logfile: Path::new(&telemetry_config()?.fuelup_log)
                .join(format!("{}.log", PROCESS_NAME)),
        })
    });

    PROCESS_WATCHER_CONFIG
        .as_ref()
        .map_err(|e| TelemetryError::InvalidConfig(e.to_string()))
}

pub struct ProcessWatcher {
    // The name of the process used as the "measurement" for InfluxDB
    exe_name: String,

    // The PID we are watching (Nix PID)
    pid_to_watch_nix: NixPid,
    // The PID we are watching (Sysinfo PID)
    pid_to_watch_sysinfo: SysinfoPid,

    // The timer for checking if the process is still alive
    check_timer: Timer,
    // The timer for measuring the process metrics
    measure_timer: Timer,

    // Max metrics values we've seen so far
    resident_memory: u64,
    virtual_memory: u64,
    run_time: u64,
    cpu_usage: f32,
}

// Prevent recursive calls to start()
static STARTED: AtomicBool = AtomicBool::new(false);

/// The PID of the currently running `ProcessWatcher` daemon
pub static PID: AtomicI32 = AtomicI32::new(0);

impl ProcessWatcher {
    pub fn new() -> Result<Self> {
        Self::new_with_pid(getpid())
    }

    pub fn new_with_pid(pid_to_watch: NixPid) -> Result<Self> {
        Ok(Self {
            exe_name: get_process_name(),

            pid_to_watch_nix: pid_to_watch,
            pid_to_watch_sysinfo: SysinfoPid::from(pid_to_watch.as_raw() as usize),

            check_timer: Timer::new(config()?.check_interval),
            measure_timer: Timer::new(config()?.measure_interval),

            resident_memory: 0,
            virtual_memory: 0,
            run_time: 0,
            cpu_usage: 0.0,
        })
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
                // We are the child process, so continue as the `ProcessWatcher`
                PID.store(getpid().as_raw(), Ordering::Relaxed);
            }
        }

        set_var("TELEMETRY_PKG_NAME", TELEMETRY_PKG_NAME);
        let (telemetry_layer, _guard) = helpers.new_fuel_telemetry()?;
        tracing_subscriber::registry().with(telemetry_layer).init();

        // Take a measurement now before going to sleep
        helpers.measure_process(self);

        while helpers.process_is_alive(self) {
            self.check_timer.last_measure = helpers.get_instant_now();

            if helpers.measure_timer_is_ready(self) {
                helpers.measure_process(self);
            }

            let next_ready_timer =
                helpers.get_next_ready_timer(&[&self.check_timer, &self.measure_timer]);

            helpers.sleep(next_ready_timer.duration_until_ready());
        }

        // Record metrics one last time
        helpers.record_metrics(self, false);

        helpers.exit(0);
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
    fn daemonise(&self, logfile: &PathBuf) -> WatcherResult<Option<NixPid>> {
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

    fn measure_process(&self, process_watcher: &mut ProcessWatcher) {
        let mut sysinfo = System::new();

        // Need to refresh twice with delay in between so that there are enough
        // data points for "cpu_usage". See `sysinfo` docs for more details.
        sysinfo.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[process_watcher.pid_to_watch_sysinfo]),
            true,
            ProcessRefreshKind::nothing().with_memory().with_cpu(),
        );

        sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);

        sysinfo.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[process_watcher.pid_to_watch_sysinfo]),
            true,
            ProcessRefreshKind::nothing().with_memory().with_cpu(),
        );

        let Some(process) = sysinfo.process(process_watcher.pid_to_watch_sysinfo) else {
            // Process has likely exited, so return and deal with it at a higher level
            return;
        };

        // Store the metrics so we can find the max values for the entire run
        let residential_memory = process.memory();
        let virtual_memory = process.virtual_memory();
        let run_time = process.run_time();
        let cpu_usage = process.cpu_usage();

        process_watcher.resident_memory = process_watcher.resident_memory.max(residential_memory);
        process_watcher.virtual_memory = process_watcher.virtual_memory.max(virtual_memory);
        process_watcher.run_time = process_watcher.run_time.max(run_time);
        process_watcher.cpu_usage = process_watcher.cpu_usage.max(cpu_usage);

        // Record the metrics to disk
        self.record_metrics(process_watcher, true);

        // Restart the measure timer
        process_watcher.measure_timer.last_measure = Instant::now();
    }

    fn process_is_alive(&self, process_watcher: &ProcessWatcher) -> bool {
        kill(process_watcher.pid_to_watch_nix, None).is_ok()
    }

    fn get_instant_now(&self) -> Instant {
        Instant::now()
    }

    fn measure_timer_is_ready(&self, process_watcher: &ProcessWatcher) -> bool {
        process_watcher.measure_timer.is_ready()
    }

    fn get_next_ready_timer<'a>(&self, timers: &[&'a Timer]) -> &'a Timer {
        Timer::next_ready_timer(timers)
    }

    fn sleep(&self, duration: Duration) {
        sleep(duration)
    }

    fn record_metrics(&self, process_watcher: &ProcessWatcher, running: bool) {
        info_telemetry!(
            exe_name = process_watcher.exe_name,
            running,
            run_time = process_watcher.run_time,
            cpu_usage = f64::from(process_watcher.cpu_usage),
            resident_memory = process_watcher.resident_memory,
            virtual_memory = process_watcher.virtual_memory,
        );
    }

    fn exit(&self, code: i32) -> ! {
        exit(code)
    }
}

#[derive(Default, Clone)]
struct DefaultStartHelpers;
impl StartHelpers for DefaultStartHelpers {}

/// A helper struct to manage timers used in the `ProcessWatcher`
struct Timer {
    last_measure: Instant,
    interval: Duration,
}

// A zero duration timer used as a default value
static ZERO_TIMER: LazyLock<Timer> = LazyLock::new(|| Timer {
    last_measure: Instant::now(),
    interval: Duration::from_secs(0),
});

impl Timer {
    fn new(interval: Duration) -> Self {
        Self {
            last_measure: Instant::now(),
            interval,
        }
    }

    /// Find the timer in the haystack that's going to go off next
    fn next_ready_timer<'a>(timers: &[&'a Timer]) -> &'a Timer {
        timers
            .iter()
            .min_by_key(|t| t.duration_until_ready())
            .copied()
            .unwrap_or(&ZERO_TIMER)
    }

    /// Check if the timer is ready to go off
    fn is_ready(&self) -> bool {
        Instant::now().duration_since(self.last_measure) >= self.interval
    }

    /// How long until the timer will go off
    fn duration_until_ready(&self) -> Duration {
        self.interval
            .saturating_sub(Instant::now().duration_since(self.last_measure))
    }
}

#[cfg(test)]
mod config {
    use super::*;
    use crate::setup_fuelup_home;
    use dirs::home_dir;
    use rusty_fork::rusty_fork_test;
    use std::env::set_var;

    rusty_fork_test! {
        #[test]
        fn all_unset() {
            let config = config().unwrap();

            assert_eq!(
                config.check_interval,
                Duration::from_secs(PROCESSWATCHER_CHECK_INTERVAL.parse().unwrap())
            );

            assert_eq!(
                config.measure_interval,
                Duration::from_secs(PROCESSWATCHER_MEASURE_INTERVAL.parse().unwrap())
            );

            assert_eq!(
                config.logfile,
                PathBuf::from(
                    &home_dir()
                        .unwrap()
                        .join(format!(".fuelup/log/{}.log", PROCESS_NAME))
                )
            );
        }

        #[test]
        fn process_watcher_check_interval_invalid() {
            set_var("PROCESSWATCHER_CHECK_INTERVAL", "invalid interval");

            assert_eq!(
                config().err(),
                Some(TelemetryError::InvalidConfig(
                    TelemetryError::Parse("invalid digit found in string".to_string()).into()
                ))
            );
        }

        #[test]
        fn process_watcher_check_interval_set() {
            set_var("PROCESSWATCHER_CHECK_INTERVAL", "2222");
            assert_eq!(config().unwrap().check_interval, Duration::from_secs(2222));
        }

        #[test]
        fn process_watcher_measure_interval_invalid() {
            set_var("PROCESSWATCHER_MEASURE_INTERVAL", "invalid interval");
            assert_eq!(
                config().err(),
                Some(TelemetryError::InvalidConfig(
                    TelemetryError::Parse("invalid digit found in string".to_string()).into()
                ))
            );
        }

        #[test]
        fn process_watcher_measure_interval_set() {
            set_var("PROCESSWATCHER_MEASURE_INTERVAL", "2222");
            assert_eq!(
                config().unwrap().measure_interval,
                Duration::from_secs(2222)
            );
        }

        #[test]
        fn all_set() {
            setup_fuelup_home();
            let fuelup_home = var("FUELUP_HOME").unwrap();

            set_var("PROCESSWATCHER_CHECK_INTERVAL", "2222");
            set_var("PROCESSWATCHER_MEASURE_INTERVAL", "3333");

            let config = config().unwrap();

            assert_eq!(config.check_interval, Duration::from_secs(2222));
            assert_eq!(config.measure_interval, Duration::from_secs(3333));

            assert_eq!(
                config.logfile,
                PathBuf::from(&fuelup_home).join(format!("log/{}.log", PROCESS_NAME))
            );
        }
    }
}

#[cfg(test)]
mod new {
    use super::*;
    use crate::setup_fuelup_home;
    use rusty_fork::rusty_fork_test;

    rusty_fork_test! {
        #[test]
        fn new() {
            setup_fuelup_home();

            let process_watcher = ProcessWatcher::new().unwrap();

            assert_eq!(process_watcher.exe_name, get_process_name());

            assert_eq!(process_watcher.pid_to_watch_nix, getpid());
            assert_eq!(
                process_watcher.pid_to_watch_sysinfo,
                SysinfoPid::from(getpid().as_raw() as usize)
            );

            assert_eq!(process_watcher.check_timer.interval, Duration::from_secs(1));
            assert_eq!(
                process_watcher.measure_timer.interval,
                Duration::from_secs(60)
            );

            assert_eq!(process_watcher.resident_memory, 0);
            assert_eq!(process_watcher.virtual_memory, 0);
            assert_eq!(process_watcher.run_time, 0);
            assert_eq!(process_watcher.cpu_usage, 0.0);
        }

        #[test]
        fn new_with_pid() {
            setup_fuelup_home();

            let process_watcher = ProcessWatcher::new_with_pid(NixPid::from_raw(1)).unwrap();

            assert_eq!(process_watcher.exe_name, get_process_name());

            assert_eq!(process_watcher.pid_to_watch_nix, NixPid::from_raw(1));
            assert_eq!(process_watcher.pid_to_watch_sysinfo, SysinfoPid::from(1));

            assert_eq!(process_watcher.check_timer.interval, Duration::from_secs(1));
            assert_eq!(
                process_watcher.measure_timer.interval,
                Duration::from_secs(60)
            );

            assert_eq!(process_watcher.resident_memory, 0);
            assert_eq!(process_watcher.virtual_memory, 0);
            assert_eq!(process_watcher.run_time, 0);
            assert_eq!(process_watcher.cpu_usage, 0.0);
        }
    }
}

// The following tests verify that the expected paths are taken on error. The
// testing of the values themselves is handled in the modules after this one.

#[cfg(test)]
mod start {
    use super::*;
    use crate::{errors::into_fatal, setup_fuelup_home, WatcherError};
    use nix::{
        sys::wait::{waitpid, WaitStatus},
        unistd::{dup2, fork, pipe, ForkResult},
    };
    use rusty_fork::rusty_fork_test;
    use std::{
        env::set_var,
        fs::File,
        io::{stdout, Read, Write},
        os::fd::{AsRawFd, FromRawFd, IntoRawFd},
        sync::Arc,
    };

    rusty_fork_test! {
        #[test]
        fn opted_out_is_true() {
            setup_fuelup_home();

            set_var("FUELUP_NO_TELEMETRY", "true");

            let mut process_watcher = ProcessWatcher::new().unwrap();
            let result = process_watcher.start();

            assert_eq!(result, Ok(()));
            assert!(!STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 0);

            assert_eq!(process_watcher.resident_memory, 0);
            assert_eq!(process_watcher.virtual_memory, 0);
            assert_eq!(process_watcher.run_time, 0);
            assert_eq!(process_watcher.cpu_usage, 0.0);
        }

        #[test]
        fn opted_out_is_empty() {
            setup_fuelup_home();

            // Even though it's empty, we only care if it's set
            set_var("FUELUP_NO_TELEMETRY", "");

            let mut process_watcher = ProcessWatcher::new().unwrap();
            let result = process_watcher.start();

            assert_eq!(result, Ok(()));
            assert!(!STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 0);

            assert_eq!(process_watcher.resident_memory, 0);
            assert_eq!(process_watcher.virtual_memory, 0);
            assert_eq!(process_watcher.run_time, 0);
            assert_eq!(process_watcher.cpu_usage, 0.0);
        }

        #[test]
        fn already_started() {
            setup_fuelup_home();

            STARTED.store(true, Ordering::Relaxed);
            PID.store(1, Ordering::Relaxed);

            let mut process_watcher = ProcessWatcher::new().unwrap();
            let result = process_watcher.start();

            assert_eq!(result, Ok(()));
            assert!(STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 1);

            assert_eq!(process_watcher.resident_memory, 0);
            assert_eq!(process_watcher.virtual_memory, 0);
            assert_eq!(process_watcher.run_time, 0);
            assert_eq!(process_watcher.cpu_usage, 0.0);

            // Try to start it again to test re-entrance
            let result = process_watcher.start();

            assert_eq!(result, Ok(()));
            assert!(STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 1);

            assert_eq!(process_watcher.resident_memory, 0);
            assert_eq!(process_watcher.virtual_memory, 0);
            assert_eq!(process_watcher.run_time, 0);
            assert_eq!(process_watcher.cpu_usage, 0.0);
        }

        #[test]
        fn daemonise_failed() {
            setup_fuelup_home();

            struct DaemoniseFailed;

            impl StartHelpers for DaemoniseFailed {
                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<NixPid>> {
                    Err(into_fatal(TelemetryError::Mock))
                }
            }

            let mut process_watcher = ProcessWatcher::new().unwrap();
            let result = process_watcher.start_with_helpers(&DaemoniseFailed);

            assert_eq!(
                result.err(),
                Some(WatcherError::Fatal(TelemetryError::Mock))
            );
            assert!(!STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 0);
        }

        #[test]
        fn daemonise_is_parent() {
            setup_fuelup_home();

            struct DaemoniseIsParent;

            impl StartHelpers for DaemoniseIsParent {
                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<NixPid>> {
                    Ok(Some(NixPid::from_raw(1337)))
                }
            }

            let mut process_watcher = ProcessWatcher::new().unwrap();
            let result = process_watcher.start_with_helpers(&DaemoniseIsParent);

            assert_eq!(result, Ok(()));
            assert!(STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 1337);
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

                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<NixPid>> {
                    Ok(None)
                }
            }

            let mut process_watcher = ProcessWatcher::new().unwrap();
            let result = process_watcher.start_with_helpers(&NewFuelTelemetryFailed);

            assert_eq!(
                result.err(),
                Some(WatcherError::Fatal(TelemetryError::Mock))
            );
        }

        #[test]
        fn process_is_dead() {
            setup_fuelup_home();

            #[derive(Default, Clone)]
            struct ProcessIsDead;

            impl StartHelpers for ProcessIsDead {
                fn process_is_alive(&self, _process_watcher: &ProcessWatcher) -> bool {
                    false
                }

                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<NixPid>> {
                    Ok(None)
                }

                fn exit(&self, _code: i32) -> ! {
                    // Test we actually exited via our expected code path
                    exit(99);
                }
            }

            match unsafe { fork() }.unwrap() {
                ForkResult::Parent { child } => match waitpid(child, None).unwrap() {
                    WaitStatus::Exited(_, code) => {
                        assert_eq!(code, 99);
                    }
                    _ => panic!("Child did not exit normally"),
                },
                ForkResult::Child => {
                    let mut process_watcher = ProcessWatcher::new().unwrap();
                    let _ = process_watcher.start_with_helpers(&ProcessIsDead);

                    // Incorrect status code that rusty_fork_test!() will detect
                    exit(86);
                }
            }
        }

        #[test]
        fn measure_process_called_when_ready() {
            setup_fuelup_home();

            #[derive(Default, Clone)]
            struct MeasureProcessCalledWhenReady {
                default_helpers: DefaultStartHelpers,
                measure_process_called_count: Arc<AtomicI32>,
            }

            impl StartHelpers for MeasureProcessCalledWhenReady {
                fn measure_process(&self, process_watcher: &mut ProcessWatcher) {
                    self.measure_process_called_count
                        .fetch_add(1, Ordering::Relaxed);

                    stdout()
                        .write_all(
                            format!(
                                "measure_process_called_count: {}",
                                self.measure_process_called_count.load(Ordering::Relaxed)
                            )
                            .as_bytes(),
                        )
                        .unwrap();
                    stdout().flush().unwrap();

                    self.default_helpers.measure_process(process_watcher);
                }

                fn process_is_alive(&self, _process_watcher: &ProcessWatcher) -> bool {
                    stdout()
                        .write_all("process_is_alive called".as_bytes())
                        .unwrap();
                    stdout().flush().unwrap();

                    self.measure_process_called_count.load(Ordering::Relaxed) < 2
                }

                fn get_instant_now(&self) -> Instant {
                    stdout()
                        .write_all("get_instant_now called".as_bytes())
                        .unwrap();
                    stdout().flush().unwrap();

                    Instant::now()
                }

                fn measure_timer_is_ready(&self, _process_watcher: &ProcessWatcher) -> bool {
                    stdout()
                        .write_all("measure_timer_is_ready called".as_bytes())
                        .unwrap();
                    stdout().flush().unwrap();

                    true
                }

                fn get_next_ready_timer<'a>(&self, timers: &[&'a Timer]) -> &'a Timer {
                    stdout()
                        .write_all("get_next_ready_timer called".as_bytes())
                        .unwrap();
                    stdout().flush().unwrap();

                    timers[0]
                }

                fn sleep(&self, _duration: Duration) {
                    stdout().write_all("sleep called".as_bytes()).unwrap();
                    stdout().flush().unwrap();
                }

                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<NixPid>> {
                    Ok(None)
                }

                fn record_metrics(&self, _process_watcher: &ProcessWatcher, _running: bool) {
                    stdout()
                        .write_all("record_metrics called".as_bytes())
                        .unwrap();
                    stdout().flush().unwrap();
                }

                fn exit(&self, _code: i32) -> ! {
                    stdout().write_all("exit called".as_bytes()).unwrap();
                    stdout().flush().unwrap();

                    // Test we actually exited via our expected code path
                    exit(99);
                }
            }

            let (read_fd, write_fd) = pipe().unwrap();
            let mut pipe_read = unsafe { File::from_raw_fd(read_fd.into_raw_fd()) };
            let pipe_write = unsafe { File::from_raw_fd(write_fd.into_raw_fd()) };

            match unsafe { fork() }.unwrap() {
                ForkResult::Parent { child } => {
                    drop(pipe_write);

                    let mut output = String::new();
                    pipe_read.read_to_string(&mut output).unwrap();

                    assert!(output.contains("measure_process_called_count: 2"));
                    assert!(output.contains("process_is_alive called"));
                    assert!(output.contains("get_instant_now called"));
                    assert!(output.contains("measure_timer_is_ready called"));
                    assert!(output.contains("get_next_ready_timer called"));
                    assert!(output.contains("sleep called"));
                    assert!(output.contains("record_metrics called"));
                    assert!(output.contains("exit called"));

                    match waitpid(child, None).unwrap() {
                        WaitStatus::Exited(_, code) => {
                            assert_eq!(code, 99);
                        }
                        _ => panic!("Child did not exit normally"),
                    }
                }
                ForkResult::Child => {
                    drop(pipe_read);
                    dup2(pipe_write.as_raw_fd(), 1).unwrap();

                    let start_helpers = MeasureProcessCalledWhenReady::default();
                    let mut process_watcher = ProcessWatcher::new().unwrap();
                    let _ = process_watcher.start_with_helpers(&start_helpers);

                    // Incorrect status code that rusty_fork_test!() will detect
                    exit(86);
                }
            }
        }
    }
}

#[cfg(test)]
mod measure_process {
    use super::*;
    use crate::setup_fuelup_home;
    use nix::{
        sys::{
            signal::{kill, Signal},
            wait::{waitpid, WaitPidFlag, WaitStatus},
        },
        unistd::{fork, ForkResult},
    };
    use rusty_fork::rusty_fork_test;
    use std::sync::Arc;

    rusty_fork_test! {
        #[test]
        fn process_died() {
            setup_fuelup_home();

            struct ProcessDied;
            impl StartHelpers for ProcessDied {}

            let mut kill_called = false;

            match unsafe { fork() }.unwrap() {
                ForkResult::Parent { child } => {
                    let helpers = ProcessDied;
                    let mut process_watcher =
                        ProcessWatcher::new_with_pid(NixPid::from_raw(child.as_raw())).unwrap();

                    assert_eq!(process_watcher.resident_memory, 0);
                    assert_eq!(process_watcher.virtual_memory, 0);
                    assert_eq!(process_watcher.run_time, 0);
                    assert_eq!(process_watcher.cpu_usage, 0.0);

                    loop {
                        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                            Ok(WaitStatus::StillAlive) => {
                                if !kill_called {
                                    kill(child, Signal::SIGKILL).unwrap();
                                    kill_called = true;
                                }
                            }
                            Ok(WaitStatus::Signaled(child_pid, signal, _)) => {
                                assert_eq!(child_pid, child);
                                assert_eq!(signal, Signal::SIGKILL);

                                helpers.measure_process(&mut process_watcher);

                                assert_eq!(process_watcher.resident_memory, 0);
                                assert_eq!(process_watcher.virtual_memory, 0);
                                assert_eq!(process_watcher.run_time, 0);
                                assert_eq!(process_watcher.cpu_usage, 0.0);

                                break;
                            }
                            _ => panic!("Child process terminated unexpectedly"),
                        }
                    }
                }
                ForkResult::Child => {
                    loop {
                        // Sleep until we're killed off
                        sleep(Duration::from_secs(1));
                    }
                }
            }
        }

        #[test]
        fn ok() {
            setup_fuelup_home();

            #[derive(Default, Clone)]
            struct AOk {
                record_metrics_called: Arc<AtomicBool>,
            }

            impl StartHelpers for AOk {
                fn record_metrics(&self, _process_watcher: &ProcessWatcher, _running: bool) {
                    self.record_metrics_called.store(true, Ordering::Relaxed);
                }
            }

            let mut process_watcher = ProcessWatcher::new().unwrap();

            assert_eq!(process_watcher.resident_memory, 0);
            assert_eq!(process_watcher.virtual_memory, 0);
            assert_eq!(process_watcher.run_time, 0);
            assert_eq!(process_watcher.cpu_usage, 0.0);

            let helpers = AOk::default();
            helpers.measure_process(&mut process_watcher);

            let at_least_one_metric_is_set = process_watcher.resident_memory > 0
                || process_watcher.virtual_memory > 0
                || process_watcher.run_time > 0
                || process_watcher.cpu_usage > 0.0;

            assert!(at_least_one_metric_is_set);

            assert!(helpers.record_metrics_called.load(Ordering::Relaxed));
        }
    }
}

#[cfg(test)]
mod process_is_alive {
    use super::*;
    use crate::setup_fuelup_home;
    use nix::{
        sys::{
            signal::{kill, Signal},
            wait::{waitpid, WaitPidFlag, WaitStatus},
        },
        unistd::{fork, ForkResult},
    };
    use rusty_fork::rusty_fork_test;

    rusty_fork_test! {
        #[test]
        fn ok() {
            setup_fuelup_home();

            struct AOk;
            impl StartHelpers for AOk {}

            let mut kill_called = false;

            match unsafe { fork() }.unwrap() {
                ForkResult::Parent { child } => {
                    let helpers = AOk;
                    let process_watcher =
                        ProcessWatcher::new_with_pid(NixPid::from_raw(child.as_raw())).unwrap();

                    assert!(helpers.process_is_alive(&process_watcher));

                    loop {
                        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                            Ok(WaitStatus::StillAlive) => {
                                if !kill_called {
                                    kill(child, Signal::SIGKILL).unwrap();
                                    kill_called = true;
                                }
                            }
                            Ok(WaitStatus::Signaled(child_pid, signal, _)) => {
                                assert_eq!(child_pid, child);
                                assert_eq!(signal, Signal::SIGKILL);
                                assert!(!helpers.process_is_alive(&process_watcher));
                                break;
                            }
                            _ => panic!("Child process terminated unexpectedly"),
                        }
                    }
                }
                ForkResult::Child => {
                    loop {
                        // Sleep until we're killed off
                        sleep(Duration::from_secs(1));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod measure_timer_is_ready {
    use super::*;
    use crate::setup_fuelup_home;
    use rusty_fork::rusty_fork_test;

    rusty_fork_test! {
        #[test]
        fn not_ready() {
            setup_fuelup_home();

            struct NotReady;
            impl StartHelpers for NotReady {}

            let mut process_watcher = ProcessWatcher::new().unwrap();

            let measure_interval = process_watcher.measure_timer.interval;
            process_watcher.measure_timer.last_measure = Instant::now() + (measure_interval * 2);

            let helpers = NotReady;
            assert!(!helpers.measure_timer_is_ready(&process_watcher));
        }

        #[test]
        fn equal() {
            setup_fuelup_home();

            struct Equal;
            impl StartHelpers for Equal {}

            let mut process_watcher = ProcessWatcher::new().unwrap();

            let measure_interval = process_watcher.measure_timer.interval;
            process_watcher.measure_timer.last_measure = Instant::now() - measure_interval;

            let helpers = Equal;
            assert!(helpers.measure_timer_is_ready(&process_watcher));
        }

        #[test]
        fn late() {
            setup_fuelup_home();

            struct Late;
            impl StartHelpers for Late {}

            let mut process_watcher = ProcessWatcher::new().unwrap();

            let measure_interval = process_watcher.measure_timer.interval;
            process_watcher.measure_timer.last_measure = Instant::now() - (measure_interval * 2);

            let helpers = Late;
            assert!(helpers.measure_timer_is_ready(&process_watcher));
        }
    }
}

#[cfg(test)]
mod get_next_ready_timer {
    use super::*;
    use crate::setup_fuelup_home;
    use rusty_fork::rusty_fork_test;

    rusty_fork_test! {
        #[test]
        fn no_timers() {
            setup_fuelup_home();

            struct NoTimers;
            impl StartHelpers for NoTimers {}

            let helpers = NoTimers;
            let results = helpers.get_next_ready_timer(&[]);

            assert_eq!(results.interval, ZERO_TIMER.interval);
            assert_eq!(results.last_measure, ZERO_TIMER.last_measure);
        }

        #[test]
        fn one_timer() {
            setup_fuelup_home();

            struct OneTimer;
            impl StartHelpers for OneTimer {}

            let helpers = OneTimer;
            let timer = Timer::new(Duration::from_secs(1));
            let results = helpers.get_next_ready_timer(&[&timer]);

            assert_eq!(results.interval, timer.interval);
            assert_eq!(results.last_measure, timer.last_measure);
        }

        #[test]
        fn two_timers() {
            setup_fuelup_home();

            struct TwoTimers;
            impl StartHelpers for TwoTimers {}

            let helpers = TwoTimers;
            let timer1 = Timer::new(Duration::from_secs(10));
            let timer2 = Timer::new(Duration::from_secs(20));

            let results = helpers.get_next_ready_timer(&[&timer1, &timer2]);
            assert_eq!(results.interval, timer1.interval);
            assert_eq!(results.last_measure, timer1.last_measure);

            let results = helpers.get_next_ready_timer(&[&timer2, &timer1]);
            assert_eq!(results.interval, timer1.interval);
            assert_eq!(results.last_measure, timer1.last_measure);
        }
    }
}

#[cfg(test)]
mod timer_new {
    use super::*;
    use rusty_fork::rusty_fork_test;

    rusty_fork_test! {
        #[test]
        fn zero_duration() {
            let timer = Timer::new(Duration::from_secs(0));
            assert_eq!(timer.interval, Duration::from_secs(0));
            assert!(timer.last_measure <= Instant::now());
        }

        #[test]
        fn new() {
            let timer = Timer::new(Duration::from_secs(123));
            assert_eq!(timer.interval, Duration::from_secs(123));
            assert!(timer.last_measure <= Instant::now());
        }
    }
}

#[cfg(test)]
mod next_ready_timer {
    use super::*;
    use rusty_fork::rusty_fork_test;

    rusty_fork_test! {
        #[test]
        fn no_timers() {
            let result = Timer::next_ready_timer(&[]);
            assert_eq!(result.interval, ZERO_TIMER.interval);
            assert_eq!(result.last_measure, ZERO_TIMER.last_measure);
        }

        #[test]
        fn one_timer() {
            let timer = Timer::new(Duration::from_secs(123));
            let result = Timer::next_ready_timer(&[&timer]);
            assert_eq!(result.interval, timer.interval);
            assert_eq!(result.last_measure, timer.last_measure);
        }

        #[test]
        fn two_timers() {
            let timer1 = Timer::new(Duration::from_secs(10));
            let timer2 = Timer::new(Duration::from_secs(20));

            let result = Timer::next_ready_timer(&[&timer1, &timer2]);
            assert_eq!(result.interval, timer1.interval);
            assert_eq!(result.last_measure, timer1.last_measure);

            let result = Timer::next_ready_timer(&[&timer2, &timer1]);
            assert_eq!(result.interval, timer1.interval);
            assert_eq!(result.last_measure, timer1.last_measure);
        }
    }
}

#[cfg(test)]
mod is_ready {
    use super::*;
    use rusty_fork::rusty_fork_test;

    rusty_fork_test! {
        #[test]
        fn not_ready() {
            let mut timer = Timer::new(Duration::from_secs(10));

            let measure_interval = timer.interval;
            timer.last_measure = Instant::now() + (measure_interval * 2);

            assert!(!timer.is_ready());
        }

        #[test]
        fn equal() {
            let mut timer = Timer::new(Duration::from_secs(10));

            let measure_interval = timer.interval;
            timer.last_measure = Instant::now() - measure_interval;

            assert!(timer.is_ready());
        }

        #[test]
        fn late() {
            let mut timer = Timer::new(Duration::from_secs(10));

            let measure_interval = timer.interval;
            timer.last_measure = Instant::now() - (measure_interval * 2);

            assert!(timer.is_ready());
        }
    }
}

#[cfg(test)]
mod duration_until_ready {
    use super::*;
    use rusty_fork::rusty_fork_test;

    rusty_fork_test! {
        #[test]
        fn not_ready() {
            let mut timer = Timer::new(Duration::from_secs(10));

            let measure_interval = timer.interval;
            timer.last_measure = Instant::now() + (measure_interval * 2);

            assert_eq!(timer.duration_until_ready(), measure_interval);
        }

        #[test]
        fn equal() {
            let mut timer = Timer::new(Duration::from_secs(10));

            let measure_interval = timer.interval;
            timer.last_measure = Instant::now() - measure_interval;

            assert_eq!(timer.duration_until_ready(), Duration::from_secs(0));
        }

        #[test]
        fn late() {
            let mut timer = Timer::new(Duration::from_secs(10));

            let measure_interval = timer.interval;
            timer.last_measure = Instant::now() - (measure_interval * 2);

            assert_eq!(timer.duration_until_ready(), Duration::from_secs(0));
        }
    }
}
