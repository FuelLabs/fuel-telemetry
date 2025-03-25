use crate::{
    daemonise, enforce_singleton, into_recoverable, telemetry_config, EnvSetting, Result,
    TelemetryError, WatcherResult,
};

use base64::{engine::general_purpose::STANDARD, DecodeError, Engine};
use chrono::NaiveDateTime;
use influxdb_line_protocol::LineProtocolBuilder;
use nix::{
    fcntl::{Flock, FlockArg},
    sys::signal::{kill, Signal::SIGKILL},
    unistd::{getpid, Pid},
};
use regex::{Captures, Regex};
use reqwest::blocking::{Client, Request, RequestBuilder};
use std::fs::ReadDir;
use std::{
    clone::Clone,
    collections::HashMap,
    env::var,
    fs::{read_dir, remove_file, File, OpenOptions},
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::exit,
    sync::{
        atomic::{AtomicBool, AtomicI32, Ordering},
        LazyLock,
    },
    thread::sleep,
    time::Duration,
};

//
// Module config
//

const PROCESS_NAME: &str = "telemetry-file-watcher";
const INFLUXDB_ORG: &str = "Dev%20Team";
const INFLUXDB_BUCKET: &str = "telemetry";
const INFLUXDB_URL: &str = "https://us-east-1-1.aws.cloud2.influxdata.com";
const INFLUXDB_TOKEN: &str = "l7Sho-XGD9BfGLQrKWwoBub-hC0gqJ5xRS2zz4pkjb6cGyBJZUQpw7qpwTfXTFGLXufCh7ZmQWv4bUtAsT60Ag==";

/// Configuration for `FileWatcher`
#[derive(Debug, Clone)]
struct FileWatcherConfig {
    // The path to its lockfile
    lockfile: PathBuf,
    // The path to its logfile
    logfile: PathBuf,
    // The token to use to authenticate with InfluxDB
    influxdb_token: String,
    // The URL of the InfluxDB instance
    influxdb_url: String,
    // The interval to poll for aged-out telemetry files
    poll_interval: Duration,
}

/// Get the `FileWatcher` configuration
///
/// This function returns the `'static` `FileWatcher` configuration.
fn config() -> Result<&'static FileWatcherConfig> {
    static FILEWATCHER_CONFIG: LazyLock<Result<FileWatcherConfig>> = LazyLock::new(|| {
        let get_env = |key, default| EnvSetting::new(key, default).get();

        // Since we use an hourly appender, we default to polling every hour
        let poll_interval = get_env("FILEWATCHER_POLL_INTERVAL", "3600").parse()?;

        // Format the InfluxDB URL (the org name needs to be URL-encoded)
        let influxdb_url = format!(
            "{}/api/v2/write?org={}&bucket={}&precision=ns",
            get_env(
                "INFLUXDB_URL",
                INFLUXDB_URL
            ),
            get_env("INFLUXDB_ORG", INFLUXDB_ORG),
            get_env("INFLUXDB_BUCKET", INFLUXDB_BUCKET),
        );

        Ok(FileWatcherConfig {
            lockfile: Path::new(&telemetry_config()?.fuelup_tmp).join(format!("{}.lock", PROCESS_NAME)),
            logfile: Path::new(&telemetry_config()?.fuelup_log).join(format!("{}.log", PROCESS_NAME)),
            poll_interval: Duration::from_secs(poll_interval),
            influxdb_token: get_env("INFLUXDB_TOKEN", INFLUXDB_TOKEN),
            influxdb_url,
        })
    });

    FILEWATCHER_CONFIG
        .as_ref()
        .map_err(|e| TelemetryError::InvalidConfig(e.to_string()))
}

//
// FileWatcher implementation
//

/// A `FileWatcher` polls for aged-out telemetry files and sends them to InfluxDB
#[derive(Default)]
pub struct FileWatcher {
    // The client used to send requests to InfluxDB
    client: Option<Client>,
    // The request to send to InfluxDB
    request: Option<Request>,
}

// Prevent recursive calls to start()
static STARTED: AtomicBool = AtomicBool::new(false);

/// The PID of the currently running `FileWatcher` daemon
pub static PID: AtomicI32 = AtomicI32::new(0);

/// A regex to parse telemetry events
static TELEMETRY_EVENT_REGEX: LazyLock<Result<Regex>> = LazyLock::new(|| {
    Ok(Regex::new(
        r"(?x)
        ^                                                                         \s*
        (?P<timestamp>[^\s]+)                                                     \s+
        (?P<level>(TRACE|DEBUG|INFO|WARN|ERROR))                                  \s+
        (?P<triple>.*?):(?P<os>.*?):(?P<os_version>.*?)                           \s+
        (?P<crate_pkg_name>[^\s]+):(?P<crate_pkg_version>[^\s]+):(?P<file>[^\s]+) \s+
        (?P<trace_id>[^\s]+)                                                      \s+
        (?P<payload>.*)                                                           \s*
        $
        ",
    )?)
});

/// A regex to parse telemetry payloads
///
/// Event payloads have the following formats:
///
/// ```text
/// - <message_only>
/// - [<span1>:<span2>:...:] [<message>] [<left1>= <right1> <left2>= <right2> ...]
/// ```
static TELEMETRY_PAYLOAD_REGEX: LazyLock<Result<Regex>> = LazyLock::new(|| {
    Ok(Regex::new(
        r"(?x)
        (?P<span>[^\s\:][^\:]*?[^\s\:]*?) :
        | (?:^|\s+) (?P<message_only>[^\=]+) \s* $
        | (?:^|\s+) (?P<message>[^\=]+) \s+
        | (?P<left>[^\s\=]+) = (?P<right>[^\=]+) (?:\s+|$)
        ",
    )?)
});

impl FileWatcher {
    /// Create a new `FileWatcher`
    ///
    /// Warning: This function should only be called in applications and not
    /// within libraries as it will clobber any set by the application.
    ///
    /// Warning: If you will be creating a `FileWatcher` and a `TelemetryLayer`,
    /// you must create the `FileWatcher` before the `TelemetryLayer` as there is
    /// a race condition in the thread runtime of `tracing` and the tokio runtime
    /// of `Reqwest`. Swapping order of the two could lead to possible deadlocks.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start the `FileWatcher`
    ///
    /// This function forks and has the parent immediately return. The forked
    /// off child then daemonises to poll for aged-out telemetry files, sending
    /// them to InfluxDB, and exits once there are no more files to process.
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
                // We are the child process, so continue as the `FileWatcher`...
                PID.store(getpid().as_raw(), Ordering::Relaxed);
            }
        }

        // From here on, we are no longer the original process, so the caller should
        // treat errors as fatal. This means that on error the process should exit
        // immediately as there should not be two identical flows of execution
        // from the caller's perspective.

        // Cache the client and request so we don't recreate them each time
        self.client = Some(Client::new());
        self.request = Some(helpers.build_request(self)?);

        loop {
            // Enforce a singleton to ensure we are the only process submitting
            // telemetry to InfluxDB
            let _lock = helpers.enforce_singleton(&config()?.lockfile)?;

            // Poll for aged-out telemetry files
            let directory_empty = helpers.poll_directory(self)?;

            if directory_empty {
                helpers.exit(0);
            }

            // Sleep for the configured interval before polling again
            helpers.sleep(config()?.poll_interval);
        }
    }

    /// Kill the `FileWatcher` daemon if one is running
    pub fn kill() -> Result<bool> {
        let pid = PID.load(Ordering::Relaxed);

        if pid > 0 {
            kill(Pid::from_raw(pid), SIGKILL)?;
            PID.store(0, Ordering::Relaxed);
            return Ok(true);
        }

        Ok(false)
    }

    /// Poll for aged-out telemetry files
    fn poll_directory(&self) -> Result<bool> {
        self.poll_directory_with_helpers(&mut DefaultPollDirectoryHelpers)
    }

    fn poll_directory_with_helpers(&self, helpers: &mut impl PollDirectoryHelpers) -> Result<bool> {
        for file in helpers.find_telemetry_files(false)? {
            // Lock the telemetry file to prevent being submitted twice
            let locked_file = helpers
                .flock(
                    OpenOptions::new().read(true).open(&file)?,
                    FlockArg::LockExclusiveNonblock,
                )
                .map_err(|(_, e)| e)?;

            // Read the telemetry file line by line
            let mut body = Vec::new();
            let lines = helpers.buffered_reader(locked_file.try_clone()?)?;

            for base64_line in lines {
                // First, decode the Base64 line
                let decoded_line = helpers.base64_decode(&base64_line)?;
                let line = helpers.string_from_utf8(decoded_line)?;

                let (event, spans_long, spans_short, fields) = helpers.parse_event(&line)?;
                let line_protocol =
                    helpers.build_line_protocol(&event, &spans_long, &spans_short, &fields);

                body.push(helpers.string_from_utf8(line_protocol)?);
            }

            if body.is_empty() {
                continue;
            }

            // Do not cache creating this request in the constructor then attempt
            // to use build_from_parts() here, because the `Client` used to build
            // the request is in another castle^Wprocess (we've since forked many
            // times), and so a `Client::new()` here will deadlock as it will
            // try to connect to a non-existant connection pool.
            let request = helpers.build_request(self, &body)?;

            if helpers.send_request(request)? {
                // Only remove the telemetry file if successful
                helpers.remove_file(&file)?;
            }
        }

        // Return false if there are pending telemetry files to process
        // regardless of age so that we keep going until there's no more work to
        // be done
        Ok(helpers.find_telemetry_files(true)?.is_empty())
    }
}

trait StartHelpers {
    fn daemonise(&self, logfile: &PathBuf) -> WatcherResult<Option<Pid>> {
        daemonise(logfile)
    }

    fn build_request(&self, file_watcher: &FileWatcher) -> Result<Request> {
        Ok(file_watcher
            .client
            .as_ref()
            .ok_or(TelemetryError::InvalidClient)?
            .post(&config()?.influxdb_url)
            .header("Content-Type", "text/plain; charset=utf-8")
            .header("Accept", "application/json")
            .header(
                "Authorization",
                format!("Token {}", config()?.influxdb_token.clone()),
            )
            .build()?)
    }

    fn enforce_singleton(&self, lockfile_path: &Path) -> Result<Flock<File>> {
        enforce_singleton(lockfile_path)
    }

    fn poll_directory(&self, file_watcher: &FileWatcher) -> Result<bool> {
        file_watcher.poll_directory()
    }

    fn exit(&self, code: i32) {
        exit(code)
    }

    fn sleep(&self, duration: Duration) {
        sleep(duration)
    }
}

struct DefaultStartHelpers;
impl StartHelpers for DefaultStartHelpers {}

trait PollDirectoryHelpers {
    fn find_telemetry_files(&mut self, ignore_age: bool) -> Result<Vec<PathBuf>> {
        find_telemetry_files(ignore_age)
    }

    fn flock(
        &self,
        file: File,
        flags: FlockArg,
    ) -> std::result::Result<Flock<File>, (File, nix::errno::Errno)> {
        Flock::lock(file, flags)
    }

    fn buffered_reader<R: Read>(
        &self,
        file: R,
    ) -> std::result::Result<Vec<String>, std::io::Error> {
        BufReader::new(file)
            .lines()
            .collect::<std::result::Result<Vec<_>, _>>()
    }

    fn base64_decode(&self, line: &str) -> std::result::Result<Vec<u8>, DecodeError> {
        STANDARD.decode(line.as_bytes())
    }

    fn string_from_utf8(
        &mut self,
        bytes: Vec<u8>,
    ) -> std::result::Result<String, std::string::FromUtf8Error> {
        String::from_utf8(bytes)
    }

    #[allow(clippy::type_complexity)]
    fn parse_event<'a>(
        &self,
        line: &'a str,
    ) -> Result<(
        Captures<'a>,
        Vec<String>,
        Vec<String>,
        HashMap<&'a str, String>,
    )> {
        let event = TELEMETRY_EVENT_REGEX
            .as_ref()?
            .captures(line)
            .ok_or_else(|| TelemetryError::InvalidTracingEvent(line.to_string()))?;

        let payload = event
            .name("payload")
            .ok_or_else(|| TelemetryError::InvalidTracingPayload(line.to_string()))?;

        let (mut spans_long, mut spans_short, mut fields) = (vec![], vec![], HashMap::new());

        for capture in TELEMETRY_PAYLOAD_REGEX
            .as_ref()?
            .captures_iter(payload.into())
        {
            if let Some(span) = capture.name("span") {
                let span_str = span.as_str();
                spans_long.push(span_str.to_string());
                spans_short.push(span_str.split('{').next().unwrap_or(span_str).to_string());
            } else if let Some(message) = capture.name("message") {
                fields.insert("message", message.as_str().to_string());
            } else if let Some(message_only) = capture.name("message_only") {
                fields.insert("message", message_only.as_str().to_string());
            } else if let (Some(left), Some(right)) = (capture.name("left"), capture.name("right"))
            {
                fields.insert(left.as_str(), right.as_str().to_string());
            }
        }

        Ok((event, spans_long, spans_short, fields))
    }

    fn build_line_protocol(
        &self,
        event: &Captures<'_>,
        spans_long: &[String],
        spans_short: &[String],
        fields: &HashMap<&str, String>,
    ) -> Vec<u8> {
        let mut line_protocol_builder = LineProtocolBuilder::new()
            .measurement(event.name("crate_pkg_name").map_or("", |m| m.as_str()))
            .tag(
                "version",
                event.name("crate_pkg_version").map_or("", |m| m.as_str()),
            )
            .tag("file", event.name("file").map_or("", |m| m.as_str()))
            .tag("spans", &spans_short.join(":"))
            .tag(
                "trace_id",
                event.name("trace_id").map_or("", |m| m.as_str()),
            )
            .field("spans_long", spans_long.join(":").as_str())
            .field("triple", event.name("triple").map_or("", |m| m.as_str()));

        for (key, value) in fields {
            line_protocol_builder = line_protocol_builder.field(key, value.as_str());
        }

        // Set the timestamp of the LineProtocol. Here we force a `.9` decimal
        // format rather than use the default nanoseconds format as InfluxDB seems
        // to have issues parsing datetime data
        let line_protocol_builder = line_protocol_builder.timestamp(
            event
                .name("timestamp")
                .and_then(|m| {
                    // Within `lib.rs:format_event()` we deliberately stick with
                    // Zulu however we use `%Z` format here as external apps writing
                    // telemetry files may use other timezone names
                    NaiveDateTime::parse_from_str(m.as_str(), "%Y-%m-%dT%H:%M:%S%.9f%Z")
                        .ok()
                        .map(|dt| dt.and_utc().timestamp_nanos_opt())
                })
                .flatten()
                .unwrap_or(0),
        );

        line_protocol_builder.close_line().build()
    }

    fn build_request(&self, file_watcher: &FileWatcher, body: &[String]) -> Result<RequestBuilder> {
        Ok(RequestBuilder::from_parts(
            file_watcher
                .client
                .as_ref()
                .ok_or(TelemetryError::InvalidClient)?
                .clone(),
            file_watcher
                .request
                .as_ref()
                .ok_or(TelemetryError::InvalidRequest)?
                .try_clone()
                .ok_or(TelemetryError::ReqwestCloneFailed)?,
        )
        .body(body.join("\n")))
    }

    fn send_request(&self, request: RequestBuilder) -> Result<bool> {
        Ok(request.send().is_ok_and(|r| r.status().is_success()))
    }

    fn remove_file(&self, file: &Path) -> std::io::Result<()> {
        remove_file(file)
    }
}

struct DefaultPollDirectoryHelpers;
impl PollDirectoryHelpers for DefaultPollDirectoryHelpers {}

/// Find telemetry files
///
/// This function finds all telemetry files in the configured directory.
///
/// If `ignore_age` is true, return telemetry files regardless of age, otherwise
/// only return files that are older than the configured poll interval.
fn find_telemetry_files(ignore_age: bool) -> Result<Vec<PathBuf>> {
    find_telemetry_files_with_read_dir_fn(ignore_age, |path| read_dir(path))
}

fn find_telemetry_files_with_read_dir_fn(
    ignore_age: bool,
    read_dir_fn: impl FnOnce(&str) -> std::result::Result<ReadDir, std::io::Error>,
) -> Result<Vec<PathBuf>> {
    let poll_interval = config()?.poll_interval;
    let telemetry_dir = &telemetry_config()?.fuelup_tmp;

    // Filter out files not containing `.telemetry.` in the filename
    //
    // Also, ignore file age if `ignore_age` is true
    read_dir_fn(telemetry_dir)?
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| p.to_string_lossy().contains(".telemetry."))
        .filter_map(|path| {
            if ignore_age
                || poll_interval < path.metadata().ok()?.modified().ok()?.elapsed().ok()?
            {
                Some(Ok(path))
            } else {
                None
            }
        })
        .collect::<Result<Vec<_>>>()
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
            assert_eq!(config.poll_interval, Duration::from_secs(3600));
            assert_eq!(config.influxdb_token, INFLUXDB_TOKEN);
            
            assert_eq!(config.influxdb_url, format!(
                "{}/api/v2/write?org={}&bucket={}&precision=ns",
                INFLUXDB_URL,
                INFLUXDB_ORG,
                INFLUXDB_BUCKET
            ));
        }

        #[test]
        fn poll_interval_set() {
            set_var("FILEWATCHER_POLL_INTERVAL", "2222");

            let config = config().unwrap();
            assert_eq!(config.poll_interval, Duration::from_secs(2222));
        }

        #[test]
        fn poll_interval_invalid() {
            set_var("FILEWATCHER_POLL_INTERVAL", "invalid");

            let config = config();
            assert_eq!(
                config.err(),
                Some(TelemetryError::InvalidConfig(
                    TelemetryError::Parse("invalid digit found in string".to_string()).into()
                ))
            );
        }

        #[test]
        fn influxdb_url_set() {
            set_var("INFLUXDB_URL", "http://localhost:8000");

            let config = config().unwrap();
            assert_eq!(
                config.influxdb_url,
                format!("{}/api/v2/write?org={}&bucket={}&precision=ns",
                "http://localhost:8000",
                INFLUXDB_ORG,
                INFLUXDB_BUCKET
            ));
        }

        #[test]
        fn influxdb_org_set() {
            set_var("INFLUXDB_ORG", "org-name");

            let config = config().unwrap();
            assert_eq!(config.influxdb_url, format!(
                "{}/api/v2/write?org={}&bucket={}&precision=ns",
                INFLUXDB_URL,
                "org-name",
                INFLUXDB_BUCKET
            ));
        }

        #[test]
        fn influxdb_bucket_set() {
            set_var("INFLUXDB_BUCKET", "bucket-name");

            let config = config().unwrap();
            assert_eq!(config.influxdb_url, format!(
                "{}/api/v2/write?org={}&bucket={}&precision=ns",
                INFLUXDB_URL,
                INFLUXDB_ORG,
                "bucket-name"
            ));
        }

        #[test]
        fn all_set() {
            setup_fuelup_home();
            let fuelup_home = var("FUELUP_HOME").unwrap();

            set_var("FILEWATCHER_POLL_INTERVAL", "2222");
            set_var("INFLUXDB_URL", "http://localhost:8000");
            set_var("INFLUXDB_ORG", "org-name");
            set_var("INFLUXDB_BUCKET", "bucket-name");

            let config = config().unwrap();

            assert_eq!(
                config.lockfile,
                Path::new(&format!("{}/tmp/{}.lock", &fuelup_home, PROCESS_NAME))
            );

            assert_eq!(
                config.logfile,
                Path::new(&format!("{}/log/{}.log", &fuelup_home, PROCESS_NAME))
            );
            assert_eq!(config.poll_interval, Duration::from_secs(2222));
            assert_eq!(config.influxdb_token, INFLUXDB_TOKEN);
            assert_eq!(
                config.influxdb_url,
                format!("{}/api/v2/write?org={}&bucket={}&precision=ns",
                    "http://localhost:8000",
                    "org-name",
                    "bucket-name"
                )
            );
        }
    }
}

#[cfg(test)]
mod new {
    use super::*;

    #[test]
    fn new() {
        let file_watcher = FileWatcher::new();

        assert!(file_watcher.client.is_none());
        assert!(file_watcher.request.is_none());
    }
}

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
    };

    rusty_fork_test! {
        #[test]
        fn opted_out_is_true() {
            set_var("FUELUP_NO_TELEMETRY", "true");

            let mut file_watcher = FileWatcher::new();
            let result = file_watcher.start();

            // Make sure it didn't continue and init values
            assert!(matches!(result, Ok(())));
            assert!(file_watcher.client.is_none());
            assert!(file_watcher.request.is_none());
            assert!(!STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 0);
        }

        #[test]
        fn opted_out_is_empty() {
            // Even though it's empty, we only care if it's set
            set_var("FUELUP_NO_TELEMETRY", "");

            let mut file_watcher = FileWatcher::new();
            let result = file_watcher.start();

            // Make sure it didn't continue and init values
            assert!(matches!(result, Ok(())));
            assert!(file_watcher.client.is_none());
            assert!(file_watcher.request.is_none());
            assert!(!STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 0);
        }

        #[test]
        fn already_started() {
            STARTED.store(true, Ordering::Relaxed);
            PID.store(1, Ordering::Relaxed);

            let mut file_watcher = FileWatcher::new();
            let result = file_watcher.start();

            // Make sure it didn't continue and init values
            assert!(matches!(result, Ok(())));
            assert!(file_watcher.client.is_none());
            assert!(file_watcher.request.is_none());
            assert!(STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 1);

            // Try to start it again to test re-entrance
            let result = file_watcher.start();

            assert!(matches!(result, Ok(())));
            assert!(file_watcher.client.is_none());
            assert!(file_watcher.request.is_none());
            assert!(STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 1);
        }

        #[test]
        fn daemonise_failed() {
            struct DaemoniseFailed;

            impl StartHelpers for DaemoniseFailed {
                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<Pid>> {
                    Err(into_fatal(TelemetryError::Mock))
                }
            }

            let mut file_watcher = FileWatcher::new();
            let result = file_watcher.start_with_helpers(&DaemoniseFailed);

            assert_eq!(
                result.err(),
                Some(WatcherError::Fatal(TelemetryError::Mock))
            );
            assert!(!STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 0);
        }

        #[test]
        fn daemonise_is_parent() {
            struct DaemoniseIsParent;

            impl StartHelpers for DaemoniseIsParent {
                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<Pid>> {
                    Ok(Some(Pid::from_raw(1337)))
                }
            }

            let mut file_watcher = FileWatcher::new();
            let result = file_watcher.start_with_helpers(&DaemoniseIsParent);

            assert_eq!(result, Ok(()));
            assert!(STARTED.load(Ordering::Relaxed));
            assert_eq!(PID.load(Ordering::Relaxed), 1337);
        }

        #[test]
        fn build_request_invalid_client() {
            struct BuildRequestInvalidClient;

            impl StartHelpers for BuildRequestInvalidClient {
                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<Pid>> {
                    Ok(None)
                }

                fn build_request(&self, _file_watcher: &FileWatcher) -> Result<Request> {
                    Err(TelemetryError::InvalidClient)
                }
            }

            let mut file_watcher = FileWatcher::new();
            let result = file_watcher.start_with_helpers(&BuildRequestInvalidClient);

            assert_eq!(
                result,
                Err(WatcherError::Fatal(TelemetryError::InvalidClient))
            );
        }

        #[test]
        fn build_request_build_failed() {
            setup_fuelup_home();

            struct BuildRequestBuildFailed;

            impl StartHelpers for BuildRequestBuildFailed {
                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<Pid>> {
                    Ok(None)
                }

                fn build_request(&self, _file_watcher: &FileWatcher) -> Result<Request> {
                    // Builder errors are private, so generate a real one
                    Ok(Client::new()
                        .post("http://localhost")
                        .header("Invalid Header", "")
                        .build()?)
                }
            }

            let mut file_watcher = FileWatcher::new();
            let result = file_watcher.start_with_helpers(&BuildRequestBuildFailed);

            assert_eq!(
                result,
                Err(WatcherError::Fatal(TelemetryError::Reqwest(
                    "builder error".to_string()
                )))
            );
        }

        #[test]
        fn enforce_singleton_failed() {
            struct EnforceSingletonFailed;

            impl StartHelpers for EnforceSingletonFailed {
                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<Pid>> {
                    Ok(None)
                }

                fn enforce_singleton(&self, _lockfile_path: &Path) -> Result<Flock<File>> {
                    Err(TelemetryError::Mock)
                }
            }

            let mut file_watcher = FileWatcher::new();
            let result = file_watcher.start_with_helpers(&EnforceSingletonFailed);

            assert_eq!(result, Err(WatcherError::Fatal(TelemetryError::Mock)));
        }

        #[test]
        fn poll_directory_failed() {
            setup_fuelup_home();

            struct PollDirectoryFailed;

            impl StartHelpers for PollDirectoryFailed {
                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<Pid>> {
                    Ok(None)
                }

                fn poll_directory(&self, _file_watcher: &FileWatcher) -> Result<bool> {
                    Err(TelemetryError::Mock)
                }
            }

            let mut file_watcher = FileWatcher::new();
            let result = file_watcher.start_with_helpers(&PollDirectoryFailed);

            assert_eq!(result, Err(WatcherError::Fatal(TelemetryError::Mock)));
        }

        #[test]
        fn poll() {
            setup_fuelup_home();

            struct Poll;

            impl StartHelpers for Poll {
                fn daemonise(&self, _logfile: &PathBuf) -> WatcherResult<Option<Pid>> {
                    // Mock daemonising by not forking to become the child
                    Ok(None)
                }

                fn poll_directory(&self, _file_watcher: &FileWatcher) -> Result<bool> {
                    static HAS_POLLED: AtomicBool = AtomicBool::new(false);

                    if !HAS_POLLED.load(Ordering::Relaxed) {
                        HAS_POLLED.store(true, Ordering::Relaxed);

                        // Send the PID so we can test it's as expected
                        let file_watcher_pid = crate::file_watcher::PID
                            .load(Ordering::Relaxed)
                            .as_raw_fd()
                            .to_ne_bytes();

                        stdout().write_all(&file_watcher_pid).unwrap();
                        stdout().flush().unwrap();

                        Ok(false)
                    } else {
                        Ok(true)
                    }
                }

                fn exit(&self, _code: i32) {
                    // Test we actually exited via our expected code path
                    exit(99)
                }

                fn sleep(&self, _duration: Duration) {
                    // No Sleep Till Brooklyn
                }
            }

            let (read_fd, write_fd) = pipe().unwrap();
            let mut pipe_read = unsafe { File::from_raw_fd(read_fd.into_raw_fd()) };
            let pipe_write = unsafe { File::from_raw_fd(write_fd.into_raw_fd()) };

            match unsafe { fork() }.unwrap() {
                ForkResult::Parent { child } => {
                    drop(pipe_write);

                    let mut pid_bytes = [0u8; std::mem::size_of::<Pid>()];
                    pipe_read.read_exact(&mut pid_bytes).unwrap();

                    let pid = Pid::from_raw(i32::from_ne_bytes(pid_bytes));
                    assert_eq!(pid, child);

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

                    // Since we're mocking daemonising by not double forking in
                    // the parent, we have to set the PID manually
                    let pid_bytes = getpid().as_raw().to_ne_bytes();
                    stdout().write_all(&pid_bytes).unwrap();
                    stdout().flush().unwrap();

                    let mut file_watcher = FileWatcher::new();
                    let _ = file_watcher.start_with_helpers(&Poll);

                    // Fallback status code
                    exit(86);
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
            crate::file_watcher::PID.store(0, Ordering::Relaxed);
            assert!(!FileWatcher::kill().unwrap());
        }

        #[test]
        fn kill_file_watcher() {
            let mut kill_called = false;

            match unsafe { fork() }.unwrap() {
                ForkResult::Parent { child } => {
                    loop {
                        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                            Ok(WaitStatus::StillAlive) => {
                                if !kill_called {
                                    // Since we're not daemonising, we have to set the PID manually
                                    crate::file_watcher::PID
                                        .store(child.as_raw(), Ordering::Relaxed);
                                    assert!(FileWatcher::kill().unwrap());

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
mod poll_directory {
    use super::*;
    use crate::setup_fuelup_home;
    use rusty_fork::rusty_fork_test;
    use std::{fs::File, io::Write, sync::OnceLock};

    fn setup_test_file() -> PathBuf {
        static TEST_FILE: OnceLock<PathBuf> = OnceLock::new();

        let filename = TEST_FILE.get_or_init(|| {
            let filename = format!("{}/{}", telemetry_config().unwrap().fuelup_tmp, "test.telemetry.file");

            let mut file = File::create(Path::new(filename.as_str())).unwrap();
            file.write_all(b"MjAyNS0wMy0xNlQxNDo0ODoxMC4wODQ4MDMwMDBaICBJTkZPIGFhcmNoNjQtYXBwbGUtZGFyd2luOkRhcndpbjoyMy42LjAgc2ltcGxlOjAuMS4wOmV4YW1wbGVzL3NpbXBsZS5ycyA0YjEyNDYyNy0wNjNiLTQwM2UtODEyZi02OWQxMzRlZjAxMzIgYXV0bzogZ0Z1ZWwh").unwrap();

            PathBuf::from(filename)
        });

        filename.clone()
    }

    rusty_fork_test! {
        #[test]
        fn find_telemetry_files_failed() {
            setup_fuelup_home();

            struct FindTelemetryFilesFailed;

            impl PollDirectoryHelpers for FindTelemetryFilesFailed {
                fn find_telemetry_files(&mut self, _ignore_age: bool) -> Result<Vec<PathBuf>> {
                    Err(TelemetryError::Mock)
                }
            }

            let file_watcher = FileWatcher::new();
            let result = file_watcher.poll_directory_with_helpers(&mut FindTelemetryFilesFailed);

            assert_eq!(result, Err(TelemetryError::Mock));
       }

        #[test]
        fn find_telemetry_files_empty() {
            setup_fuelup_home();

            struct FindTelemetryFilesEmpty;

            impl PollDirectoryHelpers for FindTelemetryFilesEmpty {
                fn find_telemetry_files(&mut self, _ignore_age: bool) -> Result<Vec<PathBuf>> {
                    Ok(vec![])
                }
            }

            let file_watcher = FileWatcher::new();
            let result = file_watcher.poll_directory_with_helpers(&mut FindTelemetryFilesEmpty);

            assert_eq!(result, Ok(true));
        }

        #[test]
        fn flock_failed() {
            setup_fuelup_home();

            struct FlockFailed;

            impl PollDirectoryHelpers for FlockFailed {
                fn find_telemetry_files(&mut self, _ignore_age: bool) -> Result<Vec<PathBuf>> {
                    Ok(vec![setup_test_file()])
                }

                fn flock(&self, file: File, _flags: FlockArg)-> std::result::Result<Flock<File>, (File, nix::errno::Errno)> {
                    Err((file, nix::errno::Errno::EOWNERDEAD))
                }
            }

            let file_watcher = FileWatcher::new();
            let result = file_watcher.poll_directory_with_helpers(&mut FlockFailed);

            assert_eq!(
                result,
                Err(TelemetryError::Nix(nix::errno::Errno::EOWNERDEAD.to_string()))
            );
        }

        #[test]
        fn buffered_reader_failed() {
            setup_fuelup_home();

            struct BufferedReaderFailed;

            impl PollDirectoryHelpers for BufferedReaderFailed {
                fn find_telemetry_files(&mut self, _ignore_age: bool) -> Result<Vec<PathBuf>> {
                    Ok(vec![setup_test_file()])
                }

                fn buffered_reader<R: Read>(&self, _file: R) -> std::result::Result<Vec<String>, std::io::Error> {
                    Err(std::io::Error::new(std::io::ErrorKind::Other, "Mock error"))
                }
            }

            let file_watcher = FileWatcher::new();
            let result = file_watcher.poll_directory_with_helpers(&mut BufferedReaderFailed);

            assert_eq!(
                result,
                Err(TelemetryError::IO("Mock error".to_string()))
            );
        }

        #[test]
        fn empty_file() {
            setup_fuelup_home();

            struct EmptyFile;

            impl PollDirectoryHelpers for EmptyFile {
                fn find_telemetry_files(&mut self, _ignore_age: bool) -> Result<Vec<PathBuf>> {
                    Ok(vec![setup_test_file()])
                }

                fn buffered_reader<R: Read>(&self, _file: R) -> std::result::Result<Vec<String>, std::io::Error> {
                    Ok(vec![])
                }
            }

            let file_watcher = FileWatcher::new();
            let result = file_watcher.poll_directory_with_helpers(&mut EmptyFile);

            // The test file was simulated as empty, so it should stick around
            assert_eq!(result, Ok(false));
        }

        #[test]
        fn base64_decode_failed() {
            setup_fuelup_home();

            struct Base64DecodeFailed;

            impl PollDirectoryHelpers for Base64DecodeFailed {
                fn find_telemetry_files(&mut self, _ignore_age: bool) -> Result<Vec<PathBuf>> {
                    Ok(vec![setup_test_file()])
                }

                fn base64_decode(&self, _line: &str) -> std::result::Result<Vec<u8>, DecodeError> {
                    Err(DecodeError::InvalidLength(111222333444555))
                }
            }

            let file_watcher = FileWatcher::new();
            let result = file_watcher.poll_directory_with_helpers(&mut Base64DecodeFailed);

            assert_eq!(
                result,
                Err(TelemetryError::Base64(DecodeError::InvalidLength(111222333444555)))
            );
        }

        #[test]
        fn string_from_utf8_failed() {
            setup_fuelup_home();

            struct StringFromUtf8Failed;

            impl PollDirectoryHelpers for StringFromUtf8Failed {
                fn find_telemetry_files(&mut self, _ignore_age: bool) -> Result<Vec<PathBuf>> {
                    Ok(vec![setup_test_file()])
                }

                fn string_from_utf8(&mut self, _bytes: Vec<u8>) -> std::result::Result<String, std::string::FromUtf8Error> {
                    // Can't manually create an error, so simulate a failed UTF-8 conversion
                    String::from_utf8(vec![0x80])
                }
            }

            let file_watcher = FileWatcher::new();
            let result = file_watcher.poll_directory_with_helpers(&mut StringFromUtf8Failed);

            assert_eq!(
                result,
                Err(TelemetryError::Utf8("invalid utf-8 sequence of 1 bytes from index 0".to_string()))
            );
        }

        #[test]
        fn parse_event_failed() {
            setup_fuelup_home();

            struct ParseEventFailed;

            impl PollDirectoryHelpers for ParseEventFailed {
                fn find_telemetry_files(&mut self, _ignore_age: bool) -> Result<Vec<PathBuf>> {
                    Ok(vec![setup_test_file()])
                }

                fn parse_event<'a>(&self, _line: &'a str) -> Result<(
                    Captures<'a>,
                    Vec<String>,
                    Vec<String>,
                    HashMap<&'a str, String>,
                )> {
                    Err(TelemetryError::Mock)
                }
            }

            let file_watcher = FileWatcher::new();
            let result = file_watcher.poll_directory_with_helpers(&mut ParseEventFailed);

            assert_eq!(result, Err(TelemetryError::Mock));
        }

        #[test]
        fn line_protocol_from_utf8_failed() {
            setup_fuelup_home();

            #[derive(Default)]
            struct LineProtocolFromUtf8Failed {
                call_counter: usize,
            }

            impl PollDirectoryHelpers for LineProtocolFromUtf8Failed {
                fn find_telemetry_files(&mut self, _ignore_age: bool) -> Result<Vec<PathBuf>> {
                    Ok(vec![setup_test_file()])
                }

                fn string_from_utf8(&mut self, bytes: Vec<u8>) -> std::result::Result<String, std::string::FromUtf8Error> {
                    self.call_counter += 1;

                    if self.call_counter == 2 {
                        String::from_utf8(vec![0x80])
                    } else {
                        String::from_utf8(bytes)
                    }
                }
            }

            let file_watcher = FileWatcher::new();
            let result = file_watcher.poll_directory_with_helpers(&mut LineProtocolFromUtf8Failed::default());

            assert_eq!(
                result,
                Err(TelemetryError::Utf8("invalid utf-8 sequence of 1 bytes from index 0".to_string()))
            );
        }

        #[test]
        fn build_request_failed() {
            setup_fuelup_home();

            struct BuildRequestFailed;

            impl PollDirectoryHelpers for BuildRequestFailed {
                fn find_telemetry_files(&mut self, _ignore_age: bool) -> Result<Vec<PathBuf>> {
                    Ok(vec![setup_test_file()])
                }

                fn build_request(&self, _file_watcher: &FileWatcher, _body: &[String]) -> Result<RequestBuilder> {
                    Err(TelemetryError::Mock)
                }
            }

            let file_watcher = FileWatcher::new();
            let result = file_watcher.poll_directory_with_helpers(&mut BuildRequestFailed);

            assert_eq!(result, Err(TelemetryError::Mock));
        }

        #[test]
        fn send_request_failed() {
            setup_fuelup_home();

            struct SendRequestFailed;


            impl PollDirectoryHelpers for SendRequestFailed {
                fn find_telemetry_files(&mut self, _ignore_age: bool) -> Result<Vec<PathBuf>> {
                    Ok(vec![setup_test_file()])
                }

                fn send_request(&self, _request: RequestBuilder) -> Result<bool> {
                    Err(TelemetryError::Mock)
                }
            }

            let mut file_watcher = FileWatcher::new();
            let start_helpers = DefaultStartHelpers;

            file_watcher.client = Some(Client::new());
            file_watcher.request = Some(start_helpers.build_request(&file_watcher).unwrap());

            let result = file_watcher.poll_directory_with_helpers(&mut SendRequestFailed);
            assert_eq!(result, Err(TelemetryError::Mock));

            let test_file = setup_test_file();
            assert!(test_file.exists());
        }

        #[test]
        fn remove_file_failed() {
            setup_fuelup_home();

            struct RemoveFileFailed;

            impl PollDirectoryHelpers for RemoveFileFailed {
                fn find_telemetry_files(&mut self, _ignore_age: bool) -> Result<Vec<PathBuf>> {
                    Ok(vec![setup_test_file()])
                }

                fn send_request(&self, _request: RequestBuilder) -> Result<bool> {
                    Ok(true)
                }

                fn remove_file(&self, _file: &Path) -> std::io::Result<()> {
                    Err(std::io::Error::new(std::io::ErrorKind::Other, "Mock error"))
                }
            }

            let mut file_watcher = FileWatcher::new();
            let start_helpers = DefaultStartHelpers;

            file_watcher.client = Some(Client::new());
            file_watcher.request = Some(start_helpers.build_request(&file_watcher).unwrap());

            let result = file_watcher.poll_directory_with_helpers(&mut RemoveFileFailed);
            assert_eq!(result, Err(TelemetryError::IO("Mock error".to_string())));

            let test_file = setup_test_file();
            assert!(test_file.exists());
        }

        #[test]
        fn ok() {
            setup_fuelup_home();

            #[derive(Default)]
            struct AOk {
                call_count: usize,
            }

            impl PollDirectoryHelpers for AOk {
                fn find_telemetry_files(&mut self, _ignore_age: bool) -> Result<Vec<PathBuf>> {
                    self.call_count += 1;

                    if self.call_count == 2 {
                        Ok(vec![])
                    } else {
                        Ok(vec![setup_test_file()])
                    }
                }

                fn send_request(&self, _request: RequestBuilder) -> Result<bool> {
                    Ok(true)
                }
            }

            let mut file_watcher = FileWatcher::new();
            let start_helpers = DefaultStartHelpers;

            file_watcher.client = Some(Client::new());
            file_watcher.request = Some(start_helpers.build_request(&file_watcher).unwrap());

            let result = file_watcher.poll_directory_with_helpers(&mut AOk::default());
            assert_eq!(result, Ok(true));

            let test_file = setup_test_file();
            assert!(!test_file.exists());
        }
    }
}

#[cfg(test)]
mod find_telemetry_files {
    use super::*;
    use crate::setup_fuelup_home;
    use rusty_fork::rusty_fork_test;
    use std::{fs::File, io::Write, time::SystemTime};

    fn setup_test_files() {
        for filename in [
            "old-file.telemetry.file",
            "new-file.telemetry.file",
            "invalid.file.name",
        ] {
            let filepath = format!("{}/{}", telemetry_config().unwrap().fuelup_tmp, filename);
            let mut file = File::create(Path::new(filepath.as_str())).unwrap();
            file.write_all(b"MjAyNS0wMy0xNlQxNDo0ODoxMC4wODQ4MDMwMDBaICBJTkZPIGFhcmNoNjQtYXBwbGUtZGFyd2luOkRhcndpbjoyMy42LjAgc2ltcGxlOjAuMS4wOmV4YW1wbGVzL3NpbXBsZS5ycyA0YjEyNDYyNy0wNjNiLTQwM2UtODEyZi02OWQxMzRlZjAxMzIgYXV0bzogZ0Z1ZWwh").unwrap();
        }

        let old_file = File::open(Path::new(
            format!(
                "{}/old-file.telemetry.file",
                telemetry_config().unwrap().fuelup_tmp
            )
            .as_str(),
        ))
        .unwrap();

        old_file
            .set_modified(
                SystemTime::now() - Duration::from_secs(config().unwrap().poll_interval.as_secs()),
            )
            .unwrap();

        for dir in ["dir1", "dir2", "dir3"] {
            let dir = format!("{}/{}", telemetry_config().unwrap().fuelup_tmp, dir);
            std::fs::create_dir_all(dir).unwrap();
        }
    }

    rusty_fork_test! {
        #[test]
        fn read_dir_failed() {
            setup_fuelup_home();
            setup_test_files();

            let result = find_telemetry_files_with_read_dir_fn(
                false,
                |_| Err(std::io::Error::new(std::io::ErrorKind::Other, "Mock error")),
            );

            assert_eq!(result, Err(TelemetryError::IO("Mock error".to_string())));
        }

        #[test]
        fn ok() {
            setup_fuelup_home();
            setup_test_files();

            let result = find_telemetry_files(false);

            assert_eq!(result, Ok(vec![
                PathBuf::from(format!("{}/old-file.telemetry.file", telemetry_config().unwrap().fuelup_tmp)),
            ]));
        }
    }
}
