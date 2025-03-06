use crate::{daemonise, enforce_singleton, telemetry_config, EnvSetting, Result, TelemetryError};

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::NaiveDateTime;
use influxdb_line_protocol::LineProtocolBuilder;
use nix::{
    fcntl::{Flock, FlockArg},
    sys::signal::{kill, Signal::SIGILL},
    unistd::{getpid, Pid},
};
use regex::Regex;
use reqwest::blocking::{Client, Request, RequestBuilder};
use std::{
    clone::Clone,
    collections::HashMap,
    env::var,
    fs::{read_dir, remove_file, OpenOptions},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::exit,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        LazyLock,
    },
    thread::sleep,
    time::Duration,
};

//
// Module config
//

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
        let poll_interval = get_env("FILEWATCHER_POLL_INTERVAL", "3600")
            .parse()
            .map_err(|e| {
                TelemetryError::InvalidConfig(format!("Poll interval is invalid: {}", e))
            })?;

        // Format the InfluxDB URL (the org name needs to be URL-encoded)
        let influxdb_url = format!(
            "{}/api/v2/write?org={}&bucket={}&precision=ns",
            get_env(
                "INFLUXDB_URL",
                "https://us-east-1-1.aws.cloud2.influxdata.com"
            ),
            get_env("INFLUXDB_ORG", "Dev%20Team"),
            get_env("INFLUXDB_BUCKET", "telemetry"),
        );

        Ok(FileWatcherConfig {
            lockfile: Path::new(&telemetry_config()?.fuelup_tmp).join("telemetry-file-watcher.lock"),
            logfile: Path::new(&telemetry_config()?.fuelup_log).join("telemetry-file-watcher.log"),
            poll_interval: Duration::from_secs(poll_interval),
            influxdb_token: get_env("INFLUXDB_TOKEN", "l7Sho-XGD9BfGLQrKWwoBub-hC0gqJ5xRS2zz4pkjb6cGyBJZUQpw7qpwTfXTFGLXufCh7ZmQWv4bUtAsT60Ag=="),
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
pub struct FileWatcher {
    // The client used to send requests to InfluxDB
    client: Option<Client>,
    // The request to send to InfluxDB
    request: Option<Request>,
    // The path to its lockfile ($FUELUP_TMP/telemetry-file-watcher.lock)
    lockfile_path: PathBuf,
}

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

/// The PID of the currently running `FileWatcher` daemon
pub static PID: AtomicUsize = AtomicUsize::new(0);

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
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: None,
            request: None,
            lockfile_path: Path::new(&telemetry_config()?.fuelup_tmp)
                .join(config()?.lockfile.clone()),
        })
    }

    /// Start the `FileWatcher`
    ///
    /// This function forks and has the parent immediately return. The forked
    /// off child then daemonises to poll for aged-out telemetry files, sending
    /// them to InfluxDB, and exits once there are no more files to process.
    pub fn start(&mut self) -> Result<()> {
        if var("FUELUP_NO_TELEMETRY").is_ok() {
            // If telemetry is disabled, immediately return
            return Ok(());
        }

        // Prevent recursive calls to start()
        static STARTED: AtomicBool = AtomicBool::new(false);

        if STARTED.load(Ordering::Relaxed) {
            return Ok(());
        } else {
            STARTED.store(true, Ordering::Relaxed);
        }

        if daemonise(&config()?.logfile)? {
            // If we are the parent, immediately return
            return Ok(());
        }

        // Record the PID of the daemon so we can kill it from tests
        PID.store(getpid().as_raw() as usize, Ordering::Relaxed);

        // Cache the client and request so we don't recreate them each time
        self.client = Some(Client::new());
        self.request = Some(
            self.client
                .as_ref()
                .ok_or(TelemetryError::InvalidClient)?
                .post(&config()?.influxdb_url)
                .header("Content-Type", "text/plain; charset=utf-8")
                .header("Accept", "application/json")
                .header(
                    "Authorization",
                    format!("Token {}", config()?.influxdb_token.clone()),
                )
                .build()?,
        );

        loop {
            // Enforce a singleton to ensure we are the only process submitting
            // telemetry to InfluxDB
            let _lock = enforce_singleton(&self.lockfile_path)?;

            // Poll for aged-out telemetry files
            let no_files_left = self.poll_directory()?;

            if no_files_left {
                exit(0)
            }

            // Sleep for the configured interval before polling again
            sleep(config()?.poll_interval);
        }
    }

    /// Kill the `FileWatcher` daemon if one is running
    pub fn kill() -> Result<()> {
        let pid = PID.load(Ordering::Relaxed);

        if pid != 0 {
            kill(Pid::from_raw(pid as i32), SIGILL)?;
            PID.store(0, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Poll for aged-out telemetry files
    fn poll_directory(&self) -> Result<bool> {
        for file in find_telemetry_files(false)? {
            // Lock the telemetry file to prevent being submitted twice
            let locked_file = Flock::lock(
                OpenOptions::new().read(true).open(&file)?,
                FlockArg::LockExclusiveNonblock,
            )
            .map_err(|(_, e)| e)?;

            // Read the telemetry file line by line
            let mut body = Vec::new();
            let lines = BufReader::new(locked_file.try_clone()?)
                .lines()
                .map(|line| line.map_err(TelemetryError::from))
                .collect::<Result<Vec<_>>>()?;

            for base64_line in lines {
                // First, decode the Base64 line
                let decoded_line = STANDARD.decode(base64_line.as_bytes())?;
                let line = String::from_utf8(decoded_line)?;

                // Parse the line for a telemetry event
                let event = TELEMETRY_EVENT_REGEX
                    .as_ref()?
                    .captures(&line)
                    .ok_or_else(|| TelemetryError::InvalidTracingEvent(line.clone()))?;

                // Parse the payload from the telemetry event
                let payload = event.name("payload").ok_or_else(|| {
                    TelemetryError::InvalidTracingPayload(
                        event
                            .name("payload")
                            .map_or(line.clone(), |m| m.as_str().to_string()),
                    )
                })?;

                let (mut spans_long, mut spans_short, mut fields) =
                    (vec![], vec![], HashMap::new());

                // Finally, parse the span from the payload
                for capture in TELEMETRY_PAYLOAD_REGEX
                    .as_ref()?
                    .captures_iter(payload.into())
                {
                    if let Some(span) = capture.name("span") {
                        let span_str = span.as_str();
                        spans_long.push(span_str.to_string());
                        spans_short
                            .push(span_str.split('{').next().unwrap_or(span_str).to_string());
                    } else if let Some(message) = capture.name("message") {
                        fields.insert("message", message.as_str().to_string());
                    } else if let Some(message_only) = capture.name("message_only") {
                        fields.insert("message", message_only.as_str().to_string());
                    } else if let (Some(left), Some(right)) =
                        (capture.name("left"), capture.name("right"))
                    {
                        fields.insert(left.as_str(), right.as_str().to_string());
                    }
                }

                // Build the LineProtocol to send to InfluxDB
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

                // Set the timestamp of the LineProtocol. Here we force a `.9`
                // decimal format rather than use the default nanoseconds format
                // as InfluxDB seems to have issues parsing datetime data
                let line_protocol_builder = line_protocol_builder.timestamp(
                    event
                        .name("timestamp")
                        .and_then(|m| {
                            // Within `lib.rs:format_event()` we deliberately
                            // stick with Zulu however we use `%Z` format here
                            // as external apps writing telemetry files may use
                            // other timezone names
                            NaiveDateTime::parse_from_str(m.as_str(), "%Y-%m-%dT%H:%M:%S%.9f%Z")
                                .ok()
                                .map(|dt| dt.and_utc().timestamp_nanos_opt())
                        })
                        .flatten()
                        .unwrap_or(0),
                );

                body.push(String::from_utf8(
                    line_protocol_builder.close_line().build(),
                )?);
            }

            if body.is_empty() {
                continue;
            }

            // Do not cache creating this request in the constructor then attempt
            // to use build_from_parts() here, because the `Client` used to build
            // the request is in another castle^Wprocess (we've since forked many
            // times), and so a `Client::new()` here will deadlock as it will
            // try to connect to a non-existant connection pool.
            let request = RequestBuilder::from_parts(
                self.client
                    .as_ref()
                    .ok_or(TelemetryError::InvalidClient)?
                    .clone(),
                self.request
                    .as_ref()
                    .ok_or(TelemetryError::InvalidRequest)?
                    .try_clone()
                    .ok_or(TelemetryError::ReqwestCloneFailed)?,
            )
            .body(body.join("\n"));

            if request.send().map_or(false, |r| r.status().is_success()) {
                // Only remove the telemetry file if successful
                remove_file(&file)?;
            }
        }

        // Return true if there are pending telemetry files to process
        // regardless of age so that we keep going until there's no more work to
        // be done
        Ok(find_telemetry_files(true)?.is_empty())
    }
}

//
// Helper functions that might be moved later to lib.rs
//

/// Find telemetry files
///
/// This function finds all telemetry files in the configured directory.
///
/// If `ignore_age` is true, return telemetry files regardless of age, otherwise
/// only return files that are older than the configured poll interval.
fn find_telemetry_files(ignore_age: bool) -> Result<Vec<PathBuf>> {
    let poll_interval = config()?.poll_interval;
    let telemetry_dir = &telemetry_config()?.fuelup_tmp;

    // Filter out files not containing `.telemetry.` in the filename
    //
    // Also, ignore file age if `ignore_age` is true
    read_dir(telemetry_dir)?
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
