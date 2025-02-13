use crate::{telemetry_config, EnvSetting, Result, TelemetryError};

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::NaiveDateTime;
use influxdb_line_protocol::LineProtocolBuilder;
use nix::{
    errno::Errno,
    fcntl::{Flock, FlockArg},
    sys::stat,
    unistd::{chdir, close, dup2, fork, setsid, sysconf, SysconfVar},
};
use regex::Regex;
use reqwest::blocking::{Client, Request, RequestBuilder};
use std::{
    clone::Clone,
    collections::HashMap,
    env::var,
    fs::{read_dir, remove_file, File, OpenOptions},
    io::{stderr, stdout, BufRead, BufReader, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::exit,
    sync::LazyLock,
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

        let rollfile_interval = get_env("FILEWATCHER_ROLLFILE_INTERVAL", "3600")
            .parse()
            .map_err(TelemetryError::InvalidRollfileInterval)?;

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
            rollfile_interval: Duration::from_secs(rollfile_interval),
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
    // A cached request to send to InfluxDB
    request: Request,
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
    pub fn new() -> Result<Self> {
        // Cache the InfluxDB request since it won't change between calls
        let request = Client::new()
            .post(&config()?.influxdb_url)
            .header("Content-Type", "text/plain; charset=utf-8")
            .header("Accept", "application/json")
            .header(
                "Authorization",
                format!("Token {}", config()?.influxdb_token.clone()),
            )
            .build()?;

        Ok(Self {
            request,
            lockfile_path: Path::new(&telemetry_config()?.fuelup_tmp)
                .join(config()?.lockfile.clone()),
        })
    }

    /// Start the `FileWatcher`
    ///
    /// This function forks and has the parent immediately return. The forked
    /// off child then daemonises to poll for aged-out telemetry files, sending
    /// them to InfluxDB, and exits once there are no more files to process.
    pub fn start(&self) -> Result<()> {
        if var("FUELUP_NO_TELEMETRY").is_ok() {
            // If telemetry is disabled, immediately return
            return Ok(());
        }

        if daemonise()? {
            // If we are the parent, immediately return
            return Ok(());
        }

        loop {
            // Enforce a singleton to ensure we are the only process submitting
            // telemetry to InfluxDB
            let _lock = enforce_singleton(&self.lockfile_path)?;

            // Poll for aged-out telemetry files
            let no_files_left = self.poll_directory()?;

            if no_files_left {
                exit(0)
            }

            sleep(config()?.rollfile_interval);
        }
    }

    /// Poll for aged-out telemetry files
    fn poll_directory(&self) -> Result<bool> {
        for file in find_telemetry_files()? {
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

            // Send LineProtocol to InfluxDB
            let response = RequestBuilder::from_parts(
                Client::new(),
                self.request
                    .try_clone()
                    .ok_or(TelemetryError::ReqwestCloneFailed)?,
            )
            .body(body.join("\n"))
            .send()?;

            if response.status().is_success() {
                // Only remove the telemetry file if successful
                remove_file(&file)?;
            }
        }

        Ok(find_telemetry_files()?.is_empty())
    }
}

//
// Helper functions that might be moved later to lib.rs
//

fn find_telemetry_files() -> Result<Vec<PathBuf>> {
    let rollfile_interval = config()?.rollfile_interval;
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
            if rollfile_interval < path.metadata().ok()?.modified().ok()?.elapsed().ok()? {
                Some(Ok(path))
            } else {
                None
            }
        })
        .collect::<Result<Vec<_>>>()
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
fn daemonise() -> Result<bool> {
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
            .join(config()?.logfile.clone())
            .to_str()
            .ok_or(TelemetryError::InvalidLogFile(
                telemetry_config()?.fuelup_tmp.clone(),
                config()?.logfile.clone(),
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