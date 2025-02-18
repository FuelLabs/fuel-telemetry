use crate::{
    daemonise, enforce_singleton, info, telemetry_config, EnvSetting, Result, TelemetryError,
};

use nix::{
    fcntl::{Flock, FlockArg},
    sys::stat::fstat,
    time::ClockId,
};
use std::{
    env::{set_var, var},
    fs::OpenOptions,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::exit,
    sync::LazyLock,
    time::Duration,
};
use sysinfo::{MemoryRefreshKind, System};

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
                interval: get_env("SYSTEMINFO_WATCHER_INTERVAL", "2592000")
                    .parse()
                    .map_err(|e| {
                        TelemetryError::InvalidConfig(format!("Interval is invalid: {}", e))
                    })?,
                metadata_timeout: get_env("METADATA_TIMEOUT", "3").parse().map_err(|e| {
                    TelemetryError::InvalidConfig(format!("Metadata timeout is invalid: {}", e))
                })?,
                lockfile: Path::new(&telemetry_config()?.fuelup_tmp)
                    .join("telemetry-systeminfo-watcher.lock"),
                logfile: Path::new(&telemetry_config()?.fuelup_log)
                    .join("telemetry-systeminfo-watcher.log"),
                touchfile: Path::new(&telemetry_config()?.fuelup_tmp)
                    .join("telemetry-systeminfo-watcher.touch"),
            })
        });

    SYSTEMINFO_WATCHER_CONFIG
        .as_ref()
        .map_err(|e| TelemetryError::InvalidConfig(e.to_string()))
}

// Although there's no need to keep the state of this watcher, keep it consistent
// with the other watchers
pub struct SystemInfoWatcher;

impl SystemInfoWatcher {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }

    pub fn start(&mut self) -> Result<()> {
        if var("FUELUP_NO_TELEMETRY").is_ok() {
            // If telemetry is disabled, immediately return
            return Ok(());
        }

        // Even though we won't be hanging around long, we still daemonise
        // so that we don't get in the way of the calling process
        if daemonise(&config()?.logfile)? {
            // If we are the parent, immediately return
            return Ok(());
        }

        // Warning: We need to create the `TelemetryLayer` after daemonising
        // as there is a race condition in the thread runtime of `tracing` and
        // the tokio runtime of `Reqwest`. Swapping order of the two could lead to
        // possible deadlocks.
        //
        // Also, we need to set the bucket name as the SystemInfoWatcher is
        // global rather than being crate/process specific
        set_var("INFLUXDB_BUCKET", "systeminfo_watcher");
        let (telemetry_layer, _guard) = TelemetryLayer::new()?;
        telemetry_layer.set_global_default();

        // Enforce a singleton to ensure we are the only process submitting
        // telemetry to InfluxDB
        let _lock = enforce_singleton(&config()?.lockfile)?;
        eprintln!("Lock enforced");

        // Check if it's time to collect metrics
        self.poll_systeminfo()?;

        exit(0);
    }

    fn poll_systeminfo(&self) -> Result<()> {
        //  Lock the touchfile, creating it if necessary
        let locked_file = Flock::lock(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&config()?.touchfile)?,
            FlockArg::LockExclusiveNonblock,
        )
        .map_err(|(_, e)| e)?;

        let now = ClockId::CLOCK_REALTIME
            .now()
            .map_err(|e| TelemetryError::Nix(e.to_string()))?;

        // Return if it's too early to collect metrics
        if now.tv_sec() < fstat(locked_file.as_raw_fd())?.st_mtime + config()?.interval as i64 {
            return Ok(());
        }

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
        let cpu_count = cpus.len().to_string();
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
        let vm = detect_vm()?;

        info!(
            cpu_arch = System::cpu_arch(),
            cpu_brand = cpu_brand,
            cpu_count = cpu_count,
            global_cpu_usage = sysinfo.global_cpu_usage(),
            total_memory = total_memory,
            free_memory = free_memory,
            free_memory_percentage = free_memory_percentage,
            os_long_name = System::long_os_version().unwrap_or_default(),
            kernel_version = System::kernel_version().unwrap_or_default(),
            uptime = System::uptime(),
            vm = vm,
            ci = ci,
            load_average_1m = load_average.one,
            load_average_5m = load_average.five,
            load_average_15m = load_average.fifteen,
        );

        Ok(())
    }
}

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

        if request.send()?.status() == reqwest::StatusCode::OK {
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
