use fuel_telemetry::{file_watcher, prelude::*, systeminfo_watcher};
use tracing_subscriber::prelude::*;

fn main() {
    // Warning: We need to create the `FileWatcher` and `SystemInfoWatcher`
    // before the `TelemetryLayer` as there is a race condition between the
    // thread runtime of `tracing` and the tokio runtime of `Reqwest`. Swapping
    // order of the two could lead to possible deadlocks.

    // Create a `FileWatcher` to submit telemetry to InfluxDB
    let mut file_watcher = file_watcher::FileWatcher::new().unwrap();

    // Start the `FileWatcher`
    file_watcher.start().unwrap_or_else(|e| {
        panic!("FileWatcher start failed: {e:?}");
    });

    // Create a `SystemInfoWatcher` to record system info
    let mut systeminfo_watcher = systeminfo_watcher::SystemInfoWatcher::new().unwrap();

    // Start the `SystemInfoWatcher`
    systeminfo_watcher.start().unwrap_or_else(|e| {
        panic!("SystemInfoWatcher start failed: {e:?}");
    });

    // Create a `TelemetryLayer` and its drop guard
    let (telemetry_layer, _guard) = fuel_telemetry::new!().unwrap();

    // Set the global default `Subscriber` to the `TelemetryLayer`
    let subscriber = tracing_subscriber::registry().with(telemetry_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();

    get_public_data(42);
    get_private_data(99);
}

fn get_public_data(seed: u64) {
    let start = std::time::Instant::now();
    // <process that takes a while>
    let duration = start.elapsed().as_secs_f64();

    // The following `Event` will be sent to InfluxDB
    info_telemetry!(seed, duration);
}

fn get_private_data(seed: u64) {
    let start = std::time::Instant::now();
    // <process that takes a while>
    let duration = start.elapsed().as_secs_f64();

    // The following `Event` will NOT be sent to InfluxDB
    info!(seed, duration);
}
