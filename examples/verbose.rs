use fuel_telemetry::{file_watcher, prelude::*, systeminfo_watcher};

fn main() {
    // Warning: We need to create the `FileWatcher` and `SystemInfoWatcher`
    // before the `TelemetryLayer` as there is a race condition in the
    // thread runtime of `tracing` and the tokio runtime of `Reqwest`.
    // Swapping order of the two could lead to possible deadlocks.

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

    // Create a `TelemetryLayer` which is a `tracing` `Layerd` that records telemetry
    let (telemetry_layer, _guard) = TelemetryLayer::new().unwrap();

    // Set `telemetry_layer` as the default tracing subscriber
    telemetry_layer.set_global_default();

    get_public_data(42);
    get_private_data(99);
}

fn get_public_data(seed: u64) {
    let start = std::time::Instant::now();
    // <process that takes a while>
    let duration = start.elapsed().as_secs_f64();

    let span = span!(Level::INFO, "get_public_data", telemetry = true);
    let _guard = span.enter();

    // The following event will have a `Span` of `get_public_data`
    // and will be sent to InfluxDB as telemetry=true for the current `Span`
    info!(seed, duration);
}

#[tracing::instrument(fields(telemetry = false))]
fn get_private_data(seed: u64) {
    let start = std::time::Instant::now();
    // <process that takes a while>
    let duration = start.elapsed().as_secs_f64();

    // The following event will NOT be sent to InfluxDB as
    // telemetry=false for the current function's attribute
    info!(seed, duration);
}