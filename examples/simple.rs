use fuel_telemetry::prelude::*;

fn main() {
    // The following line:
    // - starts a `FileWatcher` and `SystemInfoWatcher`
    // - creates a `TelemetryLayer` and its drop guard
    // - sets the global default `Subscriber` to the `TelemetryLayer`
    let _guard = fuel_telemetry::new_with_watchers_and_init!().unwrap();

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
