use fuel_telemetry::prelude::*;
use tracing_subscriber::prelude::*;

fn main() {
    // The following line:
    // - starts a `FileWatcher` and `SystemInfoWatcher`
    // - creates a `TelemetryLayer` and its drop guard
    let (telemetry_layer, _guard) = fuel_telemetry::new_with_watchers!().unwrap();

    // Create a stdout `Layer`
    let stdout_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stdout);

    // Create a `Subscriber` and combine these two `Layers`
    let subscriber = tracing_subscriber::registry()
        .with(telemetry_layer)
        .with(stdout_layer);

    // Set our subscriber as the global default `Subscriber`, which contains the
    // above two `tracing` `Layers`:
    // - `TelemetryLayer` events will appear within InfluxDB
    // - `stdout_layer` will print events to stdout
    tracing::subscriber::set_global_default(subscriber).unwrap();

    get_public_data(42);
    get_private_data(99);
}

fn get_public_data(seed: u64) {
    let start = std::time::Instant::now();
    // <process that takes a while>
    let duration = start.elapsed().as_secs_f64();

    // The following `Event` will be printed and sent to InfluxDB
    info_telemetry!(seed, duration);
}

fn get_private_data(seed: u64) {
    let start = std::time::Instant::now();
    // <process that takes a while>
    let duration = start.elapsed().as_secs_f64();

    // The following `Event` will be printed but NOT sent to InfluxDB
    info!(seed, duration);
}
