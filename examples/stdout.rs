use fuel_telemetry::prelude::*;
use tracing_subscriber::prelude::*;

fn main() {
    // Create a `Telemetry` `Layer` and its drop guard
    let (telemetry_layer, _guard) = TelemetryLayer::new_with_watchers().unwrap();

    // Create a stdout `Layer`
    let stdout_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stdout);

    // Create a `Subscriber` and combine these two `Layers`
    let subscriber = tracing_subscriber::registry()
        .with(telemetry_layer)
        .with(stdout_layer);

    // Set our subscriber as the default global subscriber, which contains the
    // above two tracing `Layers`:
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

    let span = span!(Level::INFO, "get_public_data", telemetry = true);
    let _guard = span.enter();

    // The following event will have a `Span` of `get_public_data`,
    // will be printed to stdout, and will be sent to InfluxDB as
    // telemetry=true for the current `Span`
    info!(seed, duration);
}

#[tracing::instrument(fields(telemetry = false))]
fn get_private_data(seed: u64) {
    let start = std::time::Instant::now();
    // <process that takes a while>
    let duration = start.elapsed().as_secs_f64();

    // The following event will have a `Span` of `get_private_data`,
    // will be printed to stdout, but will NOT be sent to InfluxDB as
    // telemetry=false for the current function's attribute
    info!(seed, duration);
}
