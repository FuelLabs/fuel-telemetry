use fuel_telemetry::prelude::*;

fn main() {
    // Initialise telemetry (this enables telemetry by default and sets the
    // root `Span` to `main`)
    telemetry_init().unwrap();

    get_public_data(42);
    get_private_data(99);
}

fn get_public_data(seed: u64) {
    let start = std::time::Instant::now();
    // <process that takes a while>
    let duration = start.elapsed().as_secs_f64();

    let span = span!(Level::INFO, "get_public_data");
    let _guard = span.enter();

    // The following event will have a `Span` of `main:get_public_data`
    // and will be sent to InfluxDB as telemetry is enabled
    info!(seed, duration);
}

#[tracing::instrument(fields(telemetry = false))]
fn get_private_data(seed: u64) {
    let start = std::time::Instant::now();
    // <process that takes a while>
    let duration = start.elapsed().as_secs_f64();

    let span = span!(Level::INFO, "get_private_data");
    let _guard = span.enter();

    // The following event will NOT be sent to InfluxDB as
    // telemetry=false for the current `Span`
    info!(seed, duration);
}
