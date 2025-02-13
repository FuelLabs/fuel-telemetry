use fuel_telemetry::prelude::*;
use tracing_subscriber::prelude::*;

fn main() {
    // Create a `Telemetry` `Layer` and its drop guard
    let (telemetry_layer, _guard) = TelemetryLayer::new_with_filewatcher().unwrap();

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

    info!("An event with span 'main' is ignored since telemetry=false by default");

    test_a();
}

#[tracing::instrument(fields(telemetry = false))]
fn test_a() {
    info!("An event with span 'main:test_a' is ignored since test_a()'s attribute sets telemetry=false");

    test_b();
    test_c();
    test_d();
    test_e();
}

pub fn test_b() {
    info!("An event with span 'main:test_a' is ignored since test_a()'s attribute sets telemetry=false");
}

#[tracing::instrument(fields(telemetry = true))]
pub fn test_c() {
    info!("An event with span 'main:test_a:test_c' is recorded since test_c()'s attribute sets telemetry=true");
}

pub fn test_d() {
    info!("An event with span 'main:test_a' is ignored since test_a()'s attribute sets telemetry=false");
}

#[tracing::instrument(fields(telemetry = false))]
pub fn test_e() {
    info!("An event with span 'main:test_a:test_e' is ignored since test_e()'s attribute sets telemetry=false");

    let level_e_span = span!(Level::ERROR, "level_e", telemetry = true);
    let _level_e_guard = level_e_span.enter();

    info!("An event with span 'main:test_a:test_e:level_e' is recorded since level_e's fields sets telemetry=true");
}
