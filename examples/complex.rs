use fuel_telemetry::{prelude::*, file_watcher};

fn main() {
    // Create a `TelemetryLayer` which is a `tracing` `Layerd` that records telemetry
    let (telemetry_layer, _guard) = TelemetryLayer::new().unwrap();

    // Set `telemetry_layer` as the default tracing subscriber
    telemetry_layer.set_global_default();

    // Create a `FileWatcher` to submit telemetry to InfluxDB
    let file_watcher = file_watcher::FileWatcher::new().unwrap();

    // Start the `FileWatcher`
    file_watcher.start().unwrap_or_else(|e| {
        panic!("FileWatcher start failed: {e:?}");
    });

    event!(
        Level::ERROR,
        "An event with no span is ignored since telemetry=false by default"
    );

    // Create the root `tracing` `Span` (disabled given telemetry=false by default)
    let main_span = span!(Level::INFO, "main");
    let _main_guard = main_span.enter();

    info!(
        "An event with span 'main' is ignored since main's fields sets telemetry=false by default"
    );
    error!(
        "An event with span 'main' is ignored since main's fields sets telemetry=false by default"
    );

    event!(
        Level::ERROR,
        "An event with span 'main' is ignored since main's fields sets telemetry=false by default"
    );

    // Create a leaf `tracing` `Span` (enabled given the supplied telemetry=true field)
    let level_1_span = span!(Level::INFO, "level_1", telemetry = true);
    let _level_1_guard = level_1_span.enter();

    warn!(
        "An event with span 'main:level_1' is recorded since level_1's fields sets telemetry=true"
    );
    error!(
        "An event with span 'main:level_1' is recorded since level_1's fields sets telemetry=true"
    );

    event!(
        Level::ERROR,
        "An event with span 'main:level_1' is recorded since level_1's fields sets telemetry=true"
    );

    {
        // Create a leaf `tracing` `Span` (enabled given level_1's fields sets telemetry=true)
        let level_2_span = span!(Level::INFO, "level_2");
        let _level_2_guard = level_2_span.enter();

        info!("An event with span 'main:level_1:level_2' is recorded since level_1's fields sets telemetry=true");
        error!("An event with span 'main:level_1:level_2' is recorded since level_1's fields sets telemetry=true");
    }

    test_a();
}

fn test_a() {
    info!(
        "An event with span 'main:level_1' is recorded since level_1's fields sets telemetry=true"
    );

    test_b();
    test_c();
}

#[tracing::instrument(fields(telemetry = false))]
pub fn test_b() {
    info!("An event with span 'main:level_1:test_b' is ignored since test_b()'s attribute sets telemetry=false");
}

#[tracing::instrument(fields(telemetry = false))]
pub fn test_c() {
    info!("An event with span 'main:level_1:test_c' is ignored since test_c()'s attribute sets telemetry=false");

    // Create a leaf `tracing` `Span` (enabled given the supplied telemetry=true)
    let level_c_span = span!(Level::INFO, "level_c", telemetry = true);
    let _level_c_guard = level_c_span.enter();

    error!("An event with span 'main:level_1:test_c:level_c' is recorded since level_c's fields sets telemetry=true");
}
