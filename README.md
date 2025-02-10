
# Forc Telemetry

The `forc-telemetry` crate is a `tracing` `Layer` used to implement Telemetry within our libraries and apps.

Each `tracing` `Event` is either "enabled" or "disabled" based on the current
`Span`'s setting. There are 2 ways to set this:

1. On the `Span` e.g `span!(Level::ERROR, "level1", telemetry=true)`
2. Within a function attribute e.g `#[tracing::instrument(fields(telemetry=false))]`

If a function does not have a `tracing` attribute or has one but does not set
the `telemetry` field, it will use the currently used `Span` setting if one
exists. By default, `telemetry=false`.

## Hello World Example

    use forc_telemetry::{TelemetryLayer, error, event, info, span, warn, Level, file_watcher};

    fn main() {
        // Setup `forc-telemetry` as the default tracing subscriber
        let _tracing_guard = TelemetryLayer::new_global_default().unwrap();

        // Create a `FileWatcher` which submits telemetry to InfluxDB
        let file_watcher = file_watcher::FileWatcher::new().unwrap();
        file_watcher.start().unwrap_or_else(|e| {
            eprintln!("FileWatcher start failed: {e:?}");
        });

        // Create a `tracing` `Event` outside any `Span` (disabled given telemetry=false)
        event!(Level::ERROR, "A trace event");

        // Create the root `tracing` `Span`
        let main_span = span!(Level::ERROR, "main");
        let _main_guard = main_span.enter();

        // Create `tracing` `Event`s within the `main` `Span` (disabled)
        info!("An info event");
        error!("An error event");

        // Create an `ERROR` `tracing` `Event` using the longform method (disabled)
        event!(Level::ERROR, "An error event");

        // Create a leaf `tracing` `Span` (enabled given telemetry=true)
        let level1_span = span!(Level::ERROR, "level1", telemetry=true);
        let _level1_guard = level1_span.enter();

        // Create `tracing` `Event`s within the `main:level1` `Span` (enabled)
        info!("An info event");
        error!("An error event");

        // Create an `ERROR` `tracing` `Event` using the longform method (enabled)
        event!(Level::ERROR, "An error event");

        {
            // Create a leaf `tracing` `Span` (enabled given telemetry=true)
            let level2_span = span!(Level::ERROR, "level2", telemetry=true);
            let _level2_guard = level2_span.enter();

            // Create `tracing` `Event`s within the `main:level1:level2` `Span` (enabled)
            info!("An info event");
            error!("An error event");
        }

        test_a();
    }

    #[tracing::instrument]
    fn test_a() {
        // Create a `tracing` `Event` within the `main:level1:test_a` `Span` (enabled)
        info!("An info event");

        test_b();
        test_c();
    }

    #[tracing::instrument(fields(telemetry=false))]
    pub fn test_b() {
        // Create a `tracing` `Event` within the `main:level1:test_b` `Span` (disabled)
        info!("An info event");
    }

    #[tracing::instrument(fields(telemetry=false))]
    pub fn test_c() {
        // Create a `tracing` `Event` within the `main:level1:test_b:test_c` `Span` (disabled)
        info!("An info event");

        // Create a leaf `tracing` `Span` (enabled given telemetry=true)
        let levelc_span = span!(Level::ERROR, "levelc", telemetry=true);
        let _levelc_guard = levelc_span.enter();

        // Create a `tracing` `Event` within the `main:level1:test_b:test_c:levelc` `Span` (enabled)
        info!("An info event");
    }
