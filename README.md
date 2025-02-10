
# Forc Telemetry

The `forc-telemetry` crate is a `tracing` `Layer` used to implement Telemetry within our libraries and apps.

Each `tracing` `Event` is either "enabled" or "disabled" based on the current
`Span`'s setting. There are 2 ways to set this:

1. On the `Span` e.g `span!(Level::ERROR, "level1", telemetry=true)`
2. Within a function attribute e.g `#[tracing::instrument(fields(telemetry=false))]`

If a function does not have a `tracing` attribute or has one but does not set
the `telemetry` field, it will use the currently used `Span` setting if one
exists. By default, `telemetry=false`.

## Examples

See `examples/*.rs` on the various ways to use `forc-telemetry`.

Note: if you are writing an app and `forc-telemetry` is your only `tracing`
`Layer`, the easiest way to get going is:

    use forc_telemetry::prelude::*;

    fn main() {
        telemetry_init().unwrap();

        info!("This info event will be recorded into InfluxDB");
    }