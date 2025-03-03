
# Fuel Telemetry

`fuel-telemetry` is a `tracing` `Layer` used to implement telemetry within our
apps and libraries.

Steps to get `fuel-telemetry` going:

- Create a `TelemetryLayer` `tracing` `Layer`
- Add the `TelemetryLayer` to a `tracing` `Subscriber`
- Enable the `telemetry` field on `Span`s you want sent to InfluxDB
- Use the regular `tracing` macros (e.g `info!()`, `warn!()` etc) to record `Events`
- Start a `FileWatcher` so that telemetry files will be sent to InfluxDB
- Start a `SystemInfoWatcher` so that system info will be recorded

Most of these steps are hidden away behind convenience functions within `TelemetryLayer`.

## Using `fuel-telemetry`

### Within Applications with No Existing Tracing (Enabled by Default)

If you're writing an app where:

- `fuel-telemetry` will be your only `tracing` `Layer` and `Subscriber`
- and **you want all** `tracing` `Event`s to be sent to InfluxDB by default

then the quickest way to get going is:

```rust
use fuel_telemetry::prelude::*;

fn main() {
    telemetry_init().unwrap();

    info!("This event will be sent to InfluxDB");
}
```

### Within Applications with No Existing Tracing (Disabled by Default)

If you're writing an app where:
- `fuel-telemetry` will be your only `tracing` `Layer` and `Subscriber`
- and **you do NOT want all** `tracing` `Event`s to be sent to InfluxDB by default

then the quickest way to get going is:

```rust
use fuel_telemetry::prelude::*;

fn main() {
    let _guard = TelemetryLayer::new_global_default_with_watchers()?;
    info!("This event will not be sent in InfluxDB");

    // ... <code containing tracing events with telemetry disabled>
    // ...
    // ...

    // Time to enable telemetry from now on by setting telemetry=true on a `Span`
    let enabled_span = span!(Level::INFO, "root", telemetry=true);
    let _span_guard = enabled_span.enter();

    info!("This event will be sent to InfluxDB");
}
```

### Within Applications with Existing Tracing

If you're writing an app where `fuel-telemetry` will need to work along side
other `tracing` `Layer`s or `Subscriber`s, you will need to create a
`TelemetryLayer` by hand and then add it to your existing `Subscriber` e.g:

```rust
use fuel_telemetry::prelude::*;
use tracing_subscriber::prelude::*;

fn main() {
    // Create a `Telemetry` `Layer` where events will appear in InfluxDB
    let (telemetry_layer, _guard) = TelemetryLayer::new_with_watchers().unwrap();

    // Create a stdout `Layer` where events will appear on `stdout`
    let stdout_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stdout);

    // Create a `Subscriber` and combine these two `Layers`
    let subscriber = tracing_subscriber::registry()
        .with(telemetry_layer)
        .with(stdout_layer);

    // Set our subscriber as the default global subscriber
    tracing::subscriber::set_global_default(subscriber).unwrap();

    // ... <code containing tracing events only sent to stdout>
    // ...
    // ...

    // Time to enable telemetry from now on by setting telemetry=true on a `Span`
    let enabled_span = span!(Level::INFO, "root", telemetry=true);
    let _span_guard = enabled_span.enter();

    info!("This event will be sent to InfluxDB");
}
```

### Within Libraries

**Warning: libraries should not be setting the global default subscriber as it
will clobber any set by the application. In fact, `fuel-telemetry`'s own
`set_global_default()` function will return an error if you accidently call it
from within a library.**

Libraries should not need to interact with a `TelemetryLayer` directly. Instead,
just use the convenience macros provided when you need to record telemetry
events i.e:

- `info_telemetry!()`
- `warn_telemetry!()`
- `error_telemetry!()`
- `debug_telemetry!()`
- `trace_telemetry!()`

```rust
use fuel_telemetry::prelude::*;

info_telemetry!(guess = 42);
```

**Note:** `telemetry` is `disabled` by default. See below on how to enable telemetry
on `Event`s within your library.

### Detailed Examples

For detailed examples, see `examples/*.rs`.

## Enabling Telemetry

Each `tracing` `Event` is either `enabled` or `disabled` based on the current
`Span`'s setting (if one exists). By default, the root `Span` is disabled.

There are 2 ways to set the `telemetry` field:

1. On a `Span` itself e.g `span!(Level::ERROR, "span_name", telemetry=true)`
1. Via function attributes e.g `#[tracing::instrument(fields(telemetry=true))]`

Given that `tracing` `Span`s are hierarchical, if a function does not have a
`tracing` attribute, or it does have one but the `telemetry` field is not set, we
fall back by climbing the hierarchy until we explicitly find one set. In the end
if no `Span` is found, we default to `telemetry=false`.

## Warning!

Be careful when using function attributes to enable telemetry as every function
call invocation (along with its parameter names and values) will be a recorded
as separate `Event`s and subsequently sent to InfluxDB...

* If used within a hot path, lots of data will be generated and sent over the
wire. Times this by the amount of installs across the entire userbase, and
you'll see that it could be an overwhelming amount of data and it's eventual
cost.

* PII (Personally Identifiable Information) and other sensitive information
  (think private keys and passwords) could make its way to InfluxDB by accident.
  If your functions have any PII (including Public Keys or even hashes of unique
  data etc), use the `skip()` function attribute i.e:

  `#[tracing::instrument(skip(secret_key, password))]`

## Debugging Telemetry

### Inspecting Telemetry Files

Telemetry files on disk are stored Base64 encoded. To peek into them:

```sh
cat ~/.fuelup/tmp/*.telemetry.* | while read line; do echo "$line" | base64 -d; echo; done
```

### Manually Aging Out Telemetry Files

As `FileWatcher` only submits files to InfluxDB that are over an hour old by
default, we can force files to age out early so they are instantly submitted
on next run:

```sh
for f in ~/.fuelup/tmp/*.telemetry.*; do mv "$f" "$f.old"; done
touch -t 202501010101 ~/.fuelup/tmp/*
```

### Overriding InfluxDB's Endpoint

Use the `INFLUXDB_URL` environment variable to point to a different InfluxDB
endpoint. This can be combined with running a local InfluxDB container:

```sh
docker compose up influxdb2
export INFLUXDB_URL=http://localhost:8086
```

The InfluxDB connection settings can be further configured using the following
environment variables:

- `INFLUXDB_TOKEN`
- `INFLUXDB_ORG`
- `INFLUXDB_BUCKET`

See InfluxDB's documentation for [Using Docker
Compose](https://docs.influxdata.com/influxdb/v2/install/use-docker-compose/)
for more info on getting InfluxDB running locally.

### Architectural Design

To get an overview of how `fuel-telemetry` works, the Architectural Design can
be found in `docs/architecture.md`