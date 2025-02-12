use fuel_telemetry::prelude::*;

fn main() {
    // This one-liner hides most of the tracing and telemetry boilerplate code:
    // - Sets `TelemetryLayer` as the default `tracing` `Subscriber`
    // - Creates the root `Span` with the following settings:
    //     - name: `main`
    //     - level: `Level::ERROR`
    //     - telemetry: true
    // - Starts a `FileWatcher` to poll the filesystem for aged-out telemetry
    //   files and then submit them to InfluxDB

    telemetry_init().unwrap();

    // Create a tracing `Span` that will also be submitted to InfluxDB
    info!("An event with span 'main' is recorded since telemetry_init() sets telemetry=true");

    test_a();
}

// When a function has an attribute in the form
// `#[tracing::instrument(fields(telemetry = true))]`, function calls create a
// an `Event` on entry along with the following settings:
// - span name: `<function_name>`
// - telemetry: true
// - fields: function argument name and values used during the call
//
// To hide sensitive function parameters from being recorded, the skip attribute parameter can be used:
// `#[tracing::instrument(fields(telemetry = true), skip(<sensitive_parameter_name>))]`

#[tracing::instrument(fields(telemetry = false))]
fn test_a() {
    info!("An event with span 'main:test_a' is ignored since test_a()'s attribute sets telemetry=false");

    test_b();
    test_c();
    test_d();
    test_e();
}

pub fn test_b() {
    // As there was no function argument for `test_b()`, we fall back to the
    // current span (which would be `main:test_a`), however as the `test_a()`
    // function attribute sets telemetry=false, this event will be ignored`
    info!("An event with span 'main:test_a' is ignored since test_a()'s attribute sets telemetry=false");
}

#[tracing::instrument(fields(telemetry = true))]
pub fn test_c() {
    info!("An event with span 'main:test_a:test_c' is recorded since test_c()'s attribute sets telemetry=true");
}

pub fn test_d() {
    info!("An event with span 'main:test_a' is ignored since test_a()'s attribute sets telemetry=true");
}

#[tracing::instrument(fields(telemetry = false))]
pub fn test_e() {
    info!("An event with span 'main:test_a:test_e' is ignored since test_e()'s attribute sets telemetry=false");

    // We can also create `Span`s manually rather than from a function attribute:
    let level_e_span = span!(Level::ERROR, "level_e", telemetry = true);
    let _level_e_guard = level_e_span.enter();

    info!("An event with span 'main:test_a:test_e:level_e' is recorded since level_e's fields sets telemetry=true");
}
