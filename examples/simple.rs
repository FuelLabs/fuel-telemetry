use fuel_telemetry::prelude::*;

fn main() {
    // This convenience function hides most of the tracing and telemetry
    // boilerplate code:
    //
    // - Creates a new `TelemetryLayer` `tracing` `Layer`
    // - Sets it as the global default `tracing` `Subscriber`
    // - Creates the root `span` called "main"
    // - Enters the "main" `span`
    // - Create a `FileWatcher` and starts it
    telemetry_init().unwrap();

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
//
// Here however, we are setting `telemetry=false` so `Event`s will be ignored.
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
    info!("An event with span 'main:test_a' is ignored since test_a()'s attribute sets telemetry=false");
}

#[tracing::instrument(fields(telemetry = false))]
pub fn test_e() {
    info!("An event with span 'main:test_a:test_e' is ignored since test_e()'s attribute sets telemetry=false");

    // We can also create `Span`s manually rather than from a function attribute:
    let level_e_span = span!(Level::ERROR, "level_e", telemetry = true);
    let _level_e_guard = level_e_span.enter();

    info!("An event with span 'main:test_a:test_e:level_e' is recorded since level_e's fields sets telemetry=true");
}
