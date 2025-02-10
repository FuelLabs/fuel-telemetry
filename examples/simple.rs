use forc_telemetry::prelude::*;

fn main() {
    telemetry_init().unwrap();

    info!("An event with span 'main' is recorded since telemetry_init() sets telemetry=true");

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
    info!("An event with span 'main:test_a' is ignored since test_a()'s attribute sets telemetry=true");
}

#[tracing::instrument(fields(telemetry = false))]
pub fn test_e() {
    info!("An event with span 'main:test_a:test_e' is ignored since test_e()'s attribute sets telemetry=false");

    let level_e_span = span!(Level::ERROR, "level_e", telemetry = true);
    let _level_e_guard = level_e_span.enter();

    info!("An event with span 'main:test_a:test_e:level_e' is recorded since level_e's fields sets telemetry=true");
}
