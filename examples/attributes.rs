use fuel_telemetry::prelude::*;

fn main() {
    telemetry_init().unwrap();

    info!("An event with span 'main' is recorded since telemetry_init() sets telemetry=true");

    test_a(
        "This value is recorded".to_string(),
        "This value is ignored".to_string(),
    );
}

#[tracing::instrument(fields(telemetry = true), skip(_arg_2))]
fn test_a(arg_1: String, _arg_2: String) {
    info!(
        "An event with span 'main:test_a' is recorded along with the value of arg_1 since \
           test_a()'s attribute sets telemetry=true, while _arg_2 is not recorded"
    );

    test_b();
    test_c();
    test_d(42);
    test_e(42);
    test_f(42);
}

pub fn test_b() {
    info!("An event with span 'main:test_a' is recorded since test_a()'s attribute sets telemetry=true");
}

#[tracing::instrument(name = "new_c", fields(telemetry = true))]
pub fn test_c() {
    info!("An event with span 'main:test_a:new_c' is recorded since test_c()'s attribute sets telemetry=true");
}

pub fn test_d(_answer: u8) {
    info!("An event with span 'main:test_a' is recorded since test_a()'s attribute sets telemetry=true");
}

#[tracing::instrument(fields(telemetry = false))]
pub fn test_e(answer: u8) {
    info!("An event with span 'main:test_a:test_e' is ignored since test_e()'s attribute sets telemetry=false");
}

#[tracing::instrument(fields(telemetry = true))]
pub fn test_f(answer: u8) {
    info!(
        "An event with span 'main:test_a:test_f' is recorded along with the \
        name and value of `anwser` since test_f()'s attribute sets telemetry=true"
    );
}
