use fuel_telemetry::prelude::*;

fn main() {
    telemetry_init().unwrap();

    info!("An event with span 'main' is recorded since telemetry_init() sets telemetry=true");

    let level_1_span = span!(Level::INFO, "level_1", telemetry = true);
    let _level_1_guard = level_1_span.enter();
    info!(
        "An event with span 'main:level_1' is recorded since level_1's fields sets telemetry=true"
    );

    let level_2_span = span!(Level::INFO, "level_2");
    let _level_2_guard = level_2_span.enter();
    info!("An event with span 'main:level_1:level_2' is recorded since level_1's fields sets telemetry=true");

    let level_3_span = span!(Level::INFO, "level_3");
    let _level_3_guard = level_3_span.enter();
    info!("An event with span 'main:level_1:level_2:level_3' is recorded since level_1's fields sets telemetry=true");

    let level_4_span = span!(Level::INFO, "level_4", telemetry = false);
    let _level_4_guard = level_4_span.enter();
    info!("An event with span 'main:level_1:level_2:level_3:level_4' is ignored since level_4's fields sets telemetry=false");

    let level_5_span = span!(Level::INFO, "level_5", telemetry = true);
    let _level_5_guard = level_5_span.enter();
    info!("An event with span 'main:level_1:level_2:level_3:level_4:level_5' is recorded since level_5's fields sets telemetry=true");
}
