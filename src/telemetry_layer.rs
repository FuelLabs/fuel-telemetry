use std::{env::var, path::PathBuf};
use tracing::{
    span::{self, Id, Record},
    Event,
};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::layer::Context;
use tracing_subscriber::{
    fmt::{format::DefaultFields, Layer},
    Layer as LayerTrait, Registry,
};

use crate::{
    errors::TelemetryError, telemetry_config, telemetry_formatter::TelemetryFormatter, Result,
};

/// A `tracing` `Layer` to generate telemetry to be later consumed into InfluxDB
///
/// This `tracing` `Layer` formats telemetry and stores the output in a known
/// location ($FUEL_HOME/tmp/<crate>.telemetry), ready for ingestion by an
/// InfluxDB collector.
pub struct TelemetryLayer {
    pub __inner: Layer<Registry, DefaultFields, TelemetryFormatter, NonBlocking>,
}

impl TelemetryLayer {
    /// Although public, `__new()` is only intended to be called via the
    /// following constructor macros:
    ///
    /// - `fuel_telemetry::new!()`
    /// - `fuel_telemetry::new_with_watchers!()`
    /// - `fuel_telemetry::new_with_watchers_and_init!()`
    pub fn __new() -> Result<(Self, WorkerGuard)> {
        let (writer, guard) = {
            if var("FUELUP_NO_TELEMETRY").is_ok() {
                // If telemetry is disabled, discards all output
                tracing_appender::non_blocking(std::io::sink())
            } else {
                // This value needs to come from the cargo target which must be
                // set from a macro constructor. Calling `env!('CARGO_PKG_NAME')`
                // here will be incorrect as the macro will have already expaneded
                // leading to the constant value "fuel-telemetry" for all targets
                if var("TELEMETRY_PKG_NAME").is_err() || var("TELEMETRY_PKG_VERSION").is_err() {
                    return Err(TelemetryError::InvalidUsage);
                }

                // If telemetry is enabled, telemetry will be written to a file
                // that is rotated hourly with the filename format:
                // "$FUELUP_TMP/<crate>.telemetry.YYYY-MM-DD-HH"
                tracing_appender::non_blocking(tracing_appender::rolling::hourly(
                    PathBuf::from(telemetry_config()?.fuelup_tmp.clone()),
                    format!(
                        "{}.telemetry",
                        var("TELEMETRY_PKG_NAME")
                            .map_err(|_| TelemetryError::UnreadableCrateName)?
                    ),
                ))
            }
        };

        // We need to disable ANSI codes as it breaks InfluxDB parsing
        let inner = tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .with_ansi(false)
            .event_format(TelemetryFormatter::new());

        Ok((Self { __inner: inner }, guard))
    }
}

// Implement the `Layer` trait for `TelemetryLayer`
//
// Here we simply proxy calls to the inner layer.
impl LayerTrait<Registry> for TelemetryLayer {
    fn on_close(&self, id: Id, ctx: Context<'_, Registry>) {
        self.__inner.on_close(id, ctx);
    }

    fn on_enter(&self, id: &span::Id, ctx: Context<'_, Registry>) {
        self.__inner.on_enter(id, ctx);
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, Registry>) {
        self.__inner.on_event(event, ctx);
    }

    fn on_exit(&self, id: &span::Id, ctx: Context<'_, Registry>) {
        self.__inner.on_exit(id, ctx);
    }

    fn on_id_change(&self, old: &span::Id, new: &span::Id, ctx: Context<'_, Registry>) {
        self.__inner.on_id_change(old, new, ctx);
    }

    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, Registry>) {
        self.__inner.on_new_span(attrs, id, ctx);
    }

    fn on_follows_from(&self, span: &span::Id, follows: &span::Id, ctx: Context<'_, Registry>) {
        self.__inner.on_follows_from(span, follows, ctx);
    }

    fn on_record(&self, span: &Id, values: &Record<'_>, ctx: Context<'_, Registry>) {
        self.__inner.on_record(span, values, ctx);
    }
}
