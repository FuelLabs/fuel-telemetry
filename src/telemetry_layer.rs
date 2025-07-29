use std::{env::var, io::Write, path::PathBuf};
use tracing::{
    Event,
    span::{self, Id, Record},
};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::{
    Layer as LayerTrait, Registry,
    fmt::{Layer, format::DefaultFields},
    layer::Context,
};

use crate::{
    Result, errors::TelemetryError, telemetry_config, telemetry_formatter::TelemetryFormatter,
};

/// A `tracing` `Layer` to generate telemetry to be later consumed into InfluxDB
///
/// This `tracing` `Layer` formats telemetry and stores the output in a known
/// location ($FUEL_HOME/tmp/<crate>.telemetry), ready for ingestion by an
/// InfluxDB collector.
pub struct TelemetryLayer {
    pub inner_layer: Layer<Registry, DefaultFields, TelemetryFormatter, NonBlocking>,
}

impl TelemetryLayer {
    /// Although public, `__new()` is only intended to be called via the
    /// following constructor macros:
    ///
    /// - `fuel_telemetry::new!()`
    /// - `fuel_telemetry::new_with_watchers!()`
    /// - `fuel_telemetry::new_with_watchers_and_init!()`
    pub fn __new() -> Result<(Self, WorkerGuard)> {
        Self::__new_with_helpers(&mut DefaultNewHelpers)
    }

    fn __new_with_helpers(helpers: &mut impl NewHelpers) -> Result<(Self, WorkerGuard)> {
        let (writer, guard) = {
            if var("FUELUP_NO_TELEMETRY").is_ok() {
                // If telemetry is disabled, discards all output
                helpers.create_non_blocking_sink()
            } else {
                let telemetry_pkg_name = var("TELEMETRY_PKG_NAME");

                // This value needs to come from the cargo target which must be
                // set from a macro constructor. Calling `env!('CARGO_PKG_NAME')`
                // here will be incorrect as the macro will have already expaneded
                // leading to the constant value "fuel-telemetry" for all targets
                if telemetry_pkg_name.is_err() || var("TELEMETRY_PKG_VERSION").is_err() {
                    return Err(TelemetryError::InvalidUsage);
                }

                // If telemetry is enabled, telemetry will be written to a file
                // that is rotated hourly with the filename format:
                // "$FUELUP_TMP/<crate>.telemetry.YYYY-MM-DD-HH"
                helpers.create_non_blocking_appender(tracing_appender::rolling::hourly(
                    PathBuf::from(telemetry_config()?.fuelup_tmp.clone()),
                    format!(
                        "{}.telemetry",
                        telemetry_pkg_name.map_err(|_| TelemetryError::UnreadableCrateName)?
                    ),
                ))
            }
        };

        // We need to disable ANSI codes as it breaks InfluxDB parsing
        let inner_layer = tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .with_ansi(false)
            .event_format(TelemetryFormatter::new());

        Ok((Self { inner_layer }, guard))
    }
}

/// Sets `TRACE_ID` env variable to a new UUID.
pub fn set_trace_id_env_to_new_uuid() {
    let trace_id = uuid::Uuid::new_v4().to_string();
    std::env::set_var("TRACE_ID", trace_id);
}

trait NewHelpers {
    fn create_non_blocking_sink(&mut self) -> (NonBlocking, WorkerGuard) {
        tracing_appender::non_blocking(std::io::sink())
    }

    fn create_non_blocking_appender(
        &mut self,
        writer: impl Write + Send + 'static,
    ) -> (NonBlocking, WorkerGuard) {
        tracing_appender::non_blocking(writer)
    }
}

struct DefaultNewHelpers;
impl NewHelpers for DefaultNewHelpers {}

// Implement the `Layer` trait for `TelemetryLayer`
//
// Here we simply proxy calls to the inner layer.
impl LayerTrait<Registry> for TelemetryLayer {
    fn on_close(&self, id: Id, ctx: Context<'_, Registry>) {
        self.inner_layer.on_close(id, ctx);
    }

    fn on_enter(&self, id: &span::Id, ctx: Context<'_, Registry>) {
        self.inner_layer.on_enter(id, ctx);
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, Registry>) {
        self.inner_layer.on_event(event, ctx);
    }

    fn on_exit(&self, id: &span::Id, ctx: Context<'_, Registry>) {
        self.inner_layer.on_exit(id, ctx);
    }

    fn on_id_change(&self, old: &span::Id, new: &span::Id, ctx: Context<'_, Registry>) {
        self.inner_layer.on_id_change(old, new, ctx);
    }

    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, Registry>) {
        self.inner_layer.on_new_span(attrs, id, ctx);
    }

    fn on_follows_from(&self, span: &span::Id, follows: &span::Id, ctx: Context<'_, Registry>) {
        self.inner_layer.on_follows_from(span, follows, ctx);
    }

    fn on_record(&self, span: &Id, values: &Record<'_>, ctx: Context<'_, Registry>) {
        self.inner_layer.on_record(span, values, ctx);
    }
}

#[cfg(test)]
mod __new {
    use super::*;
    use crate::setup_fuelup_home;
    use rusty_fork::rusty_fork_test;
    use std::env::{remove_var, set_var};

    rusty_fork_test! {
        #[test]
        fn opt_out_is_true() {
            setup_fuelup_home();

            set_var("FUELUP_NO_TELEMETRY", "true");

            #[derive(Default)]
            struct OptOutHelpers {
                create_non_blocking_sink_called: bool,
                create_non_blocking_appender_called: bool,
            }

            impl NewHelpers for OptOutHelpers {
                fn create_non_blocking_sink(&mut self) -> (NonBlocking, WorkerGuard) {
                    self.create_non_blocking_sink_called = true;
                    tracing_appender::non_blocking(std::io::sink())
                }

                fn create_non_blocking_appender(
                    &mut self,
                    writer: impl Write + Send + 'static,
                ) -> (NonBlocking, WorkerGuard) {
                    self.create_non_blocking_appender_called = true;
                    tracing_appender::non_blocking(writer)
                }
            }

            let mut helpers = OptOutHelpers::default();
            let result = TelemetryLayer::__new_with_helpers(&mut helpers);

            assert!(result.is_ok());
            assert!(helpers.create_non_blocking_sink_called);
            assert!(!helpers.create_non_blocking_appender_called);
        }

        #[test]
        fn opt_out_is_empty() {
            setup_fuelup_home();

            // Even though it's empty, we only care if it's set
            set_var("FUELUP_NO_TELEMETRY", "");

            #[derive(Default)]
            struct OptOutHelpers {
                create_non_blocking_sink_called: bool,
                create_non_blocking_appender_called: bool,
            }

            impl NewHelpers for OptOutHelpers {
                fn create_non_blocking_sink(&mut self) -> (NonBlocking, WorkerGuard) {
                    self.create_non_blocking_sink_called = true;
                    tracing_appender::non_blocking(std::io::sink())
                }

                fn create_non_blocking_appender(
                    &mut self,
                    writer: impl Write + Send + 'static,
                ) -> (NonBlocking, WorkerGuard) {
                    self.create_non_blocking_appender_called = true;
                    tracing_appender::non_blocking(writer)
                }
            }

            let mut helpers = OptOutHelpers::default();
            let result = TelemetryLayer::__new_with_helpers(&mut helpers);

            assert!(result.is_ok());
            assert!(helpers.create_non_blocking_sink_called);
            assert!(!helpers.create_non_blocking_appender_called);
        }

        #[test]
        fn telemetry_pkg_name_is_not_set() {
            setup_fuelup_home();

            remove_var("TELEMETRY_PKG_NAME");
            set_var("TELEMETRY_PKG_VERSION", "1.0.0");

            let result = TelemetryLayer::__new();

            assert_eq!(result.err(), Some(TelemetryError::InvalidUsage));
        }

        #[test]
        fn telemetry_pkg_version_is_not_set() {
            setup_fuelup_home();

            remove_var("TELEMETRY_PKG_VERSION");
            set_var("TELEMETRY_PKG_NAME", "test_pkg_name");

            let result = TelemetryLayer::__new();

            assert_eq!(result.err(), Some(TelemetryError::InvalidUsage));
        }

        #[test]
        fn ok() {
            setup_fuelup_home();

            set_var("TELEMETRY_PKG_NAME", "test_pkg_name");
            set_var("TELEMETRY_PKG_VERSION", "1.0.0");

            #[derive(Default)]
            struct OkHelpers {
                create_non_blocking_sink_called: bool,
                create_non_blocking_appender_called: bool,
            }

            impl NewHelpers for OkHelpers {
                fn create_non_blocking_sink(&mut self) -> (NonBlocking, WorkerGuard) {
                    self.create_non_blocking_sink_called = true;
                    tracing_appender::non_blocking(std::io::sink())
                }

                fn create_non_blocking_appender(
                    &mut self,
                    writer: impl Write + Send + 'static,
                ) -> (NonBlocking, WorkerGuard) {
                    self.create_non_blocking_appender_called = true;
                    tracing_appender::non_blocking(writer)
                }
            }

            let mut helpers = OkHelpers::default();
            let result = TelemetryLayer::__new_with_helpers(&mut helpers);

            assert!(result.is_ok());
            assert!(!helpers.create_non_blocking_sink_called);
            assert!(helpers.create_non_blocking_appender_called);
        }
    }
}
