use quote::quote;

extern crate proc_macro;

const LOG_FILTER: &str = "RUST_LOG";

// Sets environment variables from the cargo target's perspective
//
// These values need to come from the cargo target which can only be found
// during macro expansion. Calling `env!('CARGO_PKG_NAME')` within
// `telemetry_layer.rs` will be incorrect as the macro will have already
// expanded leading to the constant value "fuel-telemetry" for all targets
fn set_env_vars() -> proc_macro2::TokenStream {
    quote! {
        if std::env::var("TELEMETRY_PKG_NAME").is_err() {
            std::env::set_var("TELEMETRY_PKG_NAME", fuel_telemetry::get_process_name());
        }

        if std::env::var("TELEMETRY_PKG_VERSION").is_err() {
            std::env::set_var("TELEMETRY_PKG_VERSION", env!("CARGO_PKG_VERSION"));
        }
    }
}

// Starts the `FileWatcher` and `SystemInfoWatcher` daemon
//
// Warning: We need to create the `FileWatcher` and `SystemInfoWatcher`
// before the `TelemetryLayer` as there is a race condition in the
// thread runtime of `tracing` and the tokio runtime of `Reqwest`.
// Swapping order of the two could lead to possible deadlocks.
//
// If the watchers fail to start, we silently ignore the errors as
// telemetry should not impede the program from running.
fn start_watchers() -> proc_macro2::TokenStream {
    quote! {
        // In the following, we need to log all errors but as there is no
        // `tracing` `Subscriber` running yet, we need to fall back to appending
        // plain text to the log file instead
        //
        // Another thing to note is that as this is the original process, we
        // only exit on `Fatal` errors, meaning that we have since forked and
        // have become a child process so can safely fatally exit

        // Start the `ProcessWatcher`
        match fuel_telemetry::process_watcher::ProcessWatcher::new() {
            Ok(mut process_watcher) => {
                if let Err(err) = process_watcher.start() {
                    let _ = fuel_telemetry::process_watcher::ProcessWatcher::log_error(&format!("Failed to start `ProcessWatcher`: {:?}", err));

                    if err.is_fatal() {
                        std::process::exit(1);
                    }
                }
            }
            Err(err) => {
                let _ = fuel_telemetry::process_watcher::ProcessWatcher::log_error(&format!("Failed to create `ProcessWatcher`: {:?}", err));
                // Don't exit as this is the original process and we need to continue
            }
        }

        // Start the `FileWatcher`
        let mut file_watcher = fuel_telemetry::file_watcher::FileWatcher::new();
        if let Err(err) = file_watcher.start() {
            let _ = fuel_telemetry::file_watcher::FileWatcher::log_error(&format!("Failed to start `FileWatcher`: {:?}", err));

            if err.is_fatal() {
                std::process::exit(1);
            }
        }

        // Start the `SystemInfoWatcher`
        let mut systeminfo_watcher = fuel_telemetry::systeminfo_watcher::SystemInfoWatcher::new();
        if let Err(err) = systeminfo_watcher.start() {
            let _ = fuel_telemetry::systeminfo_watcher::SystemInfoWatcher::log_error(&format!("Failed to start `SystemInfoWatcher`: {:?}", err));

            if err.is_fatal() {
                std::process::exit(1);
            }
        }
    }
}

/// Create a new `TelemetryLayer`.
///
/// This `tracing` `Layer` is to be used along with the `tracing` crate, and
/// composes with other `Layer`s to create a `Subscriber`.
///
/// Returns a `TelemetryLayer` and a drop guard. Here, the drop guard will flush
/// any remaining telemetry to the disk.
///
/// Warning: this function does not create a `FileWatcher` and
/// `SystemInfoWatcher`, and so although telemetry files will be written to
/// disk, they will not be sent to InfluxDB. If in doubt, prefer using
/// `new_with_watchers!()` or `new_with_watchers_and_init!()` over `new!()`.
///
/// ```text
/// use fuel_telemetry::TelemetryLayer;
///
/// let (telemetry_layer, _guard) = fuel_telemetry::new!()?;
/// tracing_subscriber::registry().with(telemetry_layer).init();
///
/// info_telemetry!("This event will be sent to InfluxBD");
/// ```
#[proc_macro]
pub fn new(_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let env_vars = set_env_vars();

    quote! {
        {
            #env_vars

            fuel_telemetry::TelemetryLayer::__new().and_then(|(layer, guard)| {
                use fuel_telemetry::__reexport_EnvFilter;
                use fuel_telemetry::__reexport_Layer;

                std::env::var_os(#LOG_FILTER)
                    .map_or_else(
                        || Ok(__reexport_EnvFilter::new("info")),
                        |_| __reexport_EnvFilter::try_from_default_env()
                            .map_err(|e| fuel_telemetry::TelemetryError::InvalidEnvFilter(e.to_string()))
                    )
                    .map(|filter| (layer.inner_layer.with_filter(filter), guard))
            })
        }
    }
    .into()
}

/// A convenience macro to do `new!()` followed by creating and starting a
/// `FileWatcher` and `SystemInfoWatcher` within a single step.
///
/// Returns a `TelemetryLayer` and a drop guard. Here, the drop guard will flush
/// any remaining telemetry to the disk.
///
/// Use this macro if you are using `fuel-telemetry` along with other `tracing`
/// `Layer`s within your application, or you have your own `tracing`
/// `Subscriber`.
///
/// Otherwise, if you are using `fuel-telemetry` as your only `tracing`
/// `Subscriber`, you should instead use `new_with_watchers_and_init!()`.
///
/// ```text
/// use fuel_telemetry::prelude::*;
///
/// let (telemetry_layer, _guard) = fuel_telemetry::new_with_watchers!()?;
/// tracing_subscriber::registry().with(telemetry_layer).init();
///
/// info_telemetry!("This event will be sent to InfluxBD");
/// ```
#[proc_macro]
pub fn new_with_watchers(_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let start_watchers = start_watchers();

    quote! {
        {
            #start_watchers
            fuel_telemetry::new!()
        }
    }
    .into()
}

/// A convenience macro to do `new_with_watchers!()` followed by setting the
/// `TracingLayer` as the global default `Subscriber`.
///
/// Returns a `TelemetryLayer` and a drop guard. Here, the drop guard will flush
/// any remaining telemetry to the disk.
///
/// Use this macro if you are using `fuel-telemetry` as your only `tracing`
/// `Subscriber`.
///
/// Otherwise, if you are using `fuel-telemetry` along with other `tracing`
/// `Layer`s within your application, you should instead use `new_with_watchers!()`.
///
/// ```text
/// use fuel_telemetry::prelude::*;
///
/// let (telemetry_layer, _guard) = fuel_telemetry::new_with_watchers_and_init!()?;
///
/// info_telemetry!("This event will be sent to InfluxBD");
/// ```
#[proc_macro]
pub fn new_with_watchers_and_init(_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let args: Vec<String> = std::env::args().collect();
    let mut crate_name = String::new();
    let mut crate_type = String::new();

    // During macro expansion, we extract the crate name and type from the
    // compiler's command line arguments, as this is the only time and place
    // this information is available.
    for window in args.windows(2) {
        match window[0].as_str() {
            "--crate-name" => crate_name = window[1].clone(),
            "--crate-type" => crate_type = window[1].clone(),
            _ => {}
        }
    }

    // If the crate is a library, and it is not the `fuel_telemetry` crate,
    // then generate a compiler error so we cannot continue!
    if crate_type == "lib" && crate_name != "fuel_telemetry" {
        return quote! {
            {
                compile_error!("new_with_watchers_and_init!() cannot be called within a library")
            }
        }
        .into();
    }

    quote! {
        {
            fuel_telemetry::new_with_watchers!().map(|(layer, guard)| {
                use fuel_telemetry::__reexport_SubscriberInitExt;
                use fuel_telemetry::__reexport_tracing_subscriber;
                use fuel_telemetry::__reexport_tracing_subscriber_SubscriberExt;

                __reexport_tracing_subscriber::registry()
                    .with(layer)
                    .init();

                guard
            })
        }
    }
    .into()
}
