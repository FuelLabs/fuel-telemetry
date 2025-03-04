use quote::quote;

extern crate proc_macro;

// Sets environment variables from the cargo target's perspective
//
// These values need to come from the cargo target which can only be found
// during macro expansion. Calling `env!('CARGO_PKG_NAME')` within
// `telemetry_layer.rs` will be incorrect as the macro will have already
// expanded leading to the constant value "fuel-telemetry" for all targets
fn set_env_vars() -> proc_macro2::TokenStream {
    quote! {
        if std::env::var("TELEMETRY_PKG_NAME").is_err() {
            std::env::set_var("TELEMETRY_PKG_NAME", env!("CARGO_PKG_NAME"));
        }

        if std::env::var("TELEMETRY_PKG_VERSION").is_err() {
            std::env::set_var("TELEMETRY_PKG_VERSION", env!("CARGO_PKG_VERSION"));
        }
    }
}

// Starts the `FileWatcher` and `SystemInfoWatcher` daemon
fn start_watchers() -> proc_macro2::TokenStream {
    quote! {
        let _ = fuel_telemetry::file_watcher::FileWatcher::new()
            .and_then(|mut f| f.start())
            .map_err(|_| std::process::exit(0));

        let _ = fuel_telemetry::systeminfo_watcher::SystemInfoWatcher::new()
            .and_then(|mut s| s.start())
            .map_err(|_| std::process::exit(0));
    }
}

#[proc_macro]
pub fn new(_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let env_vars = set_env_vars();

    quote! {
        {
            #env_vars

            fuel_telemetry::TelemetryLayer::new()
        }
    }
    .into()
}

#[proc_macro]
pub fn new_with_watchers(_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let env_vars = set_env_vars();
    let start_watchers = start_watchers();

    quote! {
        {
            #env_vars
            #start_watchers

            fuel_telemetry::TelemetryLayer::new()
        }
    }
    .into()
}

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

    let env_vars = set_env_vars();
    let start_watchers = start_watchers();

    quote! {
        {
            #env_vars
            #start_watchers

            fuel_telemetry::TelemetryLayer::new().map(|(layer, guard)| {
                use fuel_telemetry::__reexport_tracing_subscriber;
                use fuel_telemetry::__reexport_tracing_subscriber_SubscriberExt;
                use fuel_telemetry::__reexport_tracing_subscriber_SubscriberInitExt;
                use fuel_telemetry::__reexport_WorkerGuard;

                __reexport_tracing_subscriber::registry()
                    .with(layer.__inner)
                    .init();

                guard
            })
        }
    }
    .into()
}
