use quote::quote;

extern crate proc_macro;

#[proc_macro]
pub fn new(_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    quote! {
        {
            if std::env::var("TELEMETRY_PKG_NAME").is_err() {
                std::env::set_var("TELEMETRY_PKG_NAME", env!("CARGO_PKG_NAME"));
            }

            if std::env::var("TELEMETRY_PKG_VERSION").is_err() {
                std::env::set_var("TELEMETRY_PKG_VERSION", env!("CARGO_PKG_VERSION"));
            }

            fuel_telemetry::TelemetryLayer::new()
        }
    }
    .into()
}

#[proc_macro]
pub fn new_with_watchers(_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    quote! {
        {
            if std::env::var("TELEMETRY_PKG_NAME").is_err() {
                std::env::set_var("TELEMETRY_PKG_NAME", env!("CARGO_PKG_NAME"));
            }

            if std::env::var("TELEMETRY_PKG_VERSION").is_err() {
                std::env::set_var("TELEMETRY_PKG_VERSION", env!("CARGO_PKG_VERSION"));
            }

            let _ = fuel_telemetry::file_watcher::FileWatcher::new()
                .and_then(|mut f| f.start())
                .map_err(|_| std::process::exit(0));

            let _ = fuel_telemetry::systeminfo_watcher::SystemInfoWatcher::new()
                .and_then(|mut s| s.start())
                .map_err(|_| std::process::exit(0));

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

    for window in args.windows(2) {
        match window[0].as_str() {
            "--crate-name" => crate_name = window[1].clone(),
            "--crate-type" => crate_type = window[1].clone(),
            _ => {}
        }
    }

    if crate_type == "lib" && crate_name != "fuel_telemetry" {
        return quote! {
            {
                compile_error!("new_with_watchers_and_init!() cannot be called within a library");
            }
        }
        .into();
    }

    quote! {
        {
            if std::env::var("TELEMETRY_PKG_NAME").is_err() {
                std::env::set_var("TELEMETRY_PKG_NAME", env!("CARGO_PKG_NAME"));
            }

            if std::env::var("TELEMETRY_PKG_VERSION").is_err() {
                std::env::set_var("TELEMETRY_PKG_VERSION", env!("CARGO_PKG_VERSION"));
            }

            let _ = fuel_telemetry::file_watcher::FileWatcher::new()
                .and_then(|mut f| f.start())
                .map_err(|_| std::process::exit(0));

            let _ = fuel_telemetry::systeminfo_watcher::SystemInfoWatcher::new()
                .and_then(|mut s| s.start())
                .map_err(|_| std::process::exit(0));

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
