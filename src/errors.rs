use base64::DecodeError;
use std::{io, path::PathBuf, string::FromUtf8Error};
use thiserror::Error;

#[derive(Error, Clone, PartialEq)]
pub enum TelemetryError {
    //
    // External errors
    //
    #[error("Base64 error: {0}")]
    Base64(#[from] DecodeError),
    #[error("IO error: {0}")]
    IO(String),
    #[error("Nix error: {0}")]
    Nix(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Reqwest error: {0}")]
    Reqwest(String),
    #[error("Request clone failed")]
    ReqwestCloneFailed,
    #[error("UTF-8 error: {0}")]
    Utf8(String),

    //
    // General errors
    //
    #[error("Invalid config: {0}")]
    InvalidConfig(String),
    #[error("Invalid client")]
    InvalidClient,
    #[error("Invalid 'RUST_LOG' filter: {0}")]
    InvalidEnvFilter(String),
    #[error("Home directory is invalid: {0}")]
    InvalidHomeDir(String),
    #[error("Log directory is invalid: {0}")]
    InvalidLogDir(String),
    #[error("Logfile is invalid: {0}/{1}")]
    InvalidLogFile(String, PathBuf),
    #[error("Invalid request")]
    InvalidRequest,
    #[error("Temporary directory is invalid: {0}")]
    InvalidTmpDir(String),
    #[error("Do not use 'TelemetryLayer::new()' directly, instead use the constructor macros")]
    InvalidUsage,
    #[error("Home directory is unreachable")]
    UnreachableHomeDir,
    #[error("Crate name is unreadable")]
    UnreadableCrateName,

    //
    // FileWatcher errors
    //,
    #[error("Tracing event is invalid: {0}")]
    InvalidTracingEvent(String),
    #[error("Tracing regex is invalid: {0}")]
    InvalidTracingRegex(#[from] regex::Error),
    #[error("Tracing payload is invalid: {0}")]
    InvalidTracingPayload(String),

    // Mock error for testing
    #[error("Mock error")]
    Mock,
}

/// Convenience impl that dereferences the error
/// so that we can use the error with `?`
impl From<&TelemetryError> for TelemetryError {
    fn from(err: &TelemetryError) -> Self {
        err.clone()
    }
}

impl From<TelemetryError> for String {
    fn from(err: TelemetryError) -> Self {
        err.to_string()
    }
}

impl std::fmt::Debug for TelemetryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

//
// The following impls are convenience impls that convert errors into our
// `TelemetryError` variant. We do this because we want to use the `?` operator
// and can't use `?` directly because the source errors don't implement
// `Clone`.
//

macro_rules! impl_error_from {
    ($from:ty, $variant:ident) => {
        impl From<$from> for TelemetryError {
            fn from(err: $from) -> Self {
                Self::$variant(err.to_string())
            }
        }
    };
}

impl_error_from!(io::Error, IO);
impl_error_from!(nix::Error, Nix);
impl_error_from!(std::num::ParseIntError, Parse);
impl_error_from!(reqwest::Error, Reqwest);
impl_error_from!(FromUtf8Error, Utf8);

#[derive(Debug, PartialEq)]
pub enum WatcherError {
    Recoverable(TelemetryError),
    Fatal(TelemetryError),
}

impl From<TelemetryError> for WatcherError {
    fn from(err: TelemetryError) -> Self {
        // Default to fatal, then be explicit about recoverable errors
        WatcherError::Fatal(err)
    }
}

pub fn into_fatal<E: Into<TelemetryError>>(err: E) -> WatcherError {
    WatcherError::Fatal(err.into())
}

pub fn into_recoverable<E: Into<TelemetryError>>(err: E) -> WatcherError {
    WatcherError::Recoverable(err.into())
}
