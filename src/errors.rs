use thiserror::Error;
use std::{io, path::PathBuf, string::FromUtf8Error};

#[derive(Error, Debug, Clone)]
pub enum TelemetryError {
    //
    // External errors
    //

    #[error("IO error: {0}")]
    IO(String),
    #[error("Nix error: {0}")]
    Nix(String),
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
    #[error("Home directory is invalid: {0}")]
    InvalidHomeDir(String),
    #[error("Log directory is invalid: {0}")]
    InvalidLogDir(String),
    #[error("Logfile is invalid: {0}/{1}")]
    InvalidLogFile(String, PathBuf),
    #[error("Temporary directory is invalid: {0}")]
    InvalidTmpDir(String),
    #[error("Home directory is unreachable")]
    UnreachableHomeDir,

    //
    // FileWatcher errors
    //

    #[error("Invalid rollfile interval: {0}")]
    InvalidRollfileInterval(#[from] std::num::ParseIntError),
    #[error("Tracing event is invalid: {0}")]
    InvalidTracingEvent(String),
    #[error("Tracing regex is invalid: {0}")]
    InvalidTracingRegex(#[from] regex::Error),
    #[error("Tracing payload is invalid: {0}")]
    InvalidTracingPayload(String),

}

impl From<&TelemetryError> for TelemetryError {
    fn from(err: &TelemetryError) -> Self {
        err.clone()
    }
}

impl From<FromUtf8Error> for TelemetryError {
    fn from(err: FromUtf8Error) -> Self {
        Self::Utf8(err.to_string())
    }
}

impl From<io::Error> for TelemetryError {
    fn from(err: io::Error) -> Self {
        Self::IO(err.to_string())
    }
}

impl From<nix::Error> for TelemetryError {
    fn from(err: nix::Error) -> Self {
        Self::Nix(err.to_string())
    }
}

impl From<reqwest::Error> for TelemetryError {
    fn from(err: reqwest::Error) -> Self {
        Self::Reqwest(err.to_string())
    }
}