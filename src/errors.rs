use std::io;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, TelemetryError>;

#[derive(Error, Debug)]
pub enum TelemetryError {
    #[error("IO error: {0}")]
    IO(#[from] io::Error),

    #[error("Home directory is invalid: {0}")]
    HomeDirInvalid(String),
    #[error("Home directory is unreachable")]
    HomeDirUnreachable,
    #[error("Temporary directory is invalid: {0}")]
    TmpDirInvalid(String),
}
