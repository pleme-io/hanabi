//! Error types for hanabi-lint
//!
//! Uses thiserror to demonstrate the patterns we enforce in Hanabi itself.

use std::path::PathBuf;
use thiserror::Error;

/// All errors that can occur during perfection checking
#[derive(Debug, Error)]
pub enum LintError {
    #[error("Failed to read file {path}: {source}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse Rust file {path}: {message}")]
    ParseError { path: PathBuf, message: String },

    #[error("Failed to run cargo command '{command}': {message}")]
    CargoError { command: String, message: String },

    #[error("Failed to parse cargo metadata: {0}")]
    MetadataError(#[from] cargo_metadata::Error),

    #[error("Failed to parse backlog file: {message}")]
    BacklogParseError { message: String },

    #[error("Workspace root not found")]
    WorkspaceNotFound,

    #[error("Hanabi package not found in workspace")]
    HanabiNotFound,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),
}

pub type Result<T> = std::result::Result<T, LintError>;
