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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_read_display() {
        let err = LintError::FileRead {
            path: PathBuf::from("/tmp/foo.rs"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("/tmp/foo.rs"));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_parse_error_display() {
        let err = LintError::ParseError {
            path: PathBuf::from("src/lib.rs"),
            message: "unexpected token".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("src/lib.rs"));
        assert!(msg.contains("unexpected token"));
    }

    #[test]
    fn test_cargo_error_display() {
        let err = LintError::CargoError {
            command: "clippy".to_string(),
            message: "exit code 1".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("clippy"));
        assert!(msg.contains("exit code 1"));
    }

    #[test]
    fn test_backlog_parse_error_display() {
        let err = LintError::BacklogParseError {
            message: "invalid format".to_string(),
        };
        assert!(format!("{}", err).contains("invalid format"));
    }

    #[test]
    fn test_workspace_not_found_display() {
        let err = LintError::WorkspaceNotFound;
        assert_eq!(format!("{}", err), "Workspace root not found");
    }

    #[test]
    fn test_hanabi_not_found_display() {
        let err = LintError::HanabiNotFound;
        assert_eq!(format!("{}", err), "Hanabi package not found in workspace");
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let lint_err: LintError = io_err.into();
        assert!(matches!(lint_err, LintError::Io(_)));
        assert!(format!("{}", lint_err).contains("denied"));
    }

    #[test]
    fn test_from_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let lint_err: LintError = json_err.into();
        assert!(matches!(lint_err, LintError::Json(_)));
    }

    #[test]
    fn test_from_regex_error() {
        let regex_err = regex::Regex::new("[invalid").unwrap_err();
        let lint_err: LintError = regex_err.into();
        assert!(matches!(lint_err, LintError::Regex(_)));
    }

    #[test]
    fn test_file_read_source_chain() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = LintError::FileRead {
            path: PathBuf::from("test.rs"),
            source: io_err,
        };
        use std::error::Error;
        let source = err.source().expect("should have source");
        assert!(source.to_string().contains("file missing"));
    }

    #[test]
    fn test_result_type_alias() {
        fn returns_ok() -> Result<i32> {
            Ok(42)
        }
        fn returns_err() -> Result<i32> {
            Err(LintError::WorkspaceNotFound)
        }
        assert!(returns_ok().is_ok());
        assert!(returns_err().is_err());
    }
}
