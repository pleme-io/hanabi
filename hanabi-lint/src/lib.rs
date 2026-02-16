//! hanabi-lint - Perfection checker for Hanabi BFF server
//!
//! This tool provides AST-based code quality analysis for the Hanabi BFF server,
//! implementing the perfection criteria defined in the hanabi-development skill.
//!
//! # Features
//!
//! - **AST-based unwrap detection**: Uses `syn` to accurately detect `unwrap()`,
//!   `expect()`, `panic!()` etc., properly distinguishing test from production code
//! - **Complexity metrics**: Cyclomatic and cognitive complexity analysis
//! - **Cargo integration**: Runs clippy, tests, and format checks
//! - **Backlog tracking**: Parses the improvement backlog for status reporting
//! - **Modularity analysis**: Layering violations, circular deps, API surface
//! - **Test coverage**: 100% coverage enforcement via llvm-cov
//! - **Configuration analysis**: Magic numbers, runtime env::var, mutable config
//!
//! # Usage
//!
//! ```bash
//! # Run full perfection check
//! cargo run --package hanabi-lint
//!
//! # JSON output for CI
//! cargo run --package hanabi-lint -- --format json
//!
//! # Skip slow checks
//! cargo run --package hanabi-lint -- --skip-tests
//!
//! # Include coverage analysis
//! cargo run --package hanabi-lint -- --coverage
//! ```

pub mod backlog;
pub mod cargo_checks;
pub mod complexity;
pub mod config_detector;
pub mod coverage;
pub mod error;
pub mod hygiene_detector;
pub mod modularity;
pub mod refactoring_detector;
pub mod report;
pub mod unwrap_detector;

pub use error::{LintError, Result};
pub use report::{PerfectionReport, PerfectionState};
