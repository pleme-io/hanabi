use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use blue_lang_host::{Entry, Loader, Program, Standard, Value};
use serde::Deserialize;
use tracing::{error, info, warn};

use crate::config::{AppConfig, BlueSource};
use crate::federation::apq::ApqCache;

pub const PACKAGE: &str = include_str!("../blue/hanabi/hanabi.b");

pub const VENDORED: &[(&str, &str, &str)] = &[
    ("hanabi", "hanabi/hanabi.b", PACKAGE),
    (
        "kousei",
        "vendor/kousei/kousei.b",
        include_str!("../blue/vendor/kousei/kousei.b"),
    ),
    (
        "kyohi",
        "vendor/kyohi/kyohi.b",
        include_str!("../blue/vendor/kyohi/kyohi.b"),
    ),
    (
        "retsu",
        "vendor/retsu/retsu.b",
        include_str!("../blue/vendor/retsu/retsu.b"),
    ),
    (
        "kazu",
        "vendor/kazu/kazu.b",
        include_str!("../blue/vendor/kazu/kazu.b"),
    ),
];

pub struct HanabiLoader;

impl Loader for HanabiLoader {
    fn load(&self, name: &str) -> Result<Vec<(String, String)>, String> {
        if name != "hanabi" && Standard.has(name) {
            return Standard.load(name);
        }
        VENDORED
            .iter()
            .find(|(n, _, _)| *n == name)
            .map(|(_, label, text)| vec![((*label).to_owned(), (*text).to_owned())])
            .ok_or_else(|| {
                format!("cannot load bidama \"{name}\": hanabi carries hanabi, kousei, kyohi, retsu and kazu")
            })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlueError {
    #[error("{path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("blue: {0}")]
    Program(#[from] blue_lang_host::Error),
    #[error("the blue program returned a shape hanabi cannot read: {0}")]
    Shape(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Refusal {
    pub fault: String,
    pub why: String,
}

#[derive(Debug, Deserialize)]
struct SettledJson {
    config: serde_json::Value,
    off: Vec<String>,
    refusals: Vec<Refusal>,
}

#[derive(Debug, Deserialize)]
struct PersistedJson {
    operations: std::collections::BTreeMap<String, String>,
    refusals: Vec<Refusal>,
}

#[derive(Debug, Clone)]
pub struct SettledConfig {
    pub config: AppConfig,
    pub off: Vec<String>,
    pub refusals: Vec<Refusal>,
}

#[derive(Debug, Clone, Default)]
pub struct PersistedOperations {
    pub operations: HashMap<String, String>,
    pub refusals: Vec<Refusal>,
}

fn read(path: &Path) -> Result<String, BlueError> {
    std::fs::read_to_string(path).map_err(|source| BlueError::Read {
        path: path.display().to_string(),
        source,
    })
}

fn program(path: Option<&Path>, text: &str) -> Result<Program<()>, BlueError> {
    Ok(Program::load_with(
        Entry { path, text },
        &HanabiLoader,
        &mut (),
    )?)
}

pub fn settle_config(path: Option<&Path>, text: &str) -> Result<SettledConfig, BlueError> {
    let mut program = program(path, text)?;
    let declaration: Value = program.call("declaration", (), &mut ())?;
    let json: String = program.call("hanabi::settle_json", (declaration,), &mut ())?;
    let settled: SettledJson = serde_json::from_str(&json)?;
    Ok(SettledConfig {
        config: serde_json::from_value(settled.config)?,
        off: settled.off,
        refusals: settled.refusals,
    })
}

pub fn settle_config_file(path: &Path) -> Result<SettledConfig, BlueError> {
    let text = read(path)?;
    let settled = settle_config(Some(path), &text)?;
    for r in &settled.refusals {
        warn!(fault = %r.fault, "blue config entry refused: {}", r.why);
    }
    info!(
        source = %path.display(),
        refused = settled.refusals.len(),
        off = settled.off.len(),
        "configuration settled from blue"
    );
    Ok(settled)
}

pub fn persisted_operations(
    path: Option<&Path>,
    text: &str,
) -> Result<PersistedOperations, BlueError> {
    let mut program = program(path, text)?;
    let table: Value = program.call("operations", (), &mut ())?;
    let json: String = program.call("hanabi::persisted_json", (table,), &mut ())?;
    let raw: PersistedJson = serde_json::from_str(&json)?;
    let mut out = PersistedOperations {
        operations: HashMap::new(),
        refusals: raw.refusals,
    };
    for (hash, operation) in raw.operations {
        if ApqCache::compute_hash(&operation) == hash {
            out.operations.insert(hash, operation);
        } else {
            out.refusals.push(Refusal {
                fault: "invalid".to_owned(),
                why: format!("{hash}: the hash is not the sha256 of its operation"),
            });
        }
    }
    Ok(out)
}

pub fn operation_table(source: &BlueSource) -> Option<Arc<HashMap<String, String>>> {
    if !source.enabled {
        return None;
    }
    let loaded = source
        .path("persisted_ops")
        .map_err(|e| e.to_string())
        .and_then(|p| persisted_operations_file(Path::new(p)).map_err(|e| e.to_string()));
    match loaded {
        Ok(table) => Some(Arc::new(table.operations)),
        Err(e) => {
            error!("persisted-operation table not loaded, so every persisted hash is refused: {e}");
            Some(Arc::new(HashMap::new()))
        }
    }
}

pub fn persisted_operations_file(path: &Path) -> Result<PersistedOperations, BlueError> {
    let text = read(path)?;
    let table = persisted_operations(Some(path), &text)?;
    for r in &table.refusals {
        warn!(fault = %r.fault, "persisted operation refused: {}", r.why);
    }
    info!(
        source = %path.display(),
        operations = table.operations.len(),
        refused = table.refusals.len(),
        "persisted-operation table loaded from blue"
    );
    Ok(table)
}
