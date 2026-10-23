use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct EmbeddedBlueConfig {
    pub config: BlueSource,
    pub persisted_ops: BlueSource,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct BlueSource {
    pub enabled: bool,
    pub source: String,
}

impl BlueSource {
    pub fn path(&self, setting: &str) -> Result<&str, String> {
        if self.source.is_empty() {
            Err(format!(
                "blue.{setting}.enabled is set but blue.{setting}.source names no file"
            ))
        } else {
            Ok(&self.source)
        }
    }
}
