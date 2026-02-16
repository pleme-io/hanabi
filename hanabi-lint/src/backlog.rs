//! Backlog parser for IMPROVEMENTS.md
//!
//! Parses the structured backlog file to extract open issues,
//! track progress, and update status.

use crate::error::{LintError, Result};
use regex::Regex;
use std::path::Path;

/// A single backlog item
#[derive(Debug, Clone, serde::Serialize)]
pub struct BacklogItem {
    pub file_location: Option<String>,
    pub description: String,
    pub category: String,
    pub priority: Priority,
    pub status: ItemStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

impl Priority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    Open,
    InProgress,
    Completed,
}

/// Summary of backlog status
#[derive(Debug, Default, serde::Serialize)]
pub struct BacklogSummary {
    pub total_open: usize,
    pub total_in_progress: usize,
    pub total_completed: usize,
    pub by_category: std::collections::HashMap<String, CategoryCount>,
    pub by_priority: std::collections::HashMap<String, usize>,
    pub items: Vec<BacklogItem>,
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct CategoryCount {
    pub open: usize,
    pub in_progress: usize,
    pub completed: usize,
}

impl BacklogSummary {
    pub fn is_empty(&self) -> bool {
        self.total_open == 0 && self.total_in_progress == 0
    }

    pub fn has_open_items(&self) -> bool {
        self.total_open > 0
    }
}

/// Parse the backlog file
pub fn parse_backlog(path: &Path) -> Result<BacklogSummary> {
    let content = std::fs::read_to_string(path).map_err(|e| LintError::FileRead {
        path: path.to_path_buf(),
        source: e,
    })?;

    parse_backlog_content(&content)
}

fn parse_backlog_content(content: &str) -> Result<BacklogSummary> {
    let mut summary = BacklogSummary::default();

    // Regex patterns for parsing
    let open_item_re = Regex::new(r"^- \[ \] `([^`]+)` - (.+)$")?;
    let open_item_no_file_re = Regex::new(r"^- \[ \] (.+)$")?;
    let completed_item_re = Regex::new(r"^- \[x\] `([^`]+)` - (.+)$")?;
    let category_re = Regex::new(r"^### (.+)$")?;
    let priority_re = Regex::new(r"^#### (Critical|High|Medium|Low)")?;

    let mut current_category = String::new();
    let mut current_priority = Priority::Medium;
    let mut in_open_section = false;
    let mut in_completed_section = false;
    let mut in_progress_section = false;

    for line in content.lines() {
        let line = line.trim();

        // Track sections
        if line.starts_with("## Open Issues") {
            in_open_section = true;
            in_completed_section = false;
            in_progress_section = false;
            continue;
        }
        if line.starts_with("## In Progress") {
            in_open_section = false;
            in_progress_section = true;
            in_completed_section = false;
            continue;
        }
        if line.starts_with("## Completed") {
            in_open_section = false;
            in_progress_section = false;
            in_completed_section = true;
            continue;
        }
        if line.starts_with("## ") && !line.contains("Current Perfection") {
            // Other section, reset
            in_open_section = false;
            in_progress_section = false;
            in_completed_section = false;
            continue;
        }

        // Track category (### headings)
        if let Some(caps) = category_re.captures(line) {
            current_category = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
            continue;
        }

        // Track priority (#### headings)
        if let Some(caps) = priority_re.captures(line) {
            let priority_str = caps.get(1).map(|m| m.as_str()).unwrap_or("Medium");
            current_priority = match priority_str {
                "Critical" => Priority::Critical,
                "High" => Priority::High,
                "Medium" => Priority::Medium,
                "Low" => Priority::Low,
                _ => Priority::Medium,
            };
            continue;
        }

        // Parse open items
        if in_open_section {
            if let Some(caps) = open_item_re.captures(line) {
                let file_location = caps.get(1).map(|m| m.as_str().to_string());
                let description = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();

                let item = BacklogItem {
                    file_location,
                    description,
                    category: current_category.clone(),
                    priority: current_priority,
                    status: ItemStatus::Open,
                };

                summary.total_open += 1;
                update_category_count(&mut summary.by_category, &current_category, ItemStatus::Open);
                *summary.by_priority.entry(current_priority.as_str().to_string()).or_default() += 1;
                summary.items.push(item);
            } else if let Some(caps) = open_item_no_file_re.captures(line) {
                // Item without file location
                if !line.starts_with("- **") {
                    // Skip impact/fix lines
                    let description = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();

                    let item = BacklogItem {
                        file_location: None,
                        description,
                        category: current_category.clone(),
                        priority: current_priority,
                        status: ItemStatus::Open,
                    };

                    summary.total_open += 1;
                    update_category_count(&mut summary.by_category, &current_category, ItemStatus::Open);
                    *summary.by_priority.entry(current_priority.as_str().to_string()).or_default() += 1;
                    summary.items.push(item);
                }
            }
        }

        // Parse in-progress items
        if in_progress_section {
            if let Some(caps) = open_item_re.captures(line) {
                let file_location = caps.get(1).map(|m| m.as_str().to_string());
                let description = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();

                let item = BacklogItem {
                    file_location,
                    description,
                    category: current_category.clone(),
                    priority: current_priority,
                    status: ItemStatus::InProgress,
                };

                summary.total_in_progress += 1;
                update_category_count(&mut summary.by_category, &current_category, ItemStatus::InProgress);
                summary.items.push(item);
            }
        }

        // Parse completed items
        if in_completed_section {
            if let Some(caps) = completed_item_re.captures(line) {
                let file_location = caps.get(1).map(|m| m.as_str().to_string());
                let description = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();

                let item = BacklogItem {
                    file_location,
                    description,
                    category: current_category.clone(),
                    priority: current_priority,
                    status: ItemStatus::Completed,
                };

                summary.total_completed += 1;
                update_category_count(&mut summary.by_category, &current_category, ItemStatus::Completed);
                summary.items.push(item);
            }
        }
    }

    Ok(summary)
}

fn update_category_count(
    map: &mut std::collections::HashMap<String, CategoryCount>,
    category: &str,
    status: ItemStatus,
) {
    let entry = map.entry(category.to_string()).or_default();
    match status {
        ItemStatus::Open => entry.open += 1,
        ItemStatus::InProgress => entry.in_progress += 1,
        ItemStatus::Completed => entry.completed += 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_open_items() {
        let content = r#"
## Open Issues

### Zero-Unwrap Violations

#### Critical (Request Path)

- [ ] `bff.rs:1248` - WebSocket `into_client_request().unwrap()`
  - **Impact**: Panic on malformed WebSocket upgrade
  - **Fix**: Return `HanabiError::WebSocket` with context

- [ ] `federation/batch.rs:284` - `state_guard.take().unwrap()`
  - **Impact**: Panic if batch state consumed twice

## Completed

- [x] `file.rs:123` - Fixed something (2025-01-15)
"#;

        let summary = parse_backlog_content(content).unwrap();

        assert_eq!(summary.total_open, 2);
        assert_eq!(summary.total_completed, 1);
        assert_eq!(summary.items.len(), 3);
    }

    #[test]
    fn test_parse_priorities() {
        let content = r#"
## Open Issues

### Test

#### Critical (Request Path)

- [ ] `file1.rs:1` - Critical item

#### High (Startup/Config)

- [ ] `file2.rs:2` - High item

#### Low

- [ ] `file3.rs:3` - Low item
"#;

        let summary = parse_backlog_content(content).unwrap();

        assert_eq!(summary.total_open, 3);
        assert_eq!(*summary.by_priority.get("critical").unwrap_or(&0), 1);
        assert_eq!(*summary.by_priority.get("high").unwrap_or(&0), 1);
        assert_eq!(*summary.by_priority.get("low").unwrap_or(&0), 1);
    }
}
