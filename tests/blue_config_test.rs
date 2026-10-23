use std::path::Path;

use hanabi::blue::{self, settle_config};
use hanabi::config::{AppConfig, CrossOriginOpenerPolicy};

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn same_config(yaml: &str, blue_file: &str) {
    let from_yaml = AppConfig::from_yaml_str(&read(yaml)).expect("yaml parses");
    let settled =
        settle_config(Some(Path::new(blue_file)), &read(blue_file)).expect("blue settles");
    assert_eq!(settled.refusals, vec![], "{blue_file} refused entries");
    assert_eq!(
        serde_json::to_value(&from_yaml).unwrap(),
        serde_json::to_value(&settled.config).unwrap(),
        "{yaml} and {blue_file} disagree"
    );
}

#[test]
fn example_yaml_and_blue_spell_the_same_config() {
    same_config("config/example.yaml", "config/example.b");
}

#[test]
fn spa_popup_auth_yaml_and_blue_spell_the_same_config() {
    same_config("config/spa-popup-auth.yaml", "config/spa-popup-auth.b");
}

#[test]
fn a_bad_entry_is_refused_alone_and_its_siblings_stand() {
    let path = "tests/fixtures/blue/scoped.b";
    let settled = settle_config(Some(Path::new(path)), &read(path)).expect("blue settles");
    let whys: Vec<&str> = settled.refusals.iter().map(|r| r.why.as_str()).collect();

    assert!(
        whys.iter()
            .any(|w| w.starts_with("server server: http_port:")),
        "{whys:?}"
    );
    assert!(
        whys.iter()
            .any(|w| w.starts_with("federation federation: hmac_secret is not a field")),
        "{whys:?}"
    );
    assert!(
        whys.iter()
            .any(|w| w.starts_with("widget widget: no such kind")),
        "{whys:?}"
    );
    assert!(
        whys.iter().any(|w| w.starts_with("metrics statsd:")),
        "{whys:?}"
    );
    assert_eq!(settled.refusals.len(), 4, "{whys:?}");

    let c = &settled.config;
    assert_eq!(c.environment, "staging");
    assert_eq!(
        c.security.headers.cross_origin_opener_policy,
        CrossOriginOpenerPolicy::SameOriginAllowPopups
    );
    assert_eq!(c.security.hsts.max_age, 31_536_000);
    assert!(!c.security.hsts.preload);
    assert_eq!(settled.off, vec!["compression".to_string()]);

    let defaults = AppConfig::from_yaml_str("{}").unwrap();
    assert_eq!(c.server.http_port, defaults.server.http_port);
    assert_eq!(c.server.static_dir, defaults.server.static_dir);
    assert_eq!(c.bff.federation.enabled, defaults.bff.federation.enabled);
    assert_eq!(c.compression.enable_gzip, defaults.compression.enable_gzip);
    assert_eq!(c.metrics.enabled, defaults.metrics.enabled);
}

#[test]
fn persisted_operations_refuse_a_hash_that_is_not_its_text() {
    let path = "tests/fixtures/blue/persisted.b";
    let table =
        blue::persisted_operations(Some(Path::new(path)), &read(path)).expect("table loads");
    assert_eq!(table.operations.len(), 1);
    assert_eq!(
        table
            .operations
            .get("49433ef41bfdad3ddc6ce4e41a1042218cc23faee2529d5c12a62274af9cc23a")
            .map(String::as_str),
        Some("query { users { id } }")
    );
    let whys: Vec<&str> = table.refusals.iter().map(|r| r.why.as_str()).collect();
    assert_eq!(whys.len(), 2, "{whys:?}");
    assert!(
        whys.contains(&"short is not a sha256 hex digest"),
        "{whys:?}"
    );
    assert!(
        whys.iter()
            .any(|w| w.starts_with("0000000000") && w.ends_with("not the sha256 of its operation")),
        "{whys:?}"
    );
}

#[test]
fn blue_config_enabled_selects_the_blue_source_and_off_keeps_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let source = std::fs::canonicalize("tests/fixtures/blue/load.b").unwrap();
    let on = dir.path().join("on.yaml");
    std::fs::write(
        &on,
        format!(
            "server:\n  static_dir: .\n  http_port: 9000\n  health_port: 9001\nblue:\n  config:\n    enabled: true\n    source: {}\n",
            source.display()
        ),
    )
    .unwrap();
    let off = dir.path().join("off.yaml");
    std::fs::write(
        &off,
        format!(
            "server:\n  static_dir: .\n  http_port: 9000\n  health_port: 9001\nblue:\n  config:\n    enabled: false\n    source: {}\n",
            source.display()
        ),
    )
    .unwrap();

    std::env::set_var("CONFIG_PATH", &on);
    let from_blue = AppConfig::load().expect("blue config loads");
    std::env::set_var("CONFIG_PATH", &off);
    let from_yaml = AppConfig::load().expect("yaml config loads");
    std::env::remove_var("CONFIG_PATH");

    assert_eq!(from_blue.server.http_port, 8000);
    assert_eq!(from_blue.environment, "production");
    assert!(from_blue.blue.config.enabled);
    assert_eq!(from_yaml.server.http_port, 9000);
    assert_eq!(from_yaml.environment, "development");
}
