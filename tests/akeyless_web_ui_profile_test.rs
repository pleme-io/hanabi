//! The scoped akeyless web-ui profile is a security artifact, so it is tested
//! like one.
//!
//! config/akeyless-web-ui.yaml replaces an nginx.conf whose header set was read
//! off a running container. These assertions pin the properties that must not
//! drift when the server underneath changes, and in particular the COOP value:
//! hanabi's default severs window.opener, which breaks popup sign-in, so the
//! profile has to override it and this test is what keeps that override honest.

use hanabi::config::{
    AppConfig, CrossOriginEmbedderPolicy, CrossOriginOpenerPolicy, CrossOriginResourcePolicy,
};

fn profile() -> AppConfig {
    let raw = std::fs::read_to_string("config/akeyless-web-ui.yaml")
        .expect("the scoped profile must exist at config/akeyless-web-ui.yaml");
    serde_yaml::from_str(&raw).expect("the scoped profile must parse into AppConfig")
}

#[test]
fn profile_parses() {
    let _ = profile();
}

#[test]
fn popup_sign_in_is_not_broken_by_coop() {
    let c = profile();
    assert_eq!(
        c.security.headers.cross_origin_opener_policy,
        CrossOriginOpenerPolicy::SameOriginAllowPopups,
        "COOP must allow popups or the login popup cannot reach its opener"
    );
    assert!(
        !c.security
            .headers
            .cross_origin_opener_policy
            .breaks_popup_auth(),
        "the chosen COOP must not be one that severs window.opener"
    );
}

#[test]
fn profile_overrides_the_defaults_it_needs_to() {
    // If these ever equal the defaults, the override was silently lost.
    let c = profile();
    let d = hanabi::config::SecurityConfig::default();
    assert_ne!(
        c.security.headers.cross_origin_opener_policy,
        d.headers.cross_origin_opener_policy,
        "the profile exists partly to change COOP; equal to default means lost"
    );
    assert_eq!(
        c.security.headers.cross_origin_resource_policy,
        CrossOriginResourcePolicy::SameOrigin,
        "CORP should be tightened from the cross-origin default"
    );
    assert_eq!(
        c.security.headers.cross_origin_embedder_policy,
        CrossOriginEmbedderPolicy::Credentialless
    );
}

#[test]
fn cleartext_requests_are_redirected() {
    let c = profile();
    assert!(
        c.security.transport.should_redirect_forwarded_http(),
        "the container does not terminate TLS, so a forwarded http request must 301"
    );
}

#[test]
fn hsts_is_preload_eligible() {
    let c = profile();
    assert_eq!(c.security.hsts.max_age, 31_536_000);
    assert!(c.security.hsts.include_subdomains);
    assert!(c.security.hsts.preload);
}

#[test]
fn every_unused_subsystem_is_off() {
    // Least functionality: this profile serves static files. An enabled BFF
    // proxy or webhook surface would be reachable attack surface with no use.
    let c = profile();
    assert!(!c.features.enable_bff, "the BFF proxy must be off");
    assert!(!c.features.enable_metrics);
    assert!(!c.features.enable_detailed_health_checks);
    assert_eq!(c.features.enable_bug_reports, Some(false));
}

#[test]
fn cors_is_a_closed_allowlist_without_credentials() {
    let c = profile();
    assert!(
        !c.security.cors.allowed_origins.is_empty(),
        "an empty allowlist would be indistinguishable from unset"
    );
    for origin in &c.security.cors.allowed_origins {
        assert!(
            origin.starts_with("https://"),
            "cleartext origin in the CORS allowlist: {origin}"
        );
        assert!(
            !origin.contains('*'),
            "wildcard origin in the CORS allowlist: {origin}"
        );
    }
    assert!(
        !c.security.cors.allow_credentials,
        "static assets never need credentialed cross-origin reads"
    );
}

#[test]
fn csp_image_sources_are_not_a_wildcard() {
    // The hanabi default is 'self' data: https: blob:, where `https:` allows any
    // origin. The profile narrows it.
    let c = profile();
    assert!(
        !c.security.csp.img_sources.iter().any(|s| s == "https:"),
        "img-src must not fall back to the https: wildcard"
    );
}

#[test]
fn csp_connect_src_carries_the_real_backend_origins() {
    let c = profile();
    for required in [
        "*.akeyless.io",
        "https://sfs.akeyless-security.com",
        "https://changelog.akeyless.io",
    ] {
        assert!(
            c.security
                .csp
                .additional_connect_src
                .iter()
                .any(|s| s == required),
            "connect-src is missing {required}, which the SPA actually calls"
        );
    }
}

#[test]
fn static_dir_is_the_path_the_chart_mounts_into() {
    // The saas chart mounts env-config.js as a subPath at
    // /usr/share/nginx/html/env-config.js. If the server reads from anywhere
    // else the mount lands in a directory nothing serves, and the tenant boots
    // with no runtime config. There is no nginx in this image; the path is
    // still the contract.
    let c = profile();
    assert_eq!(
        c.server.static_dir, "/usr/share/nginx/html",
        "static_dir must match the chart's mountPath parent"
    );
}

#[test]
fn http_port_is_non_root_bindable() {
    // Whatever the chart currently hardcodes, the server runs as a non-root uid
    // and cannot bind below 1024 without NET_BIND_SERVICE.
    let c = profile();
    assert!(
        c.server.http_port >= 1024,
        "http_port {} is privileged; a non-root server cannot bind it",
        c.server.http_port
    );
}

#[test]
fn the_profile_needs_no_server_specific_env() {
    // The deploying chart was written for nginx and knows nothing about hanabi.
    // Everything the server needs must therefore come from this file, not from
    // env the chart would have to learn to set. CONFIG_PATH is the only env var
    // involved and it already defaults to where the image puts this file.
    let c = profile();
    assert!(!c.server.static_dir.is_empty());
    assert!(c.server.http_port > 0);
}

/// Loads the profile through hanabi's OWN loader, so the loader's validate()
/// gate runs.
///
/// This test exists because the field assertions above all passed while the
/// profile was unloadable: health_port was absent, defaults to 0, and
/// validate() rejects 0. main.rs does not crashloop on that. It starts in
/// DEGRADED mode, binds, answers the liveness probe and serves an error page
/// instead of the SPA. Asserting on parsed struct fields cannot see any of
/// that; only running the real loader can.
#[test]
fn the_profile_actually_loads_through_hanabis_own_loader() {
    // validate() also requires server.static_dir to EXIST on disk. In the image
    // it does, because the assets are baked at that path; on a dev machine
    // /usr/share/nginx/html does not. So the real profile is loaded with ONLY
    // that one path redirected at a temp dir. Every other field, and the whole
    // validate() gate, is the real thing. static_dir's real value is asserted
    // separately by static_dir_is_the_path_the_chart_mounts_into.
    let raw = std::fs::read_to_string("config/akeyless-web-ui.yaml").expect("profile must exist");
    let tmp = std::env::temp_dir().join("hanabi-profile-test-static");
    std::fs::create_dir_all(&tmp).expect("temp static dir");
    let redirected = raw.replace(
        "static_dir: /usr/share/nginx/html",
        &format!("static_dir: {}", tmp.display()),
    );
    assert!(
        redirected != raw,
        "the static_dir line must have been found and redirected"
    );
    let path = std::env::temp_dir().join("hanabi-profile-test.yaml");
    std::fs::write(&path, redirected).expect("write redirected profile");

    // AppConfig::load() reads CONFIG_PATH. Serialised because env is process-wide.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().unwrap();

    let previous = std::env::var("CONFIG_PATH").ok();
    unsafe { std::env::set_var("CONFIG_PATH", &path) };

    let loaded = AppConfig::load();

    match previous {
        Some(v) => unsafe { std::env::set_var("CONFIG_PATH", v) },
        None => unsafe { std::env::remove_var("CONFIG_PATH") },
    }

    let cfg = loaded.unwrap_or_else(|e| {
        panic!("the profile must load cleanly or the pod serves a degraded error page: {e}")
    });
    assert_eq!(cfg.server.http_port, 8000);
    assert_ne!(
        cfg.server.health_port, cfg.server.http_port,
        "validate() rejects equal http and health ports"
    );
}
