//! The dark-module gate: every `pub mod` states whether anything reaches it.
//!
//! ## Why this test exists
//!
//! On 2026-09-24 an agent asked "what is hanabi?", read a stale row in
//! `tatara/docs/theory-realization-map.md` describing it as "L7 proxy + L4 LB
//! + cache + circuit breaker", and designed a fleet front door on that basis.
//! Those three things are `src/proxy`, `src/l4` and `src/mesh` — and **none of
//! them is constructed anywhere**. The row named the part that does not run.
//!
//! Establishing that took three parallel exploration agents and roughly 400K
//! tokens of reading, when the condition is one grep: a `pub mod X;` with no
//! reference to `X::` or `crate::X` outside `src/X/` is dark. This test turns
//! "read 51K lines" into "read a list", so the next person gets the answer for
//! free and a module cannot go dark silently.
//!
//! ## What it asserts
//!
//! The measured set of dark modules must equal [`EXPECTED_DARK`] exactly. That
//! is deliberately a two-way gate:
//!
//! * a **new** dark module fails the test — you must declare it here, which
//!   forces a sentence about why it is unreached;
//! * **wiring** a module also fails the test — you must remove it here, which
//!   forces the docs that describe it as dark to be corrected in the same
//!   change. That is the failure mode this whole exercise was about.
//!
//! ## Honest limits
//!
//! This is a TEXTUAL scan, not a call-graph. It can be fooled — by a macro
//! that builds a path, by re-export chains, by `use crate::x::Thing` followed
//! by bare `Thing` (which it *does* catch, since the `use` line itself
//! matches). It is a smoke alarm, not a proof. A module it calls reached is
//! reached; a module it calls dark is *probably* dark and is worth a look.
//! Self-matching is structurally impossible: this file lives in `tests/` and
//! only `src/` is ever scanned.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Modules known to be declared and unreached, each with the reason.
///
/// Keep this list SHORT and each entry justified. An entry here is a debt
/// being tracked, not a state being blessed.
const EXPECTED_DARK: &[(&str, &str)] = &[
    (
        "l4",
        "TCP balancer. Library-only — there is no `mod l4;` in main.rs, so it \
         is absent from the shipped binary. `AppConfig` has no `l4` field and \
         no backends are ever populated. UDP does not exist at all.",
    ),
    (
        "mesh",
        "Circuit breaker + retry backoff. Library-only, and a duplicate of the \
         live per-subgraph federation::load_shedding::CircuitBreakerRegistry \
         that state.rs actually constructs. Retire rather than wire.",
    ),
];

/// Modules that ARE referenced, but only as a type — never constructed.
///
/// This tier exists because the gate caught the author collapsing it. `proxy`
/// looks reached to a textual scan: `config/mod.rs` embeds
/// `crate::proxy::ProxyConfig`, which is a genuine reference. But the config
/// is never READ and `ProxyService` is never built, so the module is just as
/// inert as a fully dark one while looking wired from the outside. That is a
/// *more* dangerous state than darkness, not a lesser one — it is why
/// `AppConfig.proxy` reads in review as "the proxy is configured".
const EXPECTED_CONFIG_ONLY: &[(&str, &str, &str)] = &[(
    "proxy",
    "ProxyService",
    "L7 reverse proxy. IN the binary (main.rs has `mod proxy;`) and \
     `AppConfig.proxy` deserializes, but nothing READS `config.proxy`, there \
     is no axum handler, and `Upgrade` is unsupported — so every \
     websocket-driven UI would load and hang.",
)];

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every `pub mod NAME;` declared in `src/lib.rs`.
fn declared_modules(lib_rs: &str) -> BTreeSet<String> {
    lib_rs
        .lines()
        .map(str::trim)
        // Only the plain declaration form. `pub mod x { .. }` inline modules
        // are not a directory and cannot be dark in the sense we mean.
        .filter_map(|l| l.strip_prefix("pub mod ")?.strip_suffix(';'))
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty() && !n.contains(' '))
        .collect()
}

/// Collect every `.rs` file under `src/`, excluding `src/<skip>/`.
fn rs_files_excluding(root: &Path, skip: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let skipped = root.join(skip);
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path != skipped {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                // `src/<skip>.rs` is also part of that module.
                if path != root.join(format!("{skip}.rs")) {
                    out.push(path);
                }
            }
        }
    }
    out
}

/// Does anything outside `src/<name>/` actually reach into it?
///
/// A bare `mod name;` / `pub mod name;` line is NOT a reference — that is the
/// declaration itself, and counting it would make every module look reached,
/// which is precisely the blindness this test removes.
fn is_reached(root: &Path, name: &str) -> bool {
    let qualified = format!("{name}::");
    let via_crate = format!("crate::{name}");
    let decl_pub = format!("pub mod {name};");
    let decl_plain = format!("mod {name};");

    rs_files_excluding(root, name).iter().any(|f| {
        let Ok(text) = std::fs::read_to_string(f) else {
            return false;
        };
        text.lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("//") && !l.starts_with("//!"))
            .filter(|l| *l != decl_pub && *l != decl_plain)
            .any(|l| l.contains(&qualified) || l.contains(&via_crate))
    })
}

/// Is the module compiled into the shipped BINARY, or only the library?
///
/// `main.rs` carries its own `mod` declarations. A module in `lib.rs` but not
/// `main.rs` exists only for tests — which is exactly the difference between
/// `proxy` (shipped, unreached) and `l4` (not shipped at all), and a
/// distinction no doc in this repo made until 2026-09-24.
fn in_binary(main_rs: &str, name: &str) -> bool {
    main_rs
        .lines()
        .map(str::trim)
        .any(|l| l == format!("mod {name};") || l == format!("pub mod {name};"))
}

#[test]
fn every_declared_module_is_reached_or_declared_dark() {
    let root = src_dir();
    let lib = std::fs::read_to_string(root.join("lib.rs")).expect("src/lib.rs");

    let declared = declared_modules(&lib);
    assert!(
        declared.len() > 10,
        "only {} modules parsed out of lib.rs — the parser is broken, and a \
         broken parser reports zero dark modules, which would pass vacuously",
        declared.len()
    );

    let measured: BTreeSet<String> = declared
        .iter()
        .filter(|name| !is_reached(&root, name))
        .cloned()
        .collect();

    let expected: BTreeSet<String> = EXPECTED_DARK.iter().map(|(n, _)| n.to_string()).collect();

    let newly_dark: Vec<_> = measured.difference(&expected).collect();
    let newly_wired: Vec<_> = expected.difference(&measured).collect();

    assert!(
        newly_dark.is_empty(),
        "NEW DARK MODULE(S): {newly_dark:?}\n\
         Nothing outside src/<name>/ references these. Either wire them, or \
         add them to EXPECTED_DARK with a sentence saying why they are not \
         reached — an undeclared dark module is how 'hanabi is an L7/L4 proxy' \
         became a believed fact."
    );

    assert!(
        newly_wired.is_empty(),
        "MODULE(S) NO LONGER DARK: {newly_wired:?}\n\
         Good — now remove them from EXPECTED_DARK, and correct every doc that \
         still calls them unwired: src/lib.rs's `pub mod` block, README.md's \
         Project Structure table, and theory/VOCABULARY.md's hanabi row."
    );
}

#[test]
fn the_binary_and_library_module_sets_are_reported() {
    // Not a pass/fail on its own — it makes the shipped-vs-library split
    // legible, which is the fact that distinguishes `proxy` from `l4`.
    let root = src_dir();
    let lib = std::fs::read_to_string(root.join("lib.rs")).expect("src/lib.rs");
    let main = std::fs::read_to_string(root.join("main.rs")).expect("src/main.rs");

    for (name, _) in EXPECTED_DARK {
        let shipped = in_binary(&main, name);
        println!(
            "dark module {name:<8} in-binary={shipped}  ({})",
            if shipped {
                "compiled in, unreached"
            } else {
                "library-only, NOT in the shipped binary"
            }
        );
    }

    // The one structural claim worth asserting: `l4` is genuinely absent from
    // the binary. If someone adds `mod l4;` to main.rs without wiring it, that
    // is a change in kind and the docs must follow.
    assert!(
        !in_binary(&main, "l4"),
        "`mod l4;` has appeared in main.rs. l4 is now shipped in the binary — \
         update src/l4/mod.rs's tier header and README.md, which both state it \
         is library-only."
    );
    assert!(
        in_binary(&main, "proxy"),
        "`mod proxy;` has left main.rs. proxy is no longer in the shipped \
         binary — src/lib.rs and README.md both claim it is."
    );
    assert!(
        declared_modules(&lib).contains("proxy"),
        "proxy is no longer declared in lib.rs"
    );
}

/// Is `Type` ever CONSTRUCTED outside its own module?
///
/// Construction, not mention: `Type::new(`, `Type {`, or `Type::with`. A
/// struct field of that type does not count — that is exactly the signal that
/// fooled the first version of this gate into calling `proxy` reached.
fn is_constructed(root: &Path, module: &str, ty: &str) -> bool {
    let patterns = [
        format!("{ty}::new("),
        format!("{ty} {{"),
        format!("{ty}::with"),
    ];
    rs_files_excluding(root, module).iter().any(|f| {
        let Ok(text) = std::fs::read_to_string(f) else {
            return false;
        };
        text.lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("//") && !l.starts_with("//!"))
            .any(|l| patterns.iter().any(|p| l.contains(p.as_str())))
    })
}

#[test]
fn referenced_but_unconstructed_modules_are_declared() {
    // The tier the first version of this gate missed. `proxy` passes
    // `is_reached` because `AppConfig` embeds `crate::proxy::ProxyConfig` --
    // a real reference to a type that is never built. Being referenced makes
    // it look wired in review while behaving exactly like dark code.
    let root = src_dir();

    for (module, ty, _why) in EXPECTED_CONFIG_ONLY {
        assert!(
            is_reached(&root, module),
            "`{module}` is not referenced at all -- it belongs in EXPECTED_DARK, \
             not EXPECTED_CONFIG_ONLY"
        );
        assert!(
            !is_constructed(&root, module, ty),
            "`{ty}` IS now constructed outside src/{module}/ -- the module is \
             genuinely wired. Remove it from EXPECTED_CONFIG_ONLY and correct \
             every doc that calls it dark: src/lib.rs's `pub mod` block, \
             README.md's Project Structure table, and theory/VOCABULARY.md."
        );
    }
}
