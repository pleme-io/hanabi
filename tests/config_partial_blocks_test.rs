//! A partial config block must stay a PARTIAL BLOCK — never a whole-file refusal.
//!
//! ── ★ WHY THIS FILE EXISTS ────────────────────────────────────────────────
//! hanabi is becoming the fleet front door, rendered from nix by
//! `pleme.frontDoor`. A renderer emits whatever the operator declared and
//! nothing else, so it emits PARTIAL sections by construction — `proxy:` with
//! two fields, `l4:` with one. If any nested config struct has a field without
//! a default, that partial section is a missing-field error, and hanabi's
//! loader (like every serde loader) refuses **the entire document** and falls
//! back to prescribed defaults.
//!
//! That is not hypothetical. omoya shipped exactly this defect on 2026-09-19:
//! `DamageConfig` lacked `#[serde(default)]`, plo's rendered config carried a
//! partial `damage:` block, the whole file was refused, and the seat ran TILING
//! for hours while `layout.mode: floating` sat in the file — announced by one
//! WARN, once. The fix there was `every_section_accepts_a_partial_block`; this
//! is the same gate on the service about to inherit the same shape.
//!
//! Doctrine: `theory/UNREPRESENTABILITY.md` §II.2.1 — a refusal is scoped to
//! the bad state it names. A config document of independent sections is not the
//! unit of use, so a document-scoped refusal is mis-scoped by construction.
//! Ladder rung: `theory/CONFIGURATION-MANAGEMENT.md` §IV rung 3b.
//!
//! **The denominator is derived, not listed.** Sections come from the default
//! config's own serialization, so a section added later is covered without
//! editing this file — the failure mode of a hand-listed denominator is that it
//! silently stops covering new code.

use hanabi::config::AppConfig;

/// Every mapping-valued top-level key of the default config, derived from the
/// default itself rather than hand-listed.
fn sections() -> Vec<String> {
    let cfg: AppConfig = serde_yaml::from_str("{}")
        .expect("an empty document must load as all-defaults (ladder rung 2)");
    let yaml = serde_yaml::to_string(&cfg).expect("the default config must serialize");
    let map: serde_yaml::Mapping =
        serde_yaml::from_str(&yaml).expect("a serialized AppConfig is a mapping");

    map.iter()
        .filter(|(_, v)| v.is_mapping())
        .filter_map(|(k, _)| k.as_str().map(str::to_owned))
        .collect()
}

#[test]
fn an_empty_document_loads_as_all_defaults() {
    // Rung 2. Also the precondition for `sections()` below, stated as its own
    // test so a failure here is not misread as a partial-block failure.
    let cfg: AppConfig = serde_yaml::from_str("{}")
        .expect("an empty document must load as all-defaults, not an error");
    assert!(
        !cfg.environment.is_empty(),
        "a defaulted environment should be populated, got empty"
    );
}

#[test]
fn every_section_accepts_an_empty_block() {
    let sections = sections();

    // A gate with an empty denominator measures nothing. This floor is well
    // below the real count and exists only to fail loudly if `sections()` ever
    // resolves to nothing — the vacuous-guard class (§II.3).
    assert!(
        sections.len() >= 10,
        "denominator collapsed: expected many config sections, derived {}: {:?}",
        sections.len(),
        sections
    );

    let mut refused = Vec::new();
    for name in &sections {
        let doc = format!("{name}: {{}}\n");
        if let Err(e) = serde_yaml::from_str::<AppConfig>(&doc) {
            refused.push(format!("  {name}: {e}"));
        }
    }

    assert!(
        refused.is_empty(),
        "{} of {} sections cannot be declared partially — each one makes a \
         RENDERED PARTIAL CONFIG refuse the whole document and silently fall \
         back to defaults. Add #[serde(default)] to the offending nested \
         fields.\n{}",
        refused.len(),
        sections.len(),
        refused.join("\n")
    );
}

#[test]
fn a_partial_l4_block_does_not_refuse_the_document() {
    // The concrete case the front door will emit: `l4:` carrying only the field
    // the operator set. Named separately from the sweep above because this is
    // the one a renderer is most likely to produce first, and a named test
    // failure reads better than one row in a list.
    let cfg: AppConfig = serde_yaml::from_str("l4:\n  enabled: true\n")
        .expect("a partial l4 block must load, not refuse the document");
    assert!(cfg.l4.enabled, "the declared value must survive the load");
    assert!(
        cfg.l4.proxies.is_empty(),
        "an undeclared sibling must default, not fail"
    );
}

#[test]
fn an_unknown_key_does_not_refuse_the_document() {
    // hanabi carries NO `deny_unknown_fields` (measured: 0 occurrences in
    // src/). That is deliberate for a config a renderer writes: a key from a
    // newer renderer reaching an older binary degrades to "ignored", not to
    // "the front door will not start". Pinned so a later strictness change is a
    // decision with this cost in front of it, rather than a one-line default.
    let cfg: AppConfig =
        serde_yaml::from_str("a_key_no_version_of_hanabi_knows: 42\nl4:\n  enabled: true\n")
            .expect("an unknown key must not refuse the document");
    assert!(
        cfg.l4.enabled,
        "the rest of the document must still take effect"
    );
}
