/// The canonical `judgement` rule scripts, embedded at compile time so
/// `cerberus init` can write them into `Paths::rule_scripts_dir()` without
/// depending on the source checkout still being present on disk (the
/// installed binary may run from anywhere).
pub const RULES: &[(&str, &str)] = &[
    (
        "environment-awareness.rhai",
        include_str!("../rules/environment-awareness.rhai"),
    ),
    ("git-safety.rhai", include_str!("../rules/git-safety.rhai")),
    (
        "release-hygiene.rhai",
        include_str!("../rules/release-hygiene.rhai"),
    ),
    (
        "sandbox-integrity.rhai",
        include_str!("../rules/sandbox-integrity.rhai"),
    ),
];
