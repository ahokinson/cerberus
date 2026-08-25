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

/// The canonical `policy` head Rego policies, embedded the same way as
/// `RULES` and written by `cerberus init` into the reserved
/// `custom/cerberus/` subdirectory of cupcake's global store (see
/// `Paths::cupcake_global_custom_dir`), never into the shared `custom/`
/// namespace a user's own onboarded policies live in.
pub const CUPCAKE_POLICIES: &[(&str, &str)] = &[
    (
        "ci-trust-boundary.rego",
        include_str!("../policies/cupcake/ci-trust-boundary.rego"),
    ),
    (
        "guard-self-protection.rego",
        include_str!("../policies/cupcake/guard-self-protection.rego"),
    ),
    (
        "sandbox-integrity.rego",
        include_str!("../policies/cupcake/sandbox-integrity.rego"),
    ),
    (
        "webfetch-ssrf.rego",
        include_str!("../policies/cupcake/webfetch-ssrf.rego"),
    ),
];

/// The canonical `risk` head overlay: a small `custom_rules:` addition to
/// tirith's own built-in detections, written by `cerberus init` to
/// `Paths::tirith_overlay_policy_file()` and applied only in repos with no
/// `.tirith/policy.yaml` of their own (see `integrations::tirith`).
pub const TIRITH_POLICY: &str = include_str!("../policies/tirith/policy.yaml");
