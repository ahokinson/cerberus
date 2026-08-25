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

/// cerberus's Hermes Agent plugin: a Python `pre_tool_call` hook that
/// shells out to `cerberus guard`, since Hermes's best-documented
/// integration surface is an in-process Python callback rather than a
/// subprocess/stdin contract the way Claude Code, Codex CLI, and Cursor
/// all are. Written by `cerberus init` into `Paths::hermes_plugin_dir()`.
/// See `harness-templates/hermes/plugin.py` for why `cerberus guard`
/// itself needs no Hermes-specific code at all.
pub const HERMES_PLUGIN: &[(&str, &str)] = &[
    (
        "plugin.yaml",
        include_str!("../harness-templates/hermes/plugin.yaml"),
    ),
    (
        "plugin.py",
        include_str!("../harness-templates/hermes/plugin.py"),
    ),
];

/// cerberus's opencode plugin: an in-process TypeScript hook that shells
/// out to `cerberus guard`, since opencode plugins run inside opencode's
/// own Bun process rather than as a subprocess given JSON on stdin.
/// Written by `cerberus init` as a single file into
/// `Paths::opencode_plugin_dir()`. That directory is flat and shared
/// across every plugin from every source, unlike Hermes's per-plugin
/// subdirectory, hence the distinctive filename baked into the path
/// itself rather than a second embedded const here.
pub const OPENCODE_PLUGIN: &str = include_str!("../harness-templates/opencode/cerberus-guard.ts");
