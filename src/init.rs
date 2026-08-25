use crate::embedded;
use crate::harness::cursor;
use crate::head::Head;
use crate::integrations::cupcake;
use crate::paths::Paths;
use crate::process::command_exists;
use crate::settings;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

/// Writes the shipped rule scripts (`embedded::RULES`) into
/// `rules_dir`, creating it if needed. Overwrites only the known filenames;
/// any other `.rhai` file already there (a personal rule) is left alone.
/// Returns the number of scripts written.
fn write_rule_scripts(rules_dir: &Path) -> io::Result<usize> {
    fs::create_dir_all(rules_dir)?;
    for (name, contents) in embedded::RULES {
        fs::write(rules_dir.join(name), contents)?;
    }
    Ok(embedded::RULES.len())
}

/// Writes cerberus's shipped Rego policies (`embedded::CUPCAKE_POLICIES`)
/// into `dir` — cupcake's global store's reserved `custom/cerberus/`
/// subdirectory (see `Paths::cupcake_global_custom_dir`) — creating it if
/// needed. Same always-overwrite-the-known-files contract as
/// [`write_rule_scripts`]: this is canonical, versioned content, and the
/// directory is reserved to cerberus alone, so there's never an "unrelated
/// file" to worry about leaving in place.
fn write_cupcake_policies(dir: &Path) -> io::Result<usize> {
    fs::create_dir_all(dir)?;
    for (name, contents) in embedded::CUPCAKE_POLICIES {
        fs::write(dir.join(name), contents)?;
    }
    Ok(embedded::CUPCAKE_POLICIES.len())
}

/// Writes cerberus's tirith overlay policy (`embedded::TIRITH_POLICY`) to
/// `Paths::tirith_overlay_policy_file`, always overwriting: canonical,
/// versioned content, same as the rule scripts and cupcake policies. Pure
/// local file I/O — no `tirith` binary needed to write it, only to enforce
/// it later.
fn write_tirith_overlay(paths: &Paths) -> io::Result<()> {
    let file = paths.tirith_overlay_policy_file();
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&file, embedded::TIRITH_POLICY)
}

/// Writes cerberus's shipped Hermes Agent plugin (`embedded::HERMES_PLUGIN`)
/// into `dir`, creating it if needed. Same always-overwrite-the-known-files
/// contract as [`write_rule_scripts`]/[`write_cupcake_policies`]: this
/// directory is reserved to cerberus alone.
fn write_hermes_plugin(dir: &Path) -> io::Result<usize> {
    fs::create_dir_all(dir)?;
    for (name, contents) in embedded::HERMES_PLUGIN {
        fs::write(dir.join(name), contents)?;
    }
    Ok(embedded::HERMES_PLUGIN.len())
}

const DEFAULT_CONFIG_TOML: &str = "\
# All heads run by default. Set `disabled = true` on a head to remove it
# from `cerberus guard`'s stack. `gate` (the fail-closed backstop) always
# runs first automatically and isn't listed here.
#
# Each head catches a different kind of bad outcome:
[heads]
risk = { disabled = false }      # general risk avoidance: tirith command-pattern scanning
policy = { disabled = false }    # governance policy: cupcake policy evaluation
judgement = { disabled = false } # contextual bad decisions: Rhai situational checks
";

/// Writes the default `config.toml` if `paths.config_file()` doesn't exist
/// yet. Unlike the rule scripts (always overwritten, being canonical
/// versioned content), this file is user-owned: an existing one is never
/// touched.
/// Returns whether a file was created.
fn ensure_config_file(paths: &Paths) -> io::Result<bool> {
    let path = paths.config_file();
    if path.exists() {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, DEFAULT_CONFIG_TOML)?;
    Ok(true)
}

enum StubOutcome {
    AlreadyInstalled,
    Created,
    Skipped(String),
    Failed(String),
}

enum CodexFeatureOutcome {
    Enabled,
    AlreadyEnabled,
    ExplicitlyDisabled,
    Failed(String),
}

/// Ensures `[features] codex_hooks = true` in `config_path` (Codex's own
/// `config.toml`). Codex's hook engine is `Stage::UnderDevelopment` —
/// writing `hooks.json` alone does nothing until this flag is also set;
/// without it, hooks are documented to be silent no-ops, exactly the
/// "quietly stopped working" failure mode cerberus's own `health` exists
/// to catch elsewhere. Merges into any existing `config.toml` (preserving
/// every other key and every other feature flag), the same
/// non-destructive spirit as `settings::merge`.
///
/// Only ever sets the flag when it's absent. If a user explicitly set
/// `codex_hooks = false` themselves, that's respected rather than
/// silently overridden — reported as a problem instead, since cerberus's
/// hooks won't fire until it's removed.
fn ensure_codex_hooks_enabled(config_path: &Path) -> CodexFeatureOutcome {
    let mut doc: toml::Value = fs::read_to_string(config_path)
        .ok()
        .and_then(|raw| toml::from_str(&raw).ok())
        .unwrap_or_else(|| toml::Value::Table(Default::default()));
    if !doc.is_table() {
        doc = toml::Value::Table(Default::default());
    }

    let table = doc.as_table_mut().expect("coerced to table above");
    let features = table
        .entry("features")
        .or_insert_with(|| toml::Value::Table(Default::default()));
    if !features.is_table() {
        *features = toml::Value::Table(Default::default());
    }
    let features_table = features.as_table_mut().expect("coerced to table above");

    match features_table.get("codex_hooks") {
        Some(toml::Value::Boolean(true)) => return CodexFeatureOutcome::AlreadyEnabled,
        Some(toml::Value::Boolean(false)) => return CodexFeatureOutcome::ExplicitlyDisabled,
        _ => {
            features_table.insert("codex_hooks".to_string(), toml::Value::Boolean(true));
        }
    }

    if let Some(parent) = config_path.parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        return CodexFeatureOutcome::Failed(format!("couldn't create {}: {e}", parent.display()));
    }
    let text = match toml::to_string_pretty(&doc) {
        Ok(text) => text,
        Err(e) => return CodexFeatureOutcome::Failed(format!("couldn't serialize config: {e}")),
    };
    match fs::write(config_path, text) {
        Ok(()) => CodexFeatureOutcome::Enabled,
        Err(e) => {
            CodexFeatureOutcome::Failed(format!("couldn't write {}: {e}", config_path.display()))
        }
    }
}

/// Ensures a cupcake stub project exists at `paths.cupcake_stub()` so the
/// `policy` head has something to evaluate against. Shells out to `cupcake
/// init --harness claude` when the binary is available; otherwise reports
/// why it couldn't, per the fail-open philosophy (report, don't error out).
fn ensure_cupcake_stub(paths: &Paths) -> StubOutcome {
    let stub = paths.cupcake_stub();
    if cupcake::stub_installed(&stub) {
        return StubOutcome::AlreadyInstalled;
    }
    if !command_exists("cupcake") {
        return StubOutcome::Skipped("cupcake not on PATH".to_string());
    }
    if let Err(e) = fs::create_dir_all(&stub) {
        return StubOutcome::Failed(format!("couldn't create {}: {e}", stub.display()));
    }
    let status = Command::new("cupcake")
        .args(["init", "--harness", "claude"])
        .current_dir(&stub)
        .status();
    match status {
        Ok(s) if s.success() && cupcake::stub_installed(&stub) => StubOutcome::Created,
        Ok(s) => StubOutcome::Failed(format!("cupcake init exited with {s}")),
        Err(e) => StubOutcome::Failed(format!("failed to run cupcake init: {e}")),
    }
}

/// Ensures cupcake's **global** store exists for the `claude` harness and
/// that cerberus's own policies are current inside it. Only ever calls
/// `cupcake init --global` when the global root doesn't already have a
/// `claude` harness installed — never re-initializes a store a user (or a
/// different harness) already set up — and only ever writes beneath
/// `paths.cupcake_global_custom_dir()`, never touching anything else in the
/// store.
///
/// Runs the `cupcake init --global` subprocess with `HOME` pointed at a
/// decoy directory and `XDG_CONFIG_HOME` pointed at the real target
/// (`paths.config_home`, i.e. `cupcake_global_root()`'s parent): confirmed
/// against the real binary, `cupcake init --global` doesn't just scaffold
/// the policy tree, it also tries to auto-wire its *own* independent
/// `PreToolUse` hook (matcher `"*"`, running `cupcake eval` directly) into
/// `$HOME/.claude/settings.json` on its own initiative. Left unchecked that
/// would corrupt the single hook slot `settings::install_hooks` owns and
/// double-evaluate cupcake on every guarded call. The decoy `HOME` has no
/// `.claude/settings.json` for that probe to find, so it's a no-op there,
/// while `XDG_CONFIG_HOME` still steers the actual global store to the
/// right place.
fn ensure_cupcake_global(paths: &Paths) -> StubOutcome {
    let root = paths.cupcake_global_root();
    let already_installed = cupcake::global_installed(&root);
    if !already_installed {
        if !command_exists("cupcake") {
            return StubOutcome::Skipped("cupcake not on PATH".to_string());
        }
        let decoy_home = paths.cupcake_global_init_decoy_home();
        if let Err(e) = fs::create_dir_all(&decoy_home) {
            return StubOutcome::Failed(format!("couldn't create {}: {e}", decoy_home.display()));
        }
        let status = Command::new("cupcake")
            .args(["init", "--global", "--harness", "claude"])
            .env("HOME", &decoy_home)
            .env("XDG_CONFIG_HOME", &paths.config_home)
            .status();
        match status {
            Ok(s) if s.success() && cupcake::global_installed(&root) => {}
            Ok(s) => return StubOutcome::Failed(format!("cupcake init --global exited with {s}")),
            Err(e) => {
                return StubOutcome::Failed(format!("failed to run cupcake init --global: {e}"));
            }
        }
    }
    match write_cupcake_policies(&paths.cupcake_global_custom_dir()) {
        Ok(_) if already_installed => StubOutcome::AlreadyInstalled,
        Ok(_) => StubOutcome::Created,
        Err(e) => StubOutcome::Failed(format!("couldn't write cerberus's cupcake policies: {e}")),
    }
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

/// Bootstraps everything cerberus needs: writes the rule scripts, seeds a
/// default `config.toml`, ensures the cupcake stub project exists, and
/// wires `cerberus guard`/`cerberus health` into `~/.claude/settings.json`.
///
/// Prints a summary per artifact as it goes, then one per head (see
/// [`crate::head::Head`]), so the three-heads structure is visible at setup
/// time. Returns a process exit code: `0` fully bootstrapped, non-zero if
/// something was skipped, such as a missing binary.
pub fn run(paths: &Paths) -> i32 {
    println!("cerberus init: bootstrapping three heads:");
    for head in Head::ORDER {
        println!(
            "  {} ({}): {}",
            head.name(),
            head.purpose(),
            head.mechanism()
        );
    }
    println!();

    let mut problems = Vec::new();

    let rules_dir = paths.rule_scripts_dir();
    let rule_script_count = match write_rule_scripts(&rules_dir) {
        Ok(n) => {
            println!(
                "rule scripts: wrote {n} script(s) to {}",
                rules_dir.display()
            );
            n
        }
        Err(e) => {
            problems.push(format!(
                "couldn't write rule scripts to {}: {e}",
                rules_dir.display()
            ));
            0
        }
    };

    match ensure_config_file(paths) {
        Ok(true) => println!("config: wrote default {}", paths.config_file().display()),
        Ok(false) => println!(
            "config: existing {} left untouched",
            paths.config_file().display()
        ),
        Err(e) => problems.push(format!(
            "couldn't write {}: {e}",
            paths.config_file().display()
        )),
    }

    let tirith_on_path = command_exists("tirith");
    if !tirith_on_path {
        problems.push(format!(
            "{} ({}): tirith not on PATH, so risk will fail open until it's installed",
            Head::Risk.name(),
            Head::Risk.purpose()
        ));
    }
    let opa_on_path = command_exists("opa");
    if !opa_on_path {
        problems.push(format!(
            "{} ({}): opa (cupcake's Rego engine) not on PATH, so policy will fail open \
            until it's installed",
            Head::Policy.name(),
            Head::Policy.purpose()
        ));
    }

    let stub_outcome = ensure_cupcake_stub(paths);
    let cupcake_stub_ready = matches!(
        stub_outcome,
        StubOutcome::AlreadyInstalled | StubOutcome::Created
    );
    match stub_outcome {
        StubOutcome::AlreadyInstalled => println!(
            "cupcake stub: already installed at {}",
            paths.cupcake_stub().display()
        ),
        StubOutcome::Created => println!(
            "cupcake stub: created at {}",
            paths.cupcake_stub().display()
        ),
        StubOutcome::Skipped(reason) => {
            problems.push(format!("cupcake stub not created: {reason}"))
        }
        StubOutcome::Failed(reason) => {
            problems.push(format!("cupcake stub setup failed: {reason}"))
        }
    }

    let global_outcome = ensure_cupcake_global(paths);
    let cupcake_global_ready = matches!(
        global_outcome,
        StubOutcome::AlreadyInstalled | StubOutcome::Created
    );
    let cupcake_policies_installed = if cupcake_global_ready {
        embedded::CUPCAKE_POLICIES.len()
    } else {
        0
    };
    match global_outcome {
        StubOutcome::AlreadyInstalled => println!(
            "cupcake global store: cerberus's {} polic(ies) refreshed at {}",
            cupcake_policies_installed,
            paths.cupcake_global_custom_dir().display()
        ),
        StubOutcome::Created => println!(
            "cupcake global store: created at {}, cerberus's {} polic(ies) installed",
            paths.cupcake_global_root().display(),
            cupcake_policies_installed
        ),
        StubOutcome::Skipped(reason) => {
            problems.push(format!("cupcake global store not created: {reason}"))
        }
        StubOutcome::Failed(reason) => {
            problems.push(format!("cupcake global store setup failed: {reason}"))
        }
    }

    let tirith_overlay_written = match write_tirith_overlay(paths) {
        Ok(()) => {
            println!(
                "tirith overlay: wrote {}",
                paths.tirith_overlay_policy_file().display()
            );
            true
        }
        Err(e) => {
            problems.push(format!(
                "couldn't write tirith overlay to {}: {e}",
                paths.tirith_overlay_policy_file().display()
            ));
            false
        }
    };

    match settings::install_hooks(&paths.claude_settings_json()) {
        Ok(report) => {
            if report.pretooluse_changed {
                println!("settings.json: `cerberus guard` now runs first on PreToolUse");
            } else {
                println!("settings.json: PreToolUse entry already up to date");
            }
            if report.sessionstart_changed {
                println!("settings.json: `cerberus health` now runs first on SessionStart");
            } else {
                println!("settings.json: SessionStart entry already up to date");
            }
        }
        Err(e) => problems.push(format!(
            "couldn't update {}: {e}",
            paths.claude_settings_json().display()
        )),
    }

    let codex_on_path = command_exists("codex");
    if codex_on_path {
        match settings::install_hooks(&paths.codex_hooks_json()) {
            Ok(report) => {
                if report.pretooluse_changed {
                    println!("codex hooks.json: `cerberus guard` now runs first on PreToolUse");
                } else {
                    println!("codex hooks.json: PreToolUse entry already up to date");
                }
                if report.sessionstart_changed {
                    println!("codex hooks.json: `cerberus health` now runs first on SessionStart");
                } else {
                    println!("codex hooks.json: SessionStart entry already up to date");
                }
            }
            Err(e) => problems.push(format!(
                "couldn't update {}: {e}",
                paths.codex_hooks_json().display()
            )),
        }
        match ensure_codex_hooks_enabled(&paths.codex_config_toml()) {
            CodexFeatureOutcome::Enabled => println!(
                "codex config.toml: enabled `[features] codex_hooks` (hooks are a silent \
                no-op without it)"
            ),
            CodexFeatureOutcome::AlreadyEnabled => {
                println!("codex config.toml: `[features] codex_hooks` already enabled")
            }
            CodexFeatureOutcome::ExplicitlyDisabled => problems.push(format!(
                "{} has `[features] codex_hooks = false` set explicitly — cerberus's Codex \
                hooks are installed but will not fire until that line is removed (left alone \
                since you set it, not cerberus)",
                paths.codex_config_toml().display()
            )),
            CodexFeatureOutcome::Failed(e) => problems.push(format!(
                "couldn't enable codex_hooks in {}: {e}",
                paths.codex_config_toml().display()
            )),
        }
    } else {
        println!("codex: not on PATH, skipping hooks.json wiring");
    }

    // Cursor is a GUI app, not reliably a CLI on PATH, so detect it by its
    // own config directory instead of `command_exists`.
    let cursor_present = paths.home.join(".cursor").is_dir();
    if cursor_present {
        match cursor::install_hooks(&paths.cursor_hooks_json()) {
            Ok(report) => {
                if report.before_shell_execution_changed {
                    println!(
                        "cursor hooks.json: `cerberus guard` now runs first on beforeShellExecution"
                    );
                } else {
                    println!("cursor hooks.json: beforeShellExecution entry already up to date");
                }
                if report.before_mcp_execution_changed {
                    println!(
                        "cursor hooks.json: `cerberus guard` now runs first on beforeMCPExecution"
                    );
                } else {
                    println!("cursor hooks.json: beforeMCPExecution entry already up to date");
                }
                println!(
                    "cursor hooks.json: note — Cursor has no pre-write file hook, so Write/\
                    Edit/NotebookEdit-equivalent calls are not guarded there"
                );
            }
            Err(e) => problems.push(format!(
                "couldn't update {}: {e}",
                paths.cursor_hooks_json().display()
            )),
        }
    } else {
        println!("cursor: no ~/.cursor directory found, skipping hooks.json wiring");
    }

    let hermes_on_path = command_exists("hermes");
    if hermes_on_path {
        let plugin_dir = paths.hermes_plugin_dir();
        match write_hermes_plugin(&plugin_dir) {
            Ok(n) => println!(
                "hermes plugin: wrote {n} file(s) to {} — verify with `hermes hooks list` or \
                `hermes doctor`; this plugin's manifest is a best effort against Hermes's \
                documented format, not verified against the real binary",
                plugin_dir.display()
            ),
            Err(e) => problems.push(format!(
                "couldn't write hermes plugin to {}: {e}",
                plugin_dir.display()
            )),
        }
    } else {
        println!("hermes: not on PATH, skipping plugin install");
    }

    println!("\nper-head status:");
    println!(
        "  {:<10} ({:<24}) — tirith on PATH: {}, overlay written: {}",
        Head::Risk.name(),
        Head::Risk.purpose(),
        yes_no(tirith_on_path),
        yes_no(tirith_overlay_written)
    );
    println!(
        "  {:<10} ({:<24}) — cupcake stub ready: {}, opa on PATH: {}, global store ready: {}, \
        custom cerberus policies installed: {cupcake_policies_installed}",
        Head::Policy.name(),
        Head::Policy.purpose(),
        yes_no(cupcake_stub_ready),
        yes_no(opa_on_path),
        yes_no(cupcake_global_ready)
    );
    println!(
        "  {:<10} ({:<24}) — {rule_script_count} rule script(s) installed",
        Head::Judgement.name(),
        Head::Judgement.purpose()
    );

    if problems.is_empty() {
        println!("\ncerberus init: done, all heads bootstrapped");
        0
    } else {
        eprintln!(
            "\ncerberus init: finished with {} outstanding problem(s):",
            problems.len()
        );
        for p in &problems {
            eprintln!("  - {p}");
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir = temp_dir().join(format!("cerberus-init-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn writes_all_shipped_rule_scripts() {
        let dir = tempdir("writes-all");
        let count = write_rule_scripts(&dir).unwrap();
        assert_eq!(count, embedded::RULES.len());
        for (name, contents) in embedded::RULES {
            assert_eq!(fs::read_to_string(dir.join(name)).unwrap(), *contents);
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn leaves_unrelated_rhai_files_alone() {
        let dir = tempdir("leaves-unrelated");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("my-personal-rule.rhai"),
            "fn check(cmd, cwd, input) {}",
        )
        .unwrap();

        write_rule_scripts(&dir).unwrap();

        assert_eq!(
            fs::read_to_string(dir.join("my-personal-rule.rhai")).unwrap(),
            "fn check(cmd, cwd, input) {}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rewriting_is_idempotent() {
        let dir = tempdir("idempotent");
        write_rule_scripts(&dir).unwrap();
        let first: Vec<_> = embedded::RULES
            .iter()
            .map(|(name, _)| fs::read_to_string(dir.join(name)).unwrap())
            .collect();
        write_rule_scripts(&dir).unwrap();
        let second: Vec<_> = embedded::RULES
            .iter()
            .map(|(name, _)| fs::read_to_string(dir.join(name)).unwrap())
            .collect();
        assert_eq!(first, second);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_cupcake_policies_writes_all_shipped_policies() {
        let dir = tempdir("cupcake-writes-all");
        let count = write_cupcake_policies(&dir).unwrap();
        assert_eq!(count, embedded::CUPCAKE_POLICIES.len());
        for (name, contents) in embedded::CUPCAKE_POLICIES {
            assert_eq!(fs::read_to_string(dir.join(name)).unwrap(), *contents);
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_cupcake_policies_is_idempotent() {
        let dir = tempdir("cupcake-idempotent");
        write_cupcake_policies(&dir).unwrap();
        let first: Vec<_> = embedded::CUPCAKE_POLICIES
            .iter()
            .map(|(name, _)| fs::read_to_string(dir.join(name)).unwrap())
            .collect();
        write_cupcake_policies(&dir).unwrap();
        let second: Vec<_> = embedded::CUPCAKE_POLICIES
            .iter()
            .map(|(name, _)| fs::read_to_string(dir.join(name)).unwrap())
            .collect();
        assert_eq!(first, second);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ensure_codex_hooks_enabled_creates_config_when_missing() {
        let dir = tempdir("codex-hooks-missing");
        let config_path = dir.join("config.toml");
        let outcome = ensure_codex_hooks_enabled(&config_path);
        assert!(matches!(outcome, CodexFeatureOutcome::Enabled));
        let written = fs::read_to_string(&config_path).unwrap();
        let parsed: toml::Value = toml::from_str(&written).unwrap();
        assert_eq!(parsed["features"]["codex_hooks"].as_bool(), Some(true));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ensure_codex_hooks_enabled_preserves_other_content_and_is_idempotent() {
        let dir = tempdir("codex-hooks-preserve");
        fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        fs::write(
            &config_path,
            "model = \"gpt-5\"\n\n[features]\nother_feature = true\n",
        )
        .unwrap();

        let outcome = ensure_codex_hooks_enabled(&config_path);
        assert!(matches!(outcome, CodexFeatureOutcome::Enabled));
        let parsed: toml::Value =
            toml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(parsed["model"].as_str(), Some("gpt-5"));
        assert_eq!(parsed["features"]["other_feature"].as_bool(), Some(true));
        assert_eq!(parsed["features"]["codex_hooks"].as_bool(), Some(true));

        let second = ensure_codex_hooks_enabled(&config_path);
        assert!(matches!(second, CodexFeatureOutcome::AlreadyEnabled));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ensure_codex_hooks_enabled_respects_an_explicit_false() {
        let dir = tempdir("codex-hooks-explicit-false");
        fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        fs::write(&config_path, "[features]\ncodex_hooks = false\n").unwrap();

        let outcome = ensure_codex_hooks_enabled(&config_path);
        assert!(matches!(outcome, CodexFeatureOutcome::ExplicitlyDisabled));
        let unchanged = fs::read_to_string(&config_path).unwrap();
        assert_eq!(unchanged, "[features]\ncodex_hooks = false\n");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn writes_all_shipped_hermes_plugin_files() {
        let dir = tempdir("hermes-writes-all");
        let count = write_hermes_plugin(&dir).unwrap();
        assert_eq!(count, embedded::HERMES_PLUGIN.len());
        for (name, contents) in embedded::HERMES_PLUGIN {
            assert_eq!(fs::read_to_string(dir.join(name)).unwrap(), *contents);
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_hermes_plugin_is_idempotent() {
        let dir = tempdir("hermes-idempotent");
        write_hermes_plugin(&dir).unwrap();
        let first: Vec<_> = embedded::HERMES_PLUGIN
            .iter()
            .map(|(name, _)| fs::read_to_string(dir.join(name)).unwrap())
            .collect();
        write_hermes_plugin(&dir).unwrap();
        let second: Vec<_> = embedded::HERMES_PLUGIN
            .iter()
            .map(|(name, _)| fs::read_to_string(dir.join(name)).unwrap())
            .collect();
        assert_eq!(first, second);
        fs::remove_dir_all(&dir).ok();
    }

    fn scratch_paths(name: &str) -> Paths {
        let root = tempdir(name);
        Paths {
            state_home: root.join("state"),
            data_home: root.join("data"),
            config_home: root.join("config"),
            home: root.join("home"),
        }
    }

    #[test]
    fn writes_default_config_when_missing() {
        let paths = scratch_paths("config-missing");
        let created = ensure_config_file(&paths).unwrap();
        assert!(created);
        assert_eq!(
            fs::read_to_string(paths.config_file()).unwrap(),
            DEFAULT_CONFIG_TOML
        );
        fs::remove_dir_all(paths.config_home.parent().unwrap()).ok();
    }

    #[test]
    fn leaves_an_existing_config_untouched() {
        let paths = scratch_paths("config-existing");
        fs::create_dir_all(paths.config_file().parent().unwrap()).unwrap();
        fs::write(paths.config_file(), "[heads]\nrisk = { disabled = true }\n").unwrap();

        let created = ensure_config_file(&paths).unwrap();

        assert!(!created);
        assert_eq!(
            fs::read_to_string(paths.config_file()).unwrap(),
            "[heads]\nrisk = { disabled = true }\n"
        );
        fs::remove_dir_all(paths.config_home.parent().unwrap()).ok();
    }

    #[test]
    fn write_tirith_overlay_writes_the_shipped_policy() {
        let paths = scratch_paths("tirith-overlay");
        write_tirith_overlay(&paths).unwrap();
        assert_eq!(
            fs::read_to_string(paths.tirith_overlay_policy_file()).unwrap(),
            embedded::TIRITH_POLICY
        );
        fs::remove_dir_all(paths.data_home.parent().unwrap()).ok();
    }

    #[test]
    fn write_tirith_overlay_is_idempotent() {
        let paths = scratch_paths("tirith-overlay-idempotent");
        write_tirith_overlay(&paths).unwrap();
        let first = fs::read_to_string(paths.tirith_overlay_policy_file()).unwrap();
        write_tirith_overlay(&paths).unwrap();
        let second = fs::read_to_string(paths.tirith_overlay_policy_file()).unwrap();
        assert_eq!(first, second);
        fs::remove_dir_all(paths.data_home.parent().unwrap()).ok();
    }
}
