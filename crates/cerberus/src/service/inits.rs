use crate::config::Paths;
use crate::domain::Head;
use crate::embedded;
use crate::harnesses;
use crate::heads::policy;
use crate::heads::risk;
use crate::process::command_exists;
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
/// into `dir` — cerberus's own cupcake store's policy directory (see
/// `Paths::cupcake_policies_dir`) — creating it if needed. Same always-overwrite-the-known-files contract as
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

/// Creates the directory a user drops their own tirith fragments into. Only
/// ever created, never written to and never cleaned out: this is the risk
/// head's counterpart to a personal `.rhai` file in the rules directory, and
/// `init` has no more business editing one than the other.
fn ensure_tirith_fragments_dir(paths: &Paths) -> io::Result<()> {
    fs::create_dir_all(paths.tirith_fragments_dir())
}

/// Removes the directories and files earlier versions of cerberus left
/// behind (see `Paths::legacy_dirs` and `Paths::legacy_files`), now that
/// everything lives under one `cerberus/` namespace and its state is in one
/// database. Returns the ones that were actually there, so the removal is
/// reported by name rather than done silently — these are cerberus's own
/// artifacts, but deleting anything on a user's machine should still be
/// visible in the output.
fn remove_legacy(paths: &Paths) -> Vec<String> {
    let dirs = paths
        .legacy_dirs()
        .into_iter()
        .filter(|dir| dir.is_dir() && fs::remove_dir_all(dir).is_ok());
    let files = paths
        .legacy_files()
        .into_iter()
        .filter(|file| fs::remove_file(file).is_ok());
    dirs.chain(files).map(|p| p.display().to_string()).collect()
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

# Off by default: enabling this writes a structured record of every deny/ask
# decision (including the raw command/tool-input text, which can contain
# inline secrets) to ${XDG_STATE_HOME:-~/.local/state}/cerberus/cerberus.db. See
# `cerberus audit --help` and SECURITY.md before turning this on.
[audit]
enabled = false

# Layered policy sources: named, independently syncable rule/policy bundles
# (e.g. a team repo) that stack on top of the rules above. Managed via
# `cerberus source add/remove/list/sync`, not hand-edited here.
# [[sources]]
# name = \"team\"
# git = \"git@example.com:myorg/cerberus-policies.git\"
# ref = \"main\"
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

enum SetupOutcome {
    AlreadyInstalled,
    Created,
    Skipped(String),
    Failed(String),
}

/// Ensures a cupcake project exists at `paths.cupcake_project_root()` so
/// the `policy` head has something to evaluate against. Shells out to
/// `cupcake init --harness claude` when the binary is available; otherwise
/// reports why it couldn't, per the fail-open philosophy (report, don't
/// error out).
///
/// cerberus's own policies do not live here — they're in the global store
/// ([`ensure_cupcake_global`]). This project exists because `cupcake eval`
/// wants one, and it's scaffolded by cupcake rather than by hand so its
/// `system/` entrypoint always matches the installed cupcake version.
///
/// Runs with the same decoy `HOME` as the global init, and cleans up after
/// it: `cupcake init` also writes a `.claude/settings.json` and an
/// `.opencode/plugin/` into the project directory, wiring its own hooks
/// that would double-evaluate cupcake alongside cerberus's. Harmless where
/// they land (a directory cerberus owns, that no harness reads as a project
/// root), but there's no reason to keep them.
fn ensure_cupcake_project(paths: &Paths) -> SetupOutcome {
    let root = paths.cupcake_project_root();
    if policy::project_installed(&root) {
        return SetupOutcome::AlreadyInstalled;
    }
    if !command_exists("cupcake") {
        return SetupOutcome::Skipped("cupcake not on PATH".to_string());
    }
    let decoy_home = paths.cupcake_init_decoy_home();
    if let Err(e) = fs::create_dir_all(&root).and_then(|()| fs::create_dir_all(&decoy_home)) {
        return SetupOutcome::Failed(format!("couldn't create {}: {e}", root.display()));
    }
    let status = Command::new("cupcake")
        .args(["init", "--harness", "claude"])
        .current_dir(&root)
        .env("HOME", &decoy_home)
        .status();
    match status {
        Ok(s) if s.success() && policy::project_installed(&root) => {
            let _ = fs::remove_dir_all(root.join(".claude"));
            let _ = fs::remove_dir_all(root.join(".opencode"));
            SetupOutcome::Created
        }
        Ok(s) => SetupOutcome::Failed(format!("cupcake init exited with {s}")),
        Err(e) => SetupOutcome::Failed(format!("failed to run cupcake init: {e}")),
    }
}

/// Ensures **cerberus's own** cupcake global store exists for the `claude`
/// harness and that cerberus's policies are current inside it. Only ever
/// calls `cupcake init --global` when the store doesn't already have a
/// `claude` harness installed, and only ever writes beneath
/// `paths.cupcake_policies_dir()`.
///
/// This store is cerberus's, not the user's. `XDG_CONFIG_HOME` is pointed
/// at `paths.cupcake_init_xdg_config_home()` (i.e. `~/.config/cerberus`)
/// rather than the user's real config home, because cupcake derives its
/// global root as `$XDG_CONFIG_HOME/cupcake` — so the store lands at
/// `~/.config/cerberus/cupcake/` and the user's own `~/.config/cupcake` is
/// never read or written by cerberus at all. `cupcake eval` is then pointed
/// back at it with `--global-config`.
///
/// `HOME` is pointed at a decoy directory for the same reason it always
/// was, re-confirmed against cupcake 0.5.2: `cupcake init --global` doesn't
/// just scaffold the policy tree, it also tries to auto-wire its *own*
/// independent `PreToolUse` hook (matcher `"*"`, running `cupcake eval`
/// directly) into `$HOME/.claude/settings.json` on its own initiative. Left
/// unchecked that would corrupt the hook entries `settings::install_hooks`
/// owns and double-evaluate cupcake on every guarded call. The decoy `HOME`
/// absorbs that write instead.
///
/// Letting cupcake scaffold the store, rather than cerberus writing it from
/// embedded content, is deliberate: `cupcake init --global` produces
/// `policies/claude/system/evaluate.rego`, the WASM entrypoint the engine
/// compiles against. A hand-rolled copy would pin cerberus to one cupcake
/// version and turn a cupcake upgrade into a silently degraded policy head.
fn ensure_cupcake_global(paths: &Paths) -> SetupOutcome {
    let root = paths.cupcake_global_root();
    let already_installed = policy::global_installed(&root);
    if !already_installed {
        if !command_exists("cupcake") {
            return SetupOutcome::Skipped("cupcake not on PATH".to_string());
        }
        let decoy_home = paths.cupcake_init_decoy_home();
        if let Err(e) = fs::create_dir_all(&decoy_home) {
            return SetupOutcome::Failed(format!("couldn't create {}: {e}", decoy_home.display()));
        }
        let status = Command::new("cupcake")
            .args(["init", "--global", "--harness", "claude"])
            .env("HOME", &decoy_home)
            .env("XDG_CONFIG_HOME", paths.cupcake_init_xdg_config_home())
            .status();
        match status {
            Ok(s) if s.success() && policy::global_installed(&root) => {}
            Ok(s) => return SetupOutcome::Failed(format!("cupcake init --global exited with {s}")),
            Err(e) => {
                return SetupOutcome::Failed(format!("failed to run cupcake init --global: {e}"));
            }
        }
    }
    match write_cupcake_policies(&paths.cupcake_policies_dir()) {
        Ok(_) if already_installed => SetupOutcome::AlreadyInstalled,
        Ok(_) => SetupOutcome::Created,
        Err(e) => SetupOutcome::Failed(format!("couldn't write cerberus's cupcake policies: {e}")),
    }
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

/// Bootstraps everything cerberus needs: writes the rule scripts, seeds a
/// default `config.toml`, ensures cerberus's cupcake project and policy
/// store exist, composes the tirith overlay, and
/// wires `cerberus guard`/`cerberus health` into whichever harnesses are
/// actually present (Claude Code, Codex CLI, Cursor, Hermes, opencode),
/// each behind its own detection check. Running `init` on a machine
/// without a given harness installed doesn't create files for it.
///
/// Prints a summary per artifact as it goes, then one per head (see
/// [`crate::domain::Head`]), so the three-heads structure is visible at setup
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

    let project_outcome = ensure_cupcake_project(paths);
    let cupcake_project_ready = matches!(
        project_outcome,
        SetupOutcome::AlreadyInstalled | SetupOutcome::Created
    );
    match project_outcome {
        SetupOutcome::AlreadyInstalled => println!(
            "cupcake project: already installed at {}",
            paths.cupcake_project_root().display()
        ),
        SetupOutcome::Created => println!(
            "cupcake project: created at {}",
            paths.cupcake_project_root().display()
        ),
        SetupOutcome::Skipped(reason) => {
            problems.push(format!("cupcake project not created: {reason}"))
        }
        SetupOutcome::Failed(reason) => {
            problems.push(format!("cupcake project setup failed: {reason}"))
        }
    }

    let global_outcome = ensure_cupcake_global(paths);
    let cupcake_global_ready = matches!(
        global_outcome,
        SetupOutcome::AlreadyInstalled | SetupOutcome::Created
    );
    let cupcake_policies_installed = if cupcake_global_ready {
        embedded::CUPCAKE_POLICIES.len()
    } else {
        0
    };
    match global_outcome {
        SetupOutcome::AlreadyInstalled => println!(
            "cupcake store: cerberus's {} polic(ies) refreshed at {}",
            cupcake_policies_installed,
            paths.cupcake_policies_dir().display()
        ),
        SetupOutcome::Created => println!(
            "cupcake store: created at {}, cerberus's {} polic(ies) installed",
            paths.cupcake_global_root().display(),
            cupcake_policies_installed
        ),
        SetupOutcome::Skipped(reason) => {
            problems.push(format!("cupcake store not created: {reason}"))
        }
        SetupOutcome::Failed(reason) => {
            problems.push(format!("cupcake store setup failed: {reason}"))
        }
    }

    match ensure_tirith_fragments_dir(paths) {
        Ok(()) => println!(
            "tirith fragments: drop your own *.yaml rules in {}",
            paths.tirith_fragments_dir().display()
        ),
        Err(e) => problems.push(format!(
            "couldn't create {}: {e}",
            paths.tirith_fragments_dir().display()
        )),
    }

    let mut tirith_rule_count = 0;
    let tirith_overlay_written = match risk::write_tirith_overlay(paths) {
        Ok(composed) => {
            tirith_rule_count = composed.rule_count;
            println!(
                "tirith overlay: composed {} rule(s) from cerberus's base + {} layer(s) into {}",
                composed.rule_count,
                composed.layers_merged,
                paths.tirith_overlay_policy_file().display()
            );
            // A bad fragment costs only itself — the base still enforces, so
            // `health`'s canary still passes. Report it here, where it can be
            // fixed, rather than degrading the whole guard over it.
            problems.extend(composed.problems);
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

    for harness in harnesses::all() {
        if harness.detected(paths) {
            problems.extend(harness.install(paths));
        } else {
            println!("{}", harness.skipped());
        }
    }

    let removed = remove_legacy(paths);
    for dir in &removed {
        println!("migration: removed cerberus's former {dir}");
    }

    println!("\nper-head status:");
    println!(
        "  {:<10} ({:<24}) — tirith on PATH: {}, overlay written: {}, {tirith_rule_count} rule(s) composed",
        Head::Risk.name(),
        Head::Risk.purpose(),
        yes_no(tirith_on_path),
        yes_no(tirith_overlay_written)
    );
    println!(
        "  {:<10} ({:<24}) — cupcake project ready: {}, opa on PATH: {}, store ready: {}, \
        cerberus policies installed: {cupcake_policies_installed}",
        Head::Policy.name(),
        Head::Policy.purpose(),
        yes_no(cupcake_project_ready),
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
    fn removes_legacy_state_and_leaves_current_state_alone() {
        let root = tempdir("legacy");
        let paths = Paths {
            state_home: root.join("state"),
            data_home: root.join("data"),
            config_home: root.join("config"),
            cache_home: root.join("cache"),
            home: root.join("home"),
        };
        let state = paths.state_dir();
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(root.join("state/guard")).unwrap();
        fs::write(root.join("state/guard/degraded"), "x").unwrap();
        for name in ["violations-s1.state", "audit.jsonl", "audit.jsonl.1"] {
            fs::write(state.join(name), "x").unwrap();
        }
        for name in ["cerberus.db", "degraded", "violations-notes.txt"] {
            fs::write(state.join(name), "x").unwrap();
        }

        let removed = remove_legacy(&paths);

        assert_eq!(removed.len(), 4, "{removed:?}");
        assert!(!root.join("state/guard").exists());
        for name in ["violations-s1.state", "audit.jsonl", "audit.jsonl.1"] {
            assert!(!state.join(name).exists(), "{name} should be gone");
        }
        for name in ["cerberus.db", "degraded", "violations-notes.txt"] {
            assert!(state.join(name).exists(), "{name} must stay");
        }
        assert!(remove_legacy(&paths).is_empty(), "second run is a no-op");
        fs::remove_dir_all(&root).ok();
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

    fn scratch_paths(name: &str) -> Paths {
        let root = tempdir(name);
        Paths {
            state_home: root.join("state"),
            data_home: root.join("data"),
            config_home: root.join("config"),
            cache_home: root.join("cache"),
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
    fn default_config_parses_to_all_heads_enabled_audit_off_no_sources() {
        let paths = scratch_paths("config-default-parses");
        ensure_config_file(&paths).unwrap();
        assert_eq!(
            crate::config::enabled_heads(&paths),
            vec![Head::Risk, Head::Policy, Head::Judgement],
            "the shipped default must parse, not just fall back to all-enabled"
        );
        assert!(!crate::config::audit_enabled(&paths));
        assert!(crate::config::sources(&paths).is_empty());
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
}
