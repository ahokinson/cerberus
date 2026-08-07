use crate::embedded;
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
    let cupcake_ready = matches!(
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

    match settings::install_hooks(paths) {
        Ok(report) => {
            if report.pretooluse_bash_changed {
                println!("settings.json: PreToolUse Bash hook now runs `cerberus guard`");
            } else {
                println!("settings.json: PreToolUse Bash hook already up to date");
            }
            if report.sessionstart_health_inserted {
                println!("settings.json: added `cerberus health` to SessionStart");
            } else {
                println!("settings.json: `cerberus health` already wired into SessionStart");
            }
        }
        Err(e) => problems.push(format!(
            "couldn't update {}: {e}",
            paths.claude_settings_json().display()
        )),
    }

    println!("\nper-head status:");
    println!(
        "  {:<10} ({:<24}) — tirith on PATH: {}",
        Head::Risk.name(),
        Head::Risk.purpose(),
        yes_no(tirith_on_path)
    );
    println!(
        "  {:<10} ({:<24}) — cupcake stub ready: {}, opa on PATH: {}",
        Head::Policy.name(),
        Head::Policy.purpose(),
        yes_no(cupcake_ready),
        yes_no(opa_on_path)
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
}
