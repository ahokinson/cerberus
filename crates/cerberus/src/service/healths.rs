use crate::config;
use crate::config::Paths;
use crate::domain::{Check, Head, Status};
use crate::domain::{is_deny, sessionstart_context};
use crate::heads::judgement::engine;
use crate::heads::{policy, risk};
use crate::ports::Environment;
use crate::process::command_exists;
use serde_json::json;
use std::fs;
use std::io::Write;

/// End-to-end canary: feeds a known halt command (`rm -rf /`) through the
/// real cupcake evaluation and asserts it denies. Exercises the whole path
/// (cerberus's cupcake project, cupcake eval, opa/WASM, cerberus's own
/// policy store), calling [`policy::evaluate`] directly instead of
/// spawning a subprocess of this same binary.
fn canary_blocked(paths: &Paths) -> bool {
    let event = json!({
        "session_id": "guard-health",
        "transcript_path": "/dev/null",
        "cwd": paths.home.to_string_lossy(),
        "permission_mode": "bypassPermissions",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "rm -rf /" },
    })
    .to_string();
    policy::evaluate(paths, &event).is_some_and(|out| is_deny(&out))
}

/// Canary for the policy head's **global-store** content specifically, as
/// opposed to [`canary_blocked`], which only proves cupcake itself is wired
/// up and enforcing (cupcake's stock builtins already block `rm -rf /` on
/// their own, so reusing that event here would pass even with cerberus's
/// own policies fully stripped out). Uses a synthetic `Write` to cerberus's
/// own rule-scripts path, which only `guard-self-protection.rego`
/// (CERB-POL-004) has any reason to deny — nothing in cupcake's stock
/// builtins knows about cerberus's paths, so a pass here is attributable
/// specifically to cerberus's own shipped content.
fn global_policy_canary_blocked(paths: &Paths) -> bool {
    let event = json!({
        "session_id": "guard-health",
        "transcript_path": "/dev/null",
        "cwd": paths.home.to_string_lossy(),
        "permission_mode": "bypassPermissions",
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": paths.rule_scripts_dir().join("sandbox-integrity.rhai").to_string_lossy(),
        },
    })
    .to_string();
    policy::evaluate(paths, &event).is_some_and(|out| is_deny(&out))
}

/// Canary for the risk head's shipped overlay content
/// (`policies/tirith/policy.yaml`). Unlike `judgement`'s and `policy`'s
/// canaries, `risk` had no content of its own to verify before this — only
/// `command_exists("tirith")` was checked. Uses [`risk::overlay_blocks`]
/// to force cerberus's overlay regardless of `health`'s own `cwd`, proving
/// the overlay is present, valid, and live rather than just that tirith
/// itself is installed.
fn tirith_overlay_canary_blocked(paths: &Paths) -> bool {
    risk::overlay_blocks(paths, "rm -rf /home/guard-health/.config/cerberus")
}

/// True if the shipped `sandbox-integrity.rhai` rule (or an equivalent rule)
/// actually denies both ways an agent could weaken its own sandbox. These
/// are the rule-script head's canaries, matching `canary_blocked`'s role for
/// cupcake: rule scripts live on disk rather than being compiled into the
/// binary (see `Paths::rule_scripts_dir`), so a rule an agent edited or
/// deleted out from under the guard has to be caught here, at `SessionStart`,
/// instead of silently degrading enforcement. [`crate::gate`] turns a failed
/// canary into "block every guarded tool until repaired."
///
/// There are two because there are two shapes of the same attack, and
/// covering one proves nothing about the other. SANDBOX-001 is the Bash
/// tool's `dangerouslyDisableSandbox` flag; SANDBOX-003 is a file-writing
/// tool pointed at a Claude `settings.json`, which is the whole reason
/// `guard` runs on more than Bash.
fn rule_scripts_canary_blocked(rules_dir: &std::path::Path) -> bool {
    let disable_flag = json!({
        "session_id": "guard-health",
        "tool_name": "Bash",
        "tool_input": { "command": "ls", "dangerouslyDisableSandbox": true },
    });
    let settings_write = json!({
        "session_id": "guard-health",
        "tool_name": "Write",
        "tool_input": { "file_path": "/home/guard-health/.claude/settings.json" },
    });
    let root = std::path::Path::new("/");
    engine::evaluate(rules_dir, "ls", root, &disable_flag).is_some()
        && engine::evaluate(rules_dir, "", root, &settings_write).is_some()
}

/// Separated from [`collect_problems`] so it's testable without tirith,
/// cupcake, or opa installed: takes just the rules directory, not the full
/// environment.
fn rule_scripts_problem(rules_dir: &std::path::Path) -> Option<String> {
    let has_rule_scripts = fs::read_dir(rules_dir)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .any(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("rhai"))
        })
        .unwrap_or(false);
    if !has_rule_scripts {
        return Some(format!(
            "{} rule scripts directory missing or empty ({}), no personal rules are enforcing",
            Head::Judgement.label(),
            rules_dir.display()
        ));
    }
    if !rule_scripts_canary_blocked(rules_dir) {
        return Some(format!(
            "{} rule scripts did not block a known-dangerous call \
            (dangerouslyDisableSandbox, or a write to a Claude settings.json), \
            guard not enforcing",
            Head::Judgement.label()
        ));
    }
    None
}

fn binary_check(
    env: &dyn Environment,
    head: Head,
    id: &'static str,
    bin: &str,
    problem: &str,
) -> Check {
    if env.command_exists(bin) {
        Check::ok(Some(head), id, format!("{bin} on PATH"))
    } else {
        Check::fail(head, id, problem).fix(format!(
            "install {bin}, or fix the PATH the hook runs under (the nix wrapper provides it)"
        ))
    }
}

/// Runs every probe independently, so one failure never hides another.
/// Only checks a head's binaries and canary if it's actually in the enabled
/// stack. A disabled head isn't degraded, it's off on purpose, so `health`
/// shouldn't complain about it. A canary whose prerequisite already failed
/// is skipped: it would only fail again for the same reason.
pub fn collect_checks(paths: &Paths, env: &dyn Environment) -> Vec<Check> {
    let mut checks = Vec::new();
    let enabled = config::enabled_heads(paths);

    if enabled.contains(&Head::Risk) {
        let tirith = binary_check(
            env,
            Head::Risk,
            "risk.tirith",
            "tirith",
            "tirith not on PATH",
        );
        let have_tirith = tirith.status == Status::Ok;
        checks.push(tirith);
        if !have_tirith {
            checks.push(Check::skip(Head::Risk, "risk.overlay", "tirith missing"));
        } else if env.tirith_overlay_blocks() {
            checks.push(Check::ok(
                Some(Head::Risk),
                "risk.overlay",
                "tirith overlay blocks the canary",
            ));
        } else {
            let overlay = paths.tirith_overlay_policy_file();
            let state = if overlay.is_file() {
                "exists"
            } else {
                "missing"
            };
            checks.push(
                Check::fail(
                    Head::Risk,
                    "risk.overlay",
                    "tirith overlay did not block a known-dangerous command \
                    (cerberus-guard-self-tamper), guard not enforcing",
                )
                .detail(format!("overlay: {} ({state})", overlay.display()))
                .fix("cerberus init (recomposes the overlay)"),
            );
        }
    }

    if enabled.contains(&Head::Policy) {
        let opa = binary_check(
            env,
            Head::Policy,
            "policy.opa",
            "opa",
            "opa (cupcake's Rego engine) not on PATH",
        );
        let cupcake_bin = binary_check(
            env,
            Head::Policy,
            "policy.cupcake",
            "cupcake",
            "cupcake not on PATH",
        );
        let have_cupcake = cupcake_bin.status == Status::Ok;
        let runnable = have_cupcake && opa.status == Status::Ok;
        checks.push(opa);
        checks.push(cupcake_bin);

        let project = paths.cupcake_project_root();
        let global = paths.cupcake_global_root();
        let project_ok = env.cupcake_project_installed();
        let global_ok = env.cupcake_global_installed();

        if have_cupcake {
            checks.push(if project_ok {
                Check::ok(
                    Some(Head::Policy),
                    "policy.project",
                    "cupcake project installed",
                )
            } else {
                Check::fail(
                    Head::Policy,
                    "policy.project",
                    format!(
                        "cupcake project missing ({}/.cupcake), run `cerberus init`",
                        project.display()
                    ),
                )
                .fix("cerberus init")
            });
        }
        checks.push(if !(runnable && project_ok) {
            Check::skip(
                Head::Policy,
                "policy.canary",
                "opa, cupcake or its project missing",
            )
        } else if env.cupcake_blocks_halt() {
            Check::ok(
                Some(Head::Policy),
                "policy.canary",
                "cupcake blocks a halt command",
            )
        } else {
            Check::fail(
                Head::Policy,
                "policy.canary",
                "cupcake did not block a known-dangerous command (rm -rf /), guard \
                not enforcing",
            )
            .detail(format!("project: {}", project.display()))
            .fix("cerberus init")
        });
        if have_cupcake {
            checks.push(if global_ok {
                Check::ok(
                    Some(Head::Policy),
                    "policy.store",
                    "cerberus's cupcake store installed",
                )
            } else {
                Check::fail(
                    Head::Policy,
                    "policy.store",
                    format!(
                        "cerberus's cupcake store missing ({}), run `cerberus init`",
                        global.display()
                    ),
                )
                .fix("cerberus init")
            });
        }
        checks.push(if !(runnable && project_ok && global_ok) {
            Check::skip(
                Head::Policy,
                "policy.self_protection",
                "a prerequisite failed",
            )
        } else if env.cupcake_blocks_self_write() {
            Check::ok(
                Some(Head::Policy),
                "policy.self_protection",
                "cerberus's policies block the canary write",
            )
        } else {
            Check::fail(
                Head::Policy,
                "policy.self_protection",
                "cerberus's own cupcake policies did not block a known-dangerous \
                write (guard-self-protection), guard not enforcing",
            )
            .detail(format!("store: {}", global.display()))
            .fix("cerberus init (rewrites the shipped policies)")
        });
    }

    if enabled.contains(&Head::Judgement) {
        let dir = paths.rule_scripts_dir();
        checks.push(match env.rule_scripts_problem() {
            Some(summary) => {
                let mut check = Check::new(
                    Some(Head::Judgement),
                    "judgement.rules",
                    Status::Fail,
                    summary,
                );
                check = check
                    .detail(format!("rules dir: {}", dir.display()))
                    .fix("cerberus init (restores the shipped rule scripts)");
                check
            }
            None => Check::ok(
                Some(Head::Judgement),
                "judgement.rules",
                "rule scripts load and block the canaries",
            ),
        });
    }

    checks
}

/// The sentinel text: every failed check's summary, in order.
pub fn problems_of(checks: &[Check]) -> Vec<String> {
    checks
        .iter()
        .filter(|c| c.status == Status::Fail)
        .map(|c| c.summary.clone())
        .collect()
}

/// The real machine: PATH lookups, the filesystem, and the actual canaries.
pub struct System<'a>(pub &'a Paths);

impl Environment for System<'_> {
    fn command_exists(&self, bin: &str) -> bool {
        command_exists(bin)
    }

    fn tirith_overlay_blocks(&self) -> bool {
        tirith_overlay_canary_blocked(self.0)
    }

    fn cupcake_project_installed(&self) -> bool {
        policy::project_installed(&self.0.cupcake_project_root())
    }

    fn cupcake_global_installed(&self) -> bool {
        policy::global_installed(&self.0.cupcake_global_root())
    }

    fn cupcake_blocks_halt(&self) -> bool {
        canary_blocked(self.0)
    }

    fn cupcake_blocks_self_write(&self) -> bool {
        global_policy_canary_blocked(self.0)
    }

    fn rule_scripts_problem(&self) -> Option<String> {
        rule_scripts_problem(&self.0.rule_scripts_dir())
    }
}

fn collect_problems(paths: &Paths) -> Vec<String> {
    problems_of(&collect_checks(paths, &System(paths)))
}

pub fn run(paths: &Paths) {
    report(
        &paths.degraded_sentinel(),
        &collect_problems(paths),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
}

/// Does the actual reporting given the sentinel path and the
/// already-collected problems. [`collect_problems`] is the part that probes
/// the real environment for tirith/opa/cupcake; keeping that out of this
/// function is what makes the write-vs-clear and message-shape logic here
/// unit-testable on its own.
pub fn report(
    sentinel: &std::path::Path,
    problems: &[String],
    out: &mut impl Write,
    err: &mut impl Write,
) {
    if problems.is_empty() {
        let _ = fs::remove_file(sentinel);
        return;
    }

    let joined = problems.join(" · ");
    if let Some(parent) = sentinel.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(sentinel, &joined);
    let _ = writeln!(err, "agent guard health check failed: {joined}");
    let message = format!(
        "Security guard degraded: {joined}. bypassPermissions is active and every guarded tool \
        (Bash, Write, Edit, NotebookEdit, WebFetch, MCP) is now gated fail-closed until the \
        guard is repaired. Repair with `cerberus init`, then restart. Run `cerberus doctor` in a terminal to \
        diagnose and retest."
    );
    let _ = writeln!(out, "{}", sessionstart_context(&message));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;
    use std::path::PathBuf;

    fn rule_scripts_tempdir(name: &str) -> PathBuf {
        let dir = temp_dir().join(format!(
            "cerberus-health-rule-scripts-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn scratch_paths(name: &str) -> Paths {
        let root = temp_dir().join(format!(
            "cerberus-health-config-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        Paths {
            state_home: root.join("state"),
            data_home: root.join("data"),
            config_home: root.join("config"),
            cache_home: root.join("cache"),
            home: root.join("home"),
        }
    }

    struct FakeEnv {
        binaries: &'static [&'static str],
        overlay: bool,
        project: bool,
        global: bool,
        halt: bool,
        self_write: bool,
        rules: Option<String>,
    }

    impl FakeEnv {
        fn healthy() -> Self {
            Self {
                binaries: &["tirith", "opa", "cupcake"],
                overlay: true,
                project: true,
                global: true,
                halt: true,
                self_write: true,
                rules: None,
            }
        }
    }

    impl Environment for FakeEnv {
        fn command_exists(&self, bin: &str) -> bool {
            self.binaries.contains(&bin)
        }
        fn tirith_overlay_blocks(&self) -> bool {
            self.overlay
        }
        fn cupcake_project_installed(&self) -> bool {
            self.project
        }
        fn cupcake_global_installed(&self) -> bool {
            self.global
        }
        fn cupcake_blocks_halt(&self) -> bool {
            self.halt
        }
        fn cupcake_blocks_self_write(&self) -> bool {
            self.self_write
        }
        fn rule_scripts_problem(&self) -> Option<String> {
            self.rules.clone()
        }
    }

    fn status_of(checks: &[Check], id: &str) -> Status {
        checks.iter().find(|c| c.id == id).unwrap().status
    }

    #[test]
    fn a_healthy_environment_has_no_problems() {
        let paths = scratch_paths("fake-healthy");
        let checks = collect_checks(&paths, &FakeEnv::healthy());
        assert!(problems_of(&checks).is_empty(), "{checks:?}");
    }

    #[test]
    fn independent_policy_failures_are_all_reported() {
        let paths = scratch_paths("fake-independent");
        let env = FakeEnv {
            binaries: &["tirith", "cupcake"],
            project: false,
            global: false,
            ..FakeEnv::healthy()
        };
        let checks = collect_checks(&paths, &env);

        assert_eq!(status_of(&checks, "policy.opa"), Status::Fail);
        assert_eq!(status_of(&checks, "policy.project"), Status::Fail);
        assert_eq!(status_of(&checks, "policy.store"), Status::Fail);
        // Both canaries need opa, the project and the store, so neither runs.
        assert_eq!(status_of(&checks, "policy.canary"), Status::Skip);
        assert_eq!(status_of(&checks, "policy.self_protection"), Status::Skip);
        assert_eq!(problems_of(&checks).len(), 3);
    }

    #[test]
    fn a_missing_tirith_skips_its_overlay_canary() {
        let paths = scratch_paths("fake-no-tirith");
        let env = FakeEnv {
            binaries: &["opa", "cupcake"],
            overlay: false,
            ..FakeEnv::healthy()
        };
        let checks = collect_checks(&paths, &env);
        assert_eq!(status_of(&checks, "risk.tirith"), Status::Fail);
        assert_eq!(status_of(&checks, "risk.overlay"), Status::Skip);
    }

    #[test]
    fn a_failing_canary_is_a_fail_with_a_fix() {
        let paths = scratch_paths("fake-canary");
        let env = FakeEnv {
            halt: false,
            overlay: false,
            ..FakeEnv::healthy()
        };
        let checks = collect_checks(&paths, &env);
        for id in ["policy.canary", "risk.overlay"] {
            let check = checks.iter().find(|c| c.id == id).unwrap();
            assert_eq!(check.status, Status::Fail, "{id}");
            assert!(check.fix.is_some(), "{id} should say how to fix it");
        }
    }

    #[test]
    fn a_judgement_problem_is_reported_verbatim() {
        let paths = scratch_paths("fake-judgement");
        let env = FakeEnv {
            rules: Some("judgement (x): rule scripts directory missing or empty".into()),
            ..FakeEnv::healthy()
        };
        let problems = problems_of(&collect_checks(&paths, &env));
        assert_eq!(
            problems,
            vec!["judgement (x): rule scripts directory missing or empty".to_string()]
        );
    }

    #[test]
    fn collect_problems_skips_disabled_heads() {
        let paths = scratch_paths("skip-disabled");
        fs::create_dir_all(paths.config_file().parent().unwrap()).unwrap();
        fs::write(
            paths.config_file(),
            "[heads]\nrisk = { disabled = true }\npolicy = { disabled = true }\n",
        )
        .unwrap();

        let problems = collect_problems(&paths);

        assert!(
            !problems
                .iter()
                .any(|p| p.contains("tirith") || p.contains("cupcake") || p.contains("opa")),
            "expected no risk/policy problems when both are disabled, got {problems:?}"
        );
        let _ = fs::remove_dir_all(paths.config_home.parent().unwrap_or(&paths.config_home));
    }

    #[test]
    fn rule_scripts_problem_reports_a_missing_rules_dir() {
        let dir = rule_scripts_tempdir("missing");
        let problem = rule_scripts_problem(&dir);
        assert!(
            problem
                .as_deref()
                .is_some_and(|p| p.contains("missing or empty")),
            "expected a missing-rules-dir problem, got {problem:?}"
        );
    }

    #[test]
    fn rule_scripts_problem_reports_an_empty_rules_dir() {
        let dir = rule_scripts_tempdir("empty");
        fs::create_dir_all(&dir).unwrap();
        let problem = rule_scripts_problem(&dir);
        assert!(
            problem
                .as_deref()
                .is_some_and(|p| p.contains("missing or empty")),
            "expected a missing-rules-dir problem, got {problem:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rule_scripts_problem_reports_a_failing_canary() {
        let dir = rule_scripts_tempdir("broken-canary");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("noop.rhai"), "fn check(cmd, cwd, input) { }").unwrap();
        let problem = rule_scripts_problem(&dir);
        assert!(
            problem
                .as_deref()
                .is_some_and(|p| p.contains("dangerouslyDisableSandbox")),
            "expected a failing-canary problem, got {problem:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rule_scripts_problem_reports_a_rule_that_only_covers_the_bash_bypass() {
        // The realistic degradation now that guard runs on more than Bash:
        // SANDBOX-001 survives but the tool-shaped SANDBOX-003 has been
        // stripped out, leaving the Edit-tool bypass wide open. One canary
        // passing must not be enough.
        let dir = rule_scripts_tempdir("half-canary");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("partial.rhai"),
            r#"fn check(cmd, cwd, input) {
                if input.tool_input.dangerouslyDisableSandbox == true { return "Blocked"; }
            }"#,
        )
        .unwrap();
        let problem = rule_scripts_problem(&dir);
        assert!(
            problem
                .as_deref()
                .is_some_and(|p| p.contains("settings.json")),
            "expected a failing-canary problem, got {problem:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rule_scripts_problem_is_none_when_the_real_sandbox_integrity_rule_is_present() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules");
        assert_eq!(rule_scripts_problem(&dir), None);
    }

    fn tempdir(name: &str) -> PathBuf {
        let root = temp_dir().join(format!(
            "cerberus-health-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn writes_sentinel_and_reports_problems_when_any_exist() {
        let root = tempdir("with-problems");
        let sentinel = root.join("guard").join("degraded");
        let problems = vec!["tirith (command scanner) not on PATH".to_string()];
        let mut out = Vec::new();
        let mut err = Vec::new();
        report(&sentinel, &problems, &mut out, &mut err);

        assert!(sentinel.is_file());
        let written = fs::read_to_string(&sentinel).unwrap();
        assert!(written.contains("not on PATH"));

        let printed = String::from_utf8(out).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(printed.trim()).unwrap();
        assert_eq!(
            parsed["hookSpecificOutput"]["hookEventName"],
            "SessionStart"
        );
        assert!(
            parsed["hookSpecificOutput"]["additionalContext"]
                .as_str()
                .unwrap()
                .contains("Security guard degraded")
        );

        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("agent guard health check failed")
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn clears_a_stale_sentinel_and_prints_nothing_when_no_problems() {
        let root = tempdir("clears-sentinel");
        let sentinel = root.join("guard").join("degraded");
        fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        fs::write(&sentinel, "stale reason").unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        report(&sentinel, &[], &mut out, &mut err);

        assert!(!sentinel.exists());
        assert!(out.is_empty());
        assert!(err.is_empty());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn joins_multiple_problems_with_a_middle_dot() {
        let root = tempdir("multi-problem");
        let sentinel = root.join("guard").join("degraded");
        let problems = vec!["a".to_string(), "b".to_string()];
        let mut out = Vec::new();
        let mut err = Vec::new();
        report(&sentinel, &problems, &mut out, &mut err);
        assert_eq!(fs::read_to_string(&sentinel).unwrap(), "a · b");
        fs::remove_dir_all(&root).ok();
    }
}
