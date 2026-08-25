use super::{environment, git, shell, tool};
use crate::process::command_exists;
use rhai::{AST, Array, Dynamic, Engine, Map, Scope};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn strings_from_array(arr: Array) -> Vec<String> {
    arr.into_iter()
        .filter_map(|d| d.into_string().ok())
        .collect()
}

fn array_from_strings(items: Vec<String>) -> Array {
    items.into_iter().map(Dynamic::from).collect()
}

/// Converts a script-side value back to `serde_json`, so the `tool_*`
/// natives can reuse `rules::tool` rather than reimplementing its key
/// lookups against Rhai's map type. Failure yields `Value::Null`, which
/// those helpers already read as "names nothing" — fail-open per rule, like
/// everything else here.
fn dynamic_to_json(value: &Dynamic) -> Value {
    rhai::serde::from_dynamic(value).unwrap_or(Value::Null)
}

/// Builds the Rhai engine rule scripts run under: registers every
/// native function a `.rhai` rule may call, wrapping the existing
/// `rules::git`/`rules::environment`/`rules::shell` helpers rather than
/// reimplementing any of their parsing or subprocess logic (see
/// `CONTRIBUTING.md`). The fiddly parsing (tokenizing, walking git's global
/// flags, classifying checkout/switch/restore flags) stays in Rust and is
/// exposed pre-structured (`git_invocations`, `git_parse_checkout_args`) so
/// scripts only have to express situational judgement.
pub fn build_engine() -> Engine {
    let mut engine = Engine::new();

    engine.register_fn("tokenize", |cmd: &str| -> Array {
        array_from_strings(shell::tokenize(cmd))
    });

    engine.register_fn("command_exists", |name: &str| -> bool {
        command_exists(name)
    });

    // `guard` runs on every mutating tool, not just Bash, and each tool
    // names the thing it acts on under a different `tool_input` key. These
    // two hand a script the paths and URL already normalized, so a rule
    // about a sensitive path doesn't need a branch per tool. They take the
    // whole `input` map (rather than a pre-extracted value) so a script
    // calls them the same way it reads any other payload field.
    engine.register_fn("tool_paths", |input: Dynamic| -> Array {
        array_from_strings(tool::paths(&dynamic_to_json(&input)))
    });

    engine.register_fn("tool_url", |input: Dynamic| -> String {
        tool::url(&dynamic_to_json(&input)).unwrap_or_default()
    });

    engine.register_fn("git_is_inside_work_tree", |cwd: &str| -> bool {
        git::is_inside_work_tree(Path::new(cwd))
    });

    engine.register_fn("git_tree_dirty", |cwd: &str| -> bool {
        git::tree_is_dirty(Path::new(cwd))
    });

    engine.register_fn("git_would_discard", |cwd: &str, pathspecs: Array| -> bool {
        git::would_discard(Path::new(cwd), &strings_from_array(pathspecs))
    });

    engine.register_fn(
        "git_is_ancestor",
        |cwd: &str, ancestor: &str, descendant: &str| -> bool {
            git::is_ancestor(Path::new(cwd), ancestor, descendant)
        },
    );

    engine.register_fn("git_ref_exists", |cwd: &str, refname: &str| -> bool {
        git::ref_exists(Path::new(cwd), refname)
    });

    engine.register_fn(
        "git_ref_exists_as_branch",
        |cwd: &str, name: &str| -> bool { git::ref_exists_as_branch(Path::new(cwd), name) },
    );

    // Empty string stands in for "none" (no upstream / detached HEAD):
    // simpler and less error-prone for script authors than modeling
    // Option<T> across the Rust/Rhai boundary.
    engine.register_fn("git_upstream_ref", |cwd: &str| -> String {
        git::upstream_ref(Path::new(cwd)).unwrap_or_default()
    });

    engine.register_fn("git_current_branch", |cwd: &str| -> String {
        git::current_branch(Path::new(cwd)).unwrap_or_default()
    });

    engine.register_fn(
        "git_clean_dry_run",
        |cwd: &str, extra_args: Array| -> String {
            git::clean_dry_run(Path::new(cwd), &strings_from_array(extra_args))
        },
    );

    engine.register_fn("git_invocations", |cmd: &str| -> Array {
        let tokens = shell::tokenize(cmd);
        git::find_git_invocations(&tokens)
            .into_iter()
            .map(|invocation| {
                let mut map = Map::new();
                map.insert("subcommand".into(), Dynamic::from(invocation.subcommand));
                map.insert(
                    "args".into(),
                    Dynamic::from(array_from_strings(invocation.args)),
                );
                Dynamic::from(map)
            })
            .collect()
    });

    engine.register_fn("git_parse_checkout_args", |args: Array| -> Map {
        let parsed = git::parse_args(&strings_from_array(args));
        let mut map = Map::new();
        map.insert("creating".into(), Dynamic::from(parsed.creating));
        map.insert("staged".into(), Dynamic::from(parsed.staged));
        map.insert("worktree".into(), Dynamic::from(parsed.worktree));
        map.insert("dashdash".into(), Dynamic::from(parsed.dashdash));
        map.insert(
            "target".into(),
            Dynamic::from(parsed.target.unwrap_or_default()),
        );
        map.insert(
            "pathspecs".into(),
            Dynamic::from(array_from_strings(parsed.pathspecs)),
        );
        map
    });

    engine.register_fn("kube_context", || -> String {
        environment::kube_context().unwrap_or_default()
    });

    engine.register_fn("terraform_workspace", |cwd: &str| -> String {
        environment::terraform_workspace(Path::new(cwd)).unwrap_or_default()
    });

    engine.register_fn("looks_like_production", |name: &str| -> bool {
        environment::looks_like_production(name)
    });

    engine
}

/// Compiles every `*.rhai` file in `dir`, in sorted (deterministic) order.
/// A file that fails to compile is skipped, not fatal: matches every other
/// head's fail-open-per-check contract. A single broken rule script must
/// never take down the whole `judgement` head.
pub fn load_rules(engine: &Engine, dir: &Path) -> Vec<(String, AST)> {
    let mut rules = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return rules;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("rhai"))
        .collect();
    paths.sort();

    for path in paths {
        let Ok(src) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(ast) = engine.compile(&src) else {
            continue;
        };
        let name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("rule")
            .to_string();
        rules.push((name, ast));
    }
    rules
}

/// Loads every rule script in `dir` and runs each one's `check(cmd, cwd,
/// input)` function in turn, returning the first deny reason. `input` is
/// the full hook payload, converted once to a Rhai `Dynamic` so a script
/// can reach any field directly (e.g.
/// `input.tool_input.dangerouslyDisableSandbox`) without a new Rust
/// accessor per field. A script that returns a string denies; anything
/// else (including `()`, the implicit return of a function with no
/// `return`) allows. A runtime error (missing `check` function, type
/// mismatch, etc.) also just allows, per rule, same as [`load_rules`]'s
/// handling of a script that won't even compile.
pub fn evaluate(dir: &Path, cmd: &str, cwd: &Path, input: &Value) -> Option<String> {
    let engine = build_engine();
    let rules = load_rules(&engine, dir);
    if rules.is_empty() {
        return None;
    }

    let input_dynamic: Dynamic = rhai::serde::to_dynamic(input).unwrap_or(Dynamic::UNIT);
    let cwd_str = cwd.to_string_lossy().to_string();

    for (_name, ast) in &rules {
        let mut scope = Scope::new();
        let result = engine.call_fn::<Dynamic>(
            &mut scope,
            ast,
            "check",
            (cmd.to_string(), cwd_str.clone(), input_dynamic.clone()),
        );
        if let Ok(value) = result
            && let Ok(reason) = value.into_string()
        {
            return Some(reason);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn shipped_rule_scripts_compile() {
        let engine = build_engine();
        for src in [
            include_str!("../../rules/git-safety.rhai"),
            include_str!("../../rules/environment-awareness.rhai"),
            include_str!("../../rules/release-hygiene.rhai"),
            include_str!("../../rules/sandbox-integrity.rhai"),
        ] {
            engine.compile(src).unwrap();
        }
    }

    fn shipped_rules_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules")
    }

    #[test]
    fn sandbox_integrity_denies_the_dangerously_disable_sandbox_flag() {
        let input = serde_json::json!({
            "tool_input": {"command": "ls", "dangerouslyDisableSandbox": true}
        });
        let reason = evaluate(&shipped_rules_dir(), "ls", Path::new("/tmp"), &input);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("SANDBOX-001")),
            "expected a SANDBOX-001 deny, got {reason:?}"
        );
    }

    #[test]
    fn sandbox_integrity_allows_ordinary_bash_calls() {
        let input = serde_json::json!({"tool_input": {"command": "ls -la"}});
        assert_eq!(
            evaluate(&shipped_rules_dir(), "ls -la", Path::new("/tmp"), &input),
            None
        );
    }

    #[test]
    fn sandbox_integrity_denies_editing_the_sandbox_config_in_settings_json() {
        let input = serde_json::json!({"tool_input": {"command": "irrelevant"}});
        let cmd = "sed -i 's/\"sandbox\": {\"enabled\": true}/\"sandbox\": {\"enabled\": false}/' ~/.claude/settings.json";
        let reason = evaluate(&shipped_rules_dir(), cmd, Path::new("/tmp"), &input);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("SANDBOX-002")),
            "expected a SANDBOX-002 deny, got {reason:?}"
        );
    }

    #[test]
    fn sandbox_integrity_allows_reading_settings_json() {
        let input = serde_json::json!({"tool_input": {"command": "irrelevant"}});
        let cmd = "cat ~/.claude/settings.json | grep sandbox";
        assert_eq!(
            evaluate(&shipped_rules_dir(), cmd, Path::new("/tmp"), &input),
            None
        );
    }

    // ─── SANDBOX-003: the tool-shaped version of the same bypass. Before
    // guard ran on anything but Bash, reaching for Edit instead of `sed`
    // walked straight past SANDBOX-002.

    fn write_event(path: &str) -> Value {
        serde_json::json!({ "tool_name": "Write", "tool_input": { "file_path": path } })
    }

    #[test]
    fn sandbox_integrity_denies_writing_to_claude_settings_json() {
        for tool in ["Write", "Edit", "NotebookEdit"] {
            let input = serde_json::json!({
                "tool_name": tool,
                "tool_input": { "file_path": "/home/someone/.claude/settings.json" }
            });
            let reason = evaluate(&shipped_rules_dir(), "", Path::new("/tmp"), &input);
            assert!(
                reason.as_deref().is_some_and(|r| r.contains("SANDBOX-003")),
                "expected a SANDBOX-003 deny for {tool}, got {reason:?}"
            );
        }
    }

    #[test]
    fn sandbox_integrity_denies_writing_to_a_project_settings_local_json() {
        let input = write_event("/repo/.claude/settings.local.json");
        let reason = evaluate(&shipped_rules_dir(), "", Path::new("/tmp"), &input);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("SANDBOX-003")),
            "expected a SANDBOX-003 deny, got {reason:?}"
        );
    }

    #[test]
    fn sandbox_integrity_survives_an_event_with_no_tool_name() {
        // SANDBOX-003 reads `input.tool_name`, which is `()` when absent. If
        // comparing that against a string threw, the whole script would error
        // and fail open — silently taking SANDBOX-001 and -002 down with it.
        // Reaching a SANDBOX-002 deny proves execution got past that line.
        let input = serde_json::json!({ "tool_input": { "command": "irrelevant" } });
        let cmd = "sed -i 's/enabled/disabled/' ~/.claude/settings.json # sandbox";
        let reason = evaluate(&shipped_rules_dir(), cmd, Path::new("/tmp"), &input);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("SANDBOX-002")),
            "expected a SANDBOX-002 deny, got {reason:?}"
        );
    }

    #[test]
    fn sandbox_integrity_allows_writing_to_an_unrelated_path() {
        let input = write_event("/repo/src/main.rs");
        assert_eq!(
            evaluate(&shipped_rules_dir(), "", Path::new("/tmp"), &input),
            None
        );
    }

    #[test]
    fn sandbox_integrity_allows_reading_settings_json_with_the_read_tool() {
        // Read names a `file_path` too, and reading the file is fine. Only
        // the writing tools are denied.
        let input = serde_json::json!({
            "tool_name": "Read",
            "tool_input": { "file_path": "/home/someone/.claude/settings.json" }
        });
        assert_eq!(
            evaluate(&shipped_rules_dir(), "", Path::new("/tmp"), &input),
            None
        );
    }

    #[test]
    fn the_other_shipped_rules_stay_silent_on_a_non_bash_tool() {
        // Non-Bash calls reach the scripts with `cmd == ""`. The three
        // command-oriented rules must go inert rather than misfire on it, so
        // that widening guard beyond Bash didn't quietly change their
        // behavior. Uses a repo path so git-safety's cwd checks are live.
        let dir = init_git_repo();
        let input = write_event(&dir.join("file.txt").to_string_lossy());
        assert_eq!(evaluate(&shipped_rules_dir(), "", &dir, &input), None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sandbox_integrity_allows_unrelated_settings_json_edits() {
        let input = serde_json::json!({"tool_input": {"command": "irrelevant"}});
        let cmd = "sed -i 's/dark/light/' ~/.claude/settings.json";
        assert_eq!(
            evaluate(&shipped_rules_dir(), cmd, Path::new("/tmp"), &input),
            None
        );
    }

    // ─── git-safety.rhai: exercised end-to-end through engine::evaluate
    // against the real shipped script, verified against actual git
    // behavior rather than mocked, per CONTRIBUTING.md.

    fn init_git_repo() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cerberus-git-safety-rhai-test-{}-{}",
            std::process::id(),
            fastrand()
        ));
        fs::create_dir_all(&dir).unwrap();
        // -b main, not bare `init`: the initial branch name otherwise comes
        // from the ambient init.defaultBranch, so these fixtures would pass
        // or fail depending on whose gitconfig is in scope.
        run_git(&dir, &["init", "-q", "-b", "main"]);
        run_git(&dir, &["config", "user.email", "test@example.com"]);
        run_git(&dir, &["config", "user.name", "Test"]);
        fs::write(dir.join("file.txt"), "one\n").unwrap();
        run_git(&dir, &["add", "."]);
        run_git(&dir, &["commit", "-q", "-m", "initial"]);
        dir
    }

    fn run_git(dir: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {:?} failed in {:?}", args, dir);
    }

    fn empty_input() -> Value {
        serde_json::json!({"tool_input": {"command": "irrelevant"}})
    }

    #[test]
    fn git_safety_denies_switch_with_dirty_tree() {
        let dir = init_git_repo();
        fs::write(dir.join("file.txt"), "two\n").unwrap();
        run_git(&dir, &["branch", "other"]);
        let input = empty_input();
        let reason = evaluate(&shipped_rules_dir(), "git switch other", &dir, &input);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("CONTEXT-001")),
            "expected a CONTEXT-001 deny, got {reason:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn git_safety_allows_switch_creating_a_branch_even_when_dirty() {
        let dir = init_git_repo();
        fs::write(dir.join("file.txt"), "two\n").unwrap();
        let input = empty_input();
        assert_eq!(
            evaluate(
                &shipped_rules_dir(),
                "git switch -c new-branch",
                &dir,
                &input
            ),
            None
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn git_safety_denies_checkout_that_would_discard_changes() {
        let dir = init_git_repo();
        fs::write(dir.join("file.txt"), "two\n").unwrap();
        let input = empty_input();
        let reason = evaluate(
            &shipped_rules_dir(),
            "git checkout -- file.txt",
            &dir,
            &input,
        );
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("CONTEXT-002")),
            "expected a CONTEXT-002 deny, got {reason:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn git_safety_allows_restore_staged_only() {
        let dir = init_git_repo();
        fs::write(dir.join("file.txt"), "two\n").unwrap();
        run_git(&dir, &["add", "."]);
        let input = empty_input();
        assert_eq!(
            evaluate(
                &shipped_rules_dir(),
                "git restore --staged file.txt",
                &dir,
                &input
            ),
            None
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn git_safety_denies_force_deleting_a_branch_with_unmerged_commits() {
        let dir = init_git_repo();
        run_git(&dir, &["checkout", "-q", "-b", "feature"]);
        fs::write(dir.join("file.txt"), "feature work\n").unwrap();
        run_git(&dir, &["add", "."]);
        run_git(&dir, &["commit", "-q", "-m", "feature commit"]);
        run_git(&dir, &["checkout", "-q", "-"]);
        let input = empty_input();
        let reason = evaluate(&shipped_rules_dir(), "git branch -D feature", &dir, &input);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("CONTEXT-004")),
            "expected a CONTEXT-004 deny, got {reason:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn git_safety_allows_deleting_a_merged_branch() {
        let dir = init_git_repo();
        run_git(&dir, &["branch", "feature"]);
        let input = empty_input();
        assert_eq!(
            evaluate(&shipped_rules_dir(), "git branch -D feature", &dir, &input),
            None
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn git_safety_denies_clean_force_when_it_would_remove_files() {
        let dir = init_git_repo();
        fs::write(dir.join("untracked.txt"), "scratch\n").unwrap();
        let input = empty_input();
        let reason = evaluate(&shipped_rules_dir(), "git clean -f", &dir, &input);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("CONTEXT-007")),
            "expected a CONTEXT-007 deny, got {reason:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn git_safety_allows_clean_dry_run() {
        let dir = init_git_repo();
        fs::write(dir.join("untracked.txt"), "scratch\n").unwrap();
        let input = empty_input();
        assert_eq!(
            evaluate(&shipped_rules_dir(), "git clean -f -n", &dir, &input),
            None
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn git_safety_allows_unrelated_commands() {
        let dir = init_git_repo();
        let input = empty_input();
        assert_eq!(evaluate(&shipped_rules_dir(), "ls -la", &dir, &input), None);
        fs::remove_dir_all(&dir).ok();
    }

    fn init_repo_with_remote() -> (PathBuf, PathBuf) {
        let remote = std::env::temp_dir().join(format!(
            "cerberus-git-safety-rhai-remote-{}-{}",
            std::process::id(),
            fastrand()
        ));
        fs::create_dir_all(&remote).unwrap();
        // Must match the `HEAD:main` push below. A bare repo's HEAD points at
        // its initial branch, and a clone whose remote HEAD names a ref that
        // doesn't exist checks out nothing, which fails the commit later.
        run_git(&remote, &["init", "-q", "--bare", "-b", "main"]);

        let local = init_git_repo();
        run_git(
            &local,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        run_git(&local, &["push", "-q", "-u", "origin", "HEAD:main"]);
        (local, remote)
    }

    #[test]
    fn git_safety_denies_force_push_that_would_discard_remote_commits() {
        let (local, remote) = init_repo_with_remote();
        let other = std::env::temp_dir().join(format!(
            "cerberus-git-safety-rhai-other-{}-{}",
            std::process::id(),
            fastrand()
        ));
        run_git(
            Path::new("."),
            &[
                "clone",
                "-q",
                remote.to_str().unwrap(),
                other.to_str().unwrap(),
            ],
        );
        fs::write(other.join("file.txt"), "teammate change\n").unwrap();
        run_git(&other, &["config", "user.email", "test@example.com"]);
        run_git(&other, &["config", "user.name", "Test"]);
        run_git(&other, &["commit", "-q", "-am", "teammate commit"]);
        run_git(&other, &["push", "-q"]);
        run_git(&local, &["fetch", "-q"]);

        let input = empty_input();
        let reason = evaluate(&shipped_rules_dir(), "git push -f", &local, &input);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("CONTEXT-003")),
            "expected a CONTEXT-003 deny, got {reason:?}"
        );

        fs::remove_dir_all(&local).ok();
        fs::remove_dir_all(&remote).ok();
        fs::remove_dir_all(&other).ok();
    }

    #[test]
    fn git_safety_allows_fast_forward_force_push() {
        let (local, remote) = init_repo_with_remote();
        fs::write(local.join("file.txt"), "new local work\n").unwrap();
        run_git(&local, &["commit", "-q", "-am", "local commit"]);
        let input = empty_input();
        assert_eq!(
            evaluate(&shipped_rules_dir(), "git push -f", &local, &input),
            None
        );
        fs::remove_dir_all(&local).ok();
        fs::remove_dir_all(&remote).ok();
    }

    #[test]
    fn git_safety_denies_rebase_rewriting_pushed_head() {
        let (local, remote) = init_repo_with_remote();
        let input = empty_input();
        let reason = evaluate(&shipped_rules_dir(), "git rebase main", &local, &input);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("CONTEXT-005")),
            "expected a CONTEXT-005 deny, got {reason:?}"
        );
        fs::remove_dir_all(&local).ok();
        fs::remove_dir_all(&remote).ok();
    }

    #[test]
    fn git_safety_denies_amend_rewriting_pushed_head() {
        let (local, remote) = init_repo_with_remote();
        let input = empty_input();
        let reason = evaluate(&shipped_rules_dir(), "git commit --amend", &local, &input);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("CONTEXT-006")),
            "expected a CONTEXT-006 deny, got {reason:?}"
        );
        fs::remove_dir_all(&local).ok();
        fs::remove_dir_all(&remote).ok();
    }

    #[test]
    fn git_safety_allows_amend_of_an_unpushed_commit() {
        let (local, remote) = init_repo_with_remote();
        fs::write(local.join("file.txt"), "unpushed\n").unwrap();
        run_git(&local, &["commit", "-q", "-am", "unpushed commit"]);
        let input = empty_input();
        assert_eq!(
            evaluate(&shipped_rules_dir(), "git commit --amend", &local, &input),
            None
        );
        fs::remove_dir_all(&local).ok();
        fs::remove_dir_all(&remote).ok();
    }

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cerberus-engine-test-{}-{name}-{}",
            std::process::id(),
            fastrand()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fastrand() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos() as u64;
        nanos.wrapping_mul(1_000_003).wrapping_add(n)
    }

    fn write_rule(dir: &Path, filename: &str, src: &str) {
        fs::write(dir.join(filename), src).unwrap();
    }

    #[test]
    fn evaluate_allows_when_rules_dir_is_missing() {
        let dir = std::env::temp_dir().join("cerberus-engine-test-nonexistent");
        let input = serde_json::json!({});
        assert_eq!(evaluate(&dir, "ls -la", Path::new("/tmp"), &input), None);
    }

    #[test]
    fn evaluate_allows_when_no_script_denies() {
        let dir = tempdir("allow");
        write_rule(&dir, "noop.rhai", "fn check(cmd, cwd, input) { }");
        let input = serde_json::json!({});
        assert_eq!(evaluate(&dir, "ls -la", Path::new("/tmp"), &input), None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn evaluate_denies_when_a_script_returns_a_string() {
        let dir = tempdir("deny");
        write_rule(
            &dir,
            "deny.rhai",
            r#"fn check(cmd, cwd, input) { "Blocked (TEST-001): nope" }"#,
        );
        let input = serde_json::json!({});
        assert_eq!(
            evaluate(&dir, "ls -la", Path::new("/tmp"), &input),
            Some("Blocked (TEST-001): nope".to_string())
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn evaluate_fails_open_on_a_script_runtime_error() {
        let dir = tempdir("broken");
        write_rule(&dir, "broken.rhai", "fn check(cmd, cwd, input) { 1/0 }");
        let input = serde_json::json!({});
        assert_eq!(evaluate(&dir, "ls -la", Path::new("/tmp"), &input), None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn evaluate_fails_open_on_a_script_that_does_not_compile() {
        let dir = tempdir("uncompilable");
        write_rule(
            &dir,
            "bad.rhai",
            "fn check(cmd, cwd, input) { this is not rhai !! ",
        );
        write_rule(
            &dir,
            "still-runs.rhai",
            r#"fn check(cmd, cwd, input) { "Blocked (TEST-002): still runs" }"#,
        );
        let input = serde_json::json!({});
        assert_eq!(
            evaluate(&dir, "ls -la", Path::new("/tmp"), &input),
            Some("Blocked (TEST-002): still runs".to_string())
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn evaluate_stops_at_the_first_deny_in_sorted_file_order() {
        let dir = tempdir("order");
        write_rule(
            &dir,
            "a-first.rhai",
            r#"fn check(cmd, cwd, input) { "Blocked (TEST-A)" }"#,
        );
        write_rule(
            &dir,
            "b-second.rhai",
            r#"fn check(cmd, cwd, input) { "Blocked (TEST-B)" }"#,
        );
        let input = serde_json::json!({});
        assert_eq!(
            evaluate(&dir, "ls -la", Path::new("/tmp"), &input),
            Some("Blocked (TEST-A)".to_string())
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scripts_can_read_the_command_cwd_and_hook_input() {
        let dir = tempdir("context");
        write_rule(
            &dir,
            "echo.rhai",
            r#"
            fn check(cmd, cwd, input) {
                if cmd == "danger" && cwd == "/repo" && input.tool_input.dangerouslyDisableSandbox == true {
                    "Blocked (TEST-CTX)"
                }
            }
            "#,
        );
        let input = serde_json::json!({"tool_input": {"dangerouslyDisableSandbox": true}});
        assert_eq!(
            evaluate(&dir, "danger", Path::new("/repo"), &input),
            Some("Blocked (TEST-CTX)".to_string())
        );
        let safe_input = serde_json::json!({"tool_input": {"dangerouslyDisableSandbox": false}});
        assert_eq!(
            evaluate(&dir, "danger", Path::new("/repo"), &safe_input),
            None
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_json_fields_read_as_unit_not_a_runtime_error() {
        // Most Bash calls have no `dangerouslyDisableSandbox` field at all.
        // sandbox-integrity.rhai's `input.tool_input.dangerouslyDisableSandbox
        // == true` must stay false (and not blow up the whole script) for
        // every ordinary command, not just ones where the field is present
        // and false.
        let dir = tempdir("missing-field");
        write_rule(
            &dir,
            "check.rhai",
            r#"
            fn check(cmd, cwd, input) {
                if input.tool_input.dangerouslyDisableSandbox == true {
                    "Blocked (TEST-MISSING)"
                }
            }
            "#,
        );
        let input = serde_json::json!({"tool_input": {"command": "ls"}});
        assert_eq!(evaluate(&dir, "ls", Path::new("/tmp"), &input), None);
        let bare_input = serde_json::json!({});
        assert_eq!(evaluate(&dir, "ls", Path::new("/tmp"), &bare_input), None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tool_paths_and_tool_url_are_available_to_scripts() {
        let dir = tempdir("tool-natives");
        write_rule(
            &dir,
            "tool.rhai",
            r#"
            fn check(cmd, cwd, input) {
                let paths = tool_paths(input);
                if paths.len() == 1 && paths[0] == "/x/y" && tool_url(input) == "" {
                    "Blocked (TEST-TOOL)"
                }
            }
            "#,
        );
        let input = serde_json::json!({
            "tool_name": "Write", "tool_input": { "file_path": "/x/y" }
        });
        assert_eq!(
            evaluate(&dir, "", Path::new("/tmp"), &input),
            Some("Blocked (TEST-TOOL)".to_string())
        );

        let fetch = serde_json::json!({
            "tool_name": "WebFetch", "tool_input": { "url": "https://example.com" }
        });
        assert_eq!(evaluate(&dir, "", Path::new("/tmp"), &fetch), None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tokenize_is_available_to_scripts() {
        let dir = tempdir("tokenize");
        write_rule(
            &dir,
            "tok.rhai",
            r#"
            fn check(cmd, cwd, input) {
                let tokens = tokenize(cmd);
                if tokens.len() == 3 {
                    "Blocked (TEST-TOK)"
                }
            }
            "#,
        );
        let input = serde_json::json!({});
        assert_eq!(
            evaluate(&dir, "git checkout main", Path::new("/tmp"), &input),
            Some("Blocked (TEST-TOK)".to_string())
        );
        fs::remove_dir_all(&dir).ok();
    }
}
