//! Binary-level tests: run the real `cerberus` executable against a scratch
//! `HOME` and `XDG_*` tree. `PATH` points at an empty directory, so tirith,
//! cupcake and opa are always absent and the outcome never depends on what
//! happens to be installed on the machine running the tests.

use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "cerberus-commands-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
        Self { root }
    }

    fn sentinel(&self) -> PathBuf {
        self.root.join("state/cerberus/degraded")
    }

    fn plant_sentinel(&self, reason: &str) {
        let path = self.sentinel();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, reason).unwrap();
    }

    /// Puts an executable named `name` on the sandbox's PATH. `body` is a
    /// shell script; it runs with that same near-empty PATH, so it reaches
    /// real tools only by the absolute paths `real` finds.
    fn tool(&self, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = self.root.join("bin").join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cerberus"));
        cmd.args(args)
            .env_clear()
            .env("HOME", self.root.join("home"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env("PATH", self.root.join("bin"));
        // `env_clear` would otherwise drop where `cargo llvm-cov` asks the
        // binary to write its profile, leaving everything these tests run
        // looking uncovered.
        if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
            cmd.env("LLVM_PROFILE_FILE", profile);
        }
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    fn run_with_stdin(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// The absolute path of a real tool on the machine running the tests.
fn real(name: &str) -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
        .unwrap_or_else(|| panic!("{name} not on PATH"))
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout should be JSON")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap()
}

#[test]
fn gate_is_silent_when_nothing_is_degraded() {
    let sandbox = Sandbox::new("gate-silent");
    let output = sandbox.run(&["gate"]);
    assert!(output.status.success());
    assert_eq!(stdout(&output), "");
}

#[test]
fn gate_denies_with_the_recorded_cause_while_degraded() {
    let sandbox = Sandbox::new("gate-denies");
    sandbox.plant_sentinel("policy: opa not on PATH");

    let value = json(&sandbox.run(&["gate"]));
    let decision = &value["hookSpecificOutput"];
    assert_eq!(decision["permissionDecision"], "deny");
    let reason = decision["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("opa not on PATH"), "{reason}");
    assert!(reason.contains("cerberus doctor"), "{reason}");
}

#[test]
fn guard_denies_before_reading_stdin_while_degraded() {
    let sandbox = Sandbox::new("guard-degraded");
    sandbox.plant_sentinel("risk: tirith not on PATH");

    let output = sandbox.run_with_stdin(&["guard"], "");
    let value = json(&output);
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn health_writes_the_sentinel_and_tells_the_session() {
    let sandbox = Sandbox::new("health-writes");

    let output = sandbox.run(&["health"]);

    assert!(output.status.success(), "health always exits 0");
    let value = json(&output);
    assert_eq!(value["hookSpecificOutput"]["hookEventName"], "SessionStart");
    let context = value["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    assert!(context.contains("tirith not on PATH"), "{context}");
    assert!(context.contains("cerberus doctor"), "{context}");
    assert!(read(&sandbox.sentinel()).contains("tirith not on PATH"));
}

#[test]
fn doctor_lists_every_failure_with_a_fix_and_exits_nonzero() {
    let sandbox = Sandbox::new("doctor-fails");

    let output = sandbox.run(&["doctor"]);

    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    for id in [
        "risk.tirith",
        "policy.opa",
        "policy.cupcake",
        "judgement.rules",
    ] {
        assert!(text.contains(id), "missing {id} in:\n{text}");
    }
    assert!(text.contains("fix:"), "{text}");
    assert!(text.contains("Still degraded"), "{text}");
}

#[test]
fn doctor_refreshes_the_sentinel_but_never_clears_it_while_failing() {
    let sandbox = Sandbox::new("doctor-keeps");
    sandbox.plant_sentinel("a stale reason from an earlier run");

    let output = sandbox.run(&["doctor"]);

    assert_eq!(output.status.code(), Some(1));
    let sentinel = read(&sandbox.sentinel());
    assert!(!sentinel.contains("stale reason"), "{sentinel}");
    assert!(sentinel.contains("tirith not on PATH"), "{sentinel}");
    assert!(stdout(&output).contains("a stale reason from an earlier run"));
}

#[test]
fn doctor_json_reports_unhealthy_with_structured_checks() {
    let sandbox = Sandbox::new("doctor-json");

    let output = sandbox.run(&["doctor", "--json"]);

    assert_eq!(output.status.code(), Some(1));
    let value = json(&output);
    assert_eq!(value["healthy"], false);
    let checks = value["checks"].as_array().unwrap();
    let tirith = checks.iter().find(|c| c["id"] == "risk.tirith").unwrap();
    assert_eq!(tirith["status"], "fail");
    assert!(tirith["fix"].is_string());
}

#[test]
fn doctor_warns_about_an_unparseable_config_without_degrading_on_it() {
    let sandbox = Sandbox::new("doctor-config");
    let config = sandbox.root.join("config/cerberus/config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, "this is = = not toml").unwrap();

    let value = json(&sandbox.run(&["doctor", "--json"]));

    let checks = value["checks"].as_array().unwrap();
    let config_check = checks.iter().find(|c| c["id"] == "config").unwrap();
    assert_eq!(config_check["status"], "warn");
}

#[test]
fn guard_counts_allows_without_their_input_and_decisions_reports_them() {
    let sb = Sandbox::new("allow-audit");
    let config = sb.root.join("config/cerberus/config.toml");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, "[audit]\nenabled = true\n").unwrap();

    let payload = r#"{"session_id":"s1","cwd":"/work","tool_name":"Bash","tool_input":{"command":"API_KEY=hunter2 ls -la"}}"#;
    let out = sb.run_with_stdin(&["guard"], payload);
    assert!(stdout(&out).trim().is_empty(), "an allow prints nothing");

    let db = fs::read(sb.root.join("state/cerberus/cerberus.db")).unwrap();
    assert!(
        !String::from_utf8_lossy(&db).contains("hunter2"),
        "allows must not keep tool_input"
    );

    let report = sb.run(&["audit", "decisions"]);
    assert!(report.status.success());
    assert!(stdout(&report).contains("1 allowed, 0 blocked"));
}

#[test]
fn guard_counts_a_deny_per_session_and_violations_prints_it() {
    let sb = Sandbox::new("violations");
    let rules = sb.root.join("config/cerberus/rules");
    fs::create_dir_all(&rules).unwrap();
    fs::write(
        rules.join("tripwire.rhai"),
        r#"fn check(cmd, cwd, input) { if cmd.contains("boom") { "Blocked (T-001): boom" } }"#,
    )
    .unwrap();

    let deny = r#"{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"boom"}}"#;
    for _ in 0..2 {
        let out = sb.run_with_stdin(&["guard"], deny);
        assert!(stdout(&out).contains("deny"), "{}", stdout(&out));
    }

    let counts = sb.run(&["violations", "s1"]);
    assert_eq!(stdout(&counts), "risk=0\npolicy=0\njudgement=2\n");
    let other = sb.run(&["violations", "never-seen"]);
    assert_eq!(stdout(&other), "risk=0\npolicy=0\njudgement=0\n");
}

#[test]
fn decisions_names_the_rule_file_and_drills_down_to_its_calls() {
    let sb = Sandbox::new("drill");
    let config = sb.root.join("config/cerberus/config.toml");
    let rules = sb.root.join("config/cerberus/rules");
    fs::create_dir_all(&rules).unwrap();
    fs::write(&config, "[audit]\nenabled = true\n").unwrap();
    fs::write(
        rules.join("tripwire.rhai"),
        r#"fn check(cmd, cwd, input) { if cmd.contains("boom") { "Blocked (T-001): boom" } }"#,
    )
    .unwrap();
    let deny = r#"{"session_id":"s1","cwd":"/work","tool_name":"Bash","tool_input":{"command":"boom   now"}}"#;
    sb.run_with_stdin(&["guard"], deny);

    let report = stdout(&sb.run(&["audit", "decisions"]));
    assert!(report.contains("rule T-001: 1 blocked"), "{report}");
    assert!(report.contains("tripwire.rhai"), "{report}");

    let rows = stdout(&sb.run(&["audit", "decisions", "T-001"]));
    assert!(rows.contains("1 blocked by T-001"), "{rows}");
    assert!(rows.contains("s1  /work  boom now"), "{rows}");
    assert!(stdout(&sb.run(&["audit", "decisions", "NOPE-9"])).contains("no blocked calls"));

    assert!(stdout(&sb.run(&["audit", "decisions", "--since", "1h"])).contains("1 blocked"));
    let bad = sb.run(&["audit", "decisions", "--since", "soon"]);
    assert_eq!(bad.status.code(), Some(1));
}

#[test]
fn allows_and_rules_surveys_read_the_record() {
    let sb = Sandbox::new("survey");
    let config = sb.root.join("config/cerberus/config.toml");
    let rules = sb.root.join("config/cerberus/rules");
    fs::create_dir_all(&rules).unwrap();
    fs::write(&config, "[audit]\nenabled = true\n").unwrap();
    fs::write(
        rules.join("tripwire.rhai"),
        r#"fn check(cmd, cwd, input) { if cmd.contains("boom") { "Blocked (T-001): boom" } }
// "(T-002)" is declared here but never fires"#,
    )
    .unwrap();

    let call = |command: &str| {
        let payload = format!(
            r#"{{"session_id":"s1","cwd":"/work","tool_name":"Bash","tool_input":{{"command":"{command}"}}}}"#
        );
        sb.run_with_stdin(&["guard"], &payload);
    };
    for _ in 0..21 {
        call("curl https://example.com");
    }
    call("boom");

    let allows = stdout(&sb.run(&["audit", "allows"]));
    assert!(allows.contains("21 allowed"), "{allows}");
    assert!(allows.contains("curl: 21 allowed"), "{allows}");
    assert!(
        allows.contains("the record isn't older than the window"),
        "{allows}"
    );
    assert!(allows.contains("Bash: 21 allowed, 1 blocked"), "{allows}");

    let rules_out = stdout(&sb.run(&["audit", "rules"]));
    assert!(rules_out.contains("T-001: 1 times"), "{rules_out}");
    let silent = rules_out.split("never fired:").nth(1).unwrap();
    assert!(
        silent.contains("T-002") && !silent.contains("T-001"),
        "{rules_out}"
    );
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn init_with_nothing_installed_writes_what_it_can_and_reports_the_rest() {
    let sb = Sandbox::new("init-bare");
    let out = sb.run(&["init"]);
    assert_eq!(out.status.code(), Some(1), "missing tools are problems");
    let text = stdout(&out);
    assert!(text.contains("rule scripts: wrote"), "{text}");
    assert!(text.contains("config: wrote default"), "{text}");
    assert!(text.contains("claude: not on PATH"), "{text}");
    let problems = stderr(&out);
    assert!(problems.contains("tirith not on PATH"), "{problems}");
    assert!(problems.contains("opa"), "{problems}");
    assert!(problems.contains("cupcake not on PATH"), "{problems}");
    assert!(sb.root.join("config/cerberus/config.toml").is_file());
    assert!(
        sb.root
            .join("data/cerberus/tirith/.tirith/policy.yaml")
            .is_file()
    );

    let again = stdout(&sb.run(&["init"]));
    assert!(
        again.contains("existing"),
        "second run leaves config alone: {again}"
    );
}

#[test]
fn init_migrates_legacy_state_and_wires_every_harness_it_finds() {
    let sb = Sandbox::new("init-full");
    let mkdir = real("mkdir");
    let mkdir = mkdir.display();
    // A fake cupcake that scaffolds just what `init` checks for.
    sb.tool(
        "cupcake",
        &format!(
            r#"case "$*" in
  *--global*) {mkdir} -p "$XDG_CONFIG_HOME/cupcake/policies/claude" ;;
  *) {mkdir} -p .cupcake/policies/claude ;;
esac"#
        ),
    );
    for name in ["tirith", "opa", "claude", "codex", "hermes", "opencode"] {
        sb.tool(name, "exit 0");
    }
    fs::create_dir_all(sb.root.join("home/.cursor")).unwrap();
    fs::create_dir_all(sb.root.join("state/guard")).unwrap();
    fs::create_dir_all(sb.root.join("state/cerberus")).unwrap();
    fs::write(sb.root.join("state/cerberus/violations-old.state"), "x").unwrap();

    let out = sb.run(&["init"]);
    let (text, problems) = (stdout(&out), stderr(&out));
    assert_eq!(out.status.code(), Some(0), "{text}\n{problems}");
    assert!(text.contains("cupcake project: created"), "{text}");
    assert!(text.contains("cupcake store: created"), "{text}");
    assert!(text.contains("migration: removed"), "{text}");
    assert!(!sb.root.join("state/guard").exists());
    assert!(!sb.root.join("state/cerberus/violations-old.state").exists());
    for wired in ["home/.claude/settings.json", "home/.cursor/hooks.json"] {
        assert!(sb.root.join(wired).is_file(), "{wired} should be written");
    }

    let again = stdout(&sb.run(&["init"]));
    assert!(
        again.contains("cupcake project: already installed"),
        "{again}"
    );
    assert!(again.contains("refreshed"), "{again}");
}

#[test]
fn init_reports_a_cupcake_that_fails_to_scaffold() {
    let sb = Sandbox::new("init-badcupcake");
    sb.tool("cupcake", "exit 3");
    let out = sb.run(&["init"]);
    let problems = stderr(&out);
    assert!(
        problems.contains("cupcake project setup failed"),
        "{problems}"
    );
    assert!(
        problems.contains("cupcake store setup failed"),
        "{problems}"
    );
}

/// Runs the machine's real git (not the sandbox's) to build an upstream repo.
fn git(dir: &Path, args: &[&str]) {
    let out = Command::new(real("git"))
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
}

#[test]
fn source_add_list_sync_and_remove_round_trip_through_a_local_repo() {
    let sb = Sandbox::new("source");
    std::os::unix::fs::symlink(real("git"), sb.root.join("bin/git")).unwrap();
    std::os::unix::fs::symlink(real("sh"), sb.root.join("bin/sh")).unwrap();

    let upstream = sb.root.join("upstream");
    fs::create_dir_all(upstream.join("rules")).unwrap();
    fs::create_dir_all(upstream.join("policies")).unwrap();
    fs::write(
        upstream.join("rules/team.rhai"),
        r#"fn check(cmd, cwd, input) { if cmd.contains("boom") { "Blocked (TEAM-001): boom" } }"#,
    )
    .unwrap();
    fs::write(
        upstream.join("policies/team.rego"),
        "package cerberus.team\n",
    )
    .unwrap();
    git(&upstream, &["init", "-q", "-b", "main"]);
    git(&upstream, &["add", "."]);
    git(&upstream, &["commit", "-q", "-m", "first"]);
    let url = upstream.to_str().unwrap();

    let added = sb.run(&["source", "add", url, "--name", "team"]);
    assert!(added.status.success(), "{}", stderr(&added));
    assert!(stdout(&added).contains("source 'team' added"));
    assert!(stderr(&added).contains("installed unvalidated"));
    assert!(
        sb.root
            .join("config/cerberus/rules/sources/team/team.rhai")
            .is_file()
    );

    let listed = stdout(&sb.run(&["source", "list"]));
    assert!(
        listed.contains("team") && listed.contains("pinned"),
        "{listed}"
    );

    assert!(stdout(&sb.run(&["source", "sync"])).contains("team: up to date"));

    fs::write(
        upstream.join("rules/more.rhai"),
        "fn check(cmd, cwd, input) { }",
    )
    .unwrap();
    git(&upstream, &["add", "."]);
    git(&upstream, &["commit", "-q", "-m", "second"]);

    let pending = sb.run(&["source", "sync"]);
    assert_eq!(pending.status.code(), Some(1));
    let text = stdout(&pending);
    assert!(text.contains("update available"), "{text}");
    assert!(text.contains("source sync team --yes"), "{text}");

    let applied = stdout(&sb.run(&["source", "sync", "team", "--yes"]));
    assert!(applied.contains("team: updated"), "{applied}");
    assert!(
        sb.root
            .join("config/cerberus/rules/sources/team/more.rhai")
            .is_file()
    );

    assert_eq!(sb.run(&["source", "sync", "nope"]).status.code(), Some(1));
    assert!(stdout(&sb.run(&["source", "remove", "team"])).contains("removed"));
    assert!(!sb.root.join("config/cerberus/rules/sources/team").exists());
    let gone = sb.run(&["source", "remove", "team"]);
    assert_eq!(gone.status.code(), Some(1));
    assert!(stdout(&gone).contains("no source named"));
    assert!(stdout(&sb.run(&["source", "list"])).contains("no policy sources"));
}

#[test]
fn audit_tail_summary_and_export_read_the_same_record() {
    let sb = Sandbox::new("audit-read");
    let rules = sb.root.join("config/cerberus/rules");
    fs::create_dir_all(&rules).unwrap();
    fs::write(
        sb.root.join("config/cerberus/config.toml"),
        "[audit]\nenabled = true\n",
    )
    .unwrap();
    fs::write(
        rules.join("tripwire.rhai"),
        r#"fn check(cmd, cwd, input) { if cmd.contains("boom") { "Blocked (T-001): boom, loudly" } }"#,
    )
    .unwrap();
    let deny =
        r#"{"session_id":"s1","cwd":"/work","tool_name":"Bash","tool_input":{"command":"boom"}}"#;
    sb.run_with_stdin(&["guard"], deny);
    sb.run_with_stdin(&["guard"], deny);

    let tail = stdout(&sb.run(&["audit", "tail", "-n", "1"]));
    assert_eq!(tail.lines().count(), 1, "{tail}");
    assert!(tail.contains("[judgement] Bash deny"), "{tail}");

    let summary = stdout(&sb.run(&["audit", "summary", "--since", "1d"]));
    assert!(summary.contains("2 blocked in the last 1d"), "{summary}");
    assert!(summary.contains("head judgement: 2"), "{summary}");
    assert!(summary.contains("tool Bash: 2"), "{summary}");
    assert!(summary.contains("rule T-001: 2"), "{summary}");
    let bad = sb.run(&["audit", "summary", "--since", "soon"]);
    assert_eq!(bad.status.code(), Some(1));

    let json: Value = serde_json::from_str(&stdout(&sb.run(&["audit", "export"]))).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 2);
    let csv_path = sb.root.join("out.csv");
    let csv = sb.run(&[
        "audit",
        "export",
        "--format",
        "csv",
        "--out",
        csv_path.to_str().unwrap(),
    ]);
    assert!(csv.status.success());
    assert!(read(&csv_path).starts_with("ts,session_id,head"));
    let unwritable = sb.root.join("missing-dir/out.csv");
    let failed = sb.run(&["audit", "export", "--out", unwritable.to_str().unwrap()]);
    assert_eq!(failed.status.code(), Some(1));
    assert!(stderr(&failed).contains("couldn't write export"));
}

#[test]
fn environment_awareness_reads_the_kube_context_and_terraform_workspace() {
    let sb = Sandbox::new("environment");
    sb.run(&["init"]); // writes the shipped rule scripts
    let call = |command: &str| {
        let payload = format!(
            r#"{{"session_id":"s1","cwd":"{}","tool_name":"Bash","tool_input":{{"command":"{command}"}}}}"#,
            sb.root.display()
        );
        stdout(&sb.run_with_stdin(&["guard"], &payload))
    };

    // Neither tool installed: nothing to look up, so nothing to block.
    assert!(call("kubectl delete pod x").trim().is_empty());

    sb.tool("kubectl", "echo prod-east");
    sb.tool("terraform", "echo production");
    assert!(call("kubectl delete pod x").contains("ENV-001"));
    assert!(call("terraform destroy").contains("ENV-002"));
    assert!(call("terraform apply").contains("apply"));

    sb.tool("kubectl", "echo staging");
    sb.tool("terraform", "echo staging");
    assert!(call("kubectl delete pod x").trim().is_empty());
    assert!(call("terraform apply").trim().is_empty());

    sb.tool("kubectl", "exit 1");
    sb.tool("terraform", "exit 1");
    assert!(call("kubectl delete pod x").trim().is_empty());
    assert!(call("terraform apply").trim().is_empty());

    sb.tool("kubectl", "echo ''");
    sb.tool("terraform", "echo ''");
    assert!(call("kubectl delete pod x").trim().is_empty());
    assert!(call("terraform apply").trim().is_empty());
}

#[test]
fn audit_commands_say_so_when_the_database_is_unreadable() {
    let sb = Sandbox::new("audit-broken");
    let db = sb.root.join("state/cerberus/cerberus.db");
    fs::create_dir_all(db.parent().unwrap()).unwrap();
    fs::write(&db, "this is not a database").unwrap();
    for args in [["audit", "tail"], ["audit", "decisions"]] {
        let out = sb.run(&args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(stderr(&out).contains("couldn't read the decision database"));
    }
    let violations = sb.run(&["violations", "s1"]);
    assert_eq!(violations.status.code(), Some(1));
    assert!(stderr(&violations).contains("couldn't read the state database"));
}

#[test]
fn source_add_rejects_what_it_cannot_use() {
    let sb = Sandbox::new("source-bad");
    let bad_spec = sb.run(&["source", "add", "not-a-slug"]);
    assert_eq!(bad_spec.status.code(), Some(1));
    assert!(stderr(&bad_spec).contains("couldn't add source"));

    let no_git = sb.run(&["source", "add", "/nowhere/team"]);
    assert_eq!(no_git.status.code(), Some(1));
    assert!(
        stderr(&no_git).contains("git not on PATH"),
        "{}",
        stderr(&no_git)
    );

    std::os::unix::fs::symlink(real("git"), sb.root.join("bin/git")).unwrap();
    let unreachable = sb.run(&["source", "add", "/nowhere/team"]);
    assert_eq!(unreachable.status.code(), Some(1));
    assert!(stderr(&unreachable).contains("couldn't add source 'team'"));
}

// ---- Fake tirith, cupcake and opa -----------------------------------------
//
// The real tools are installed on a developer machine but not on a CI runner,
// so the code that shells out to them is exercised against stand-ins that
// speak just enough of each protocol. The tests that run the real tools stay
// where they are and skip themselves when the tools are absent.

/// A `tirith` that blocks any command containing `danger` (and the health
/// canary), reports a specific custom rule for `fire:<id>`, and fails to emit
/// JSON for `opaque`. `drift` reports a policy path other than the one
/// requested, which is what makes `risk` re-compose the overlay. `rule
/// validate` rejects any policy containing the word INVALID.
fn fake_tirith(sb: &Sandbox) {
    let cat = real("cat").display().to_string();
    sb.tool(
        "tirith",
        &format!(
            r#"case "$1" in
rule)
  case "$({cat} "$4")" in *INVALID*) echo "bad policy" >&2; exit 2 ;; esac
  exit 0 ;;
check)
  for a; do cmd="$a"; done
  used=""
  [ -n "${{TIRITH_POLICY_ROOT:-}}" ] && used="$TIRITH_POLICY_ROOT/.tirith/policy.yaml"
  case "$cmd" in
    fire:*)
      id="${{cmd#fire:}}"
      echo '{{"findings":[{{"rule_id":"custom_rule_match","custom_rule_id":"'"$id"'","severity":"HIGH","title":"fires"}}],"policy_path_used":"'"$used"'"}}'
      exit 1 ;;
    opaque) exit 1 ;;
    drift) echo '{{"findings":[],"policy_path_used":"/elsewhere/policy.yaml"}}'; exit 0 ;;
    *danger*|"rm -rf /home/guard-health/.config/cerberus")
      echo '{{"findings":[{{"rule_id":"curl_pipe_shell","severity":"CRITICAL","title":"Danger","description":"line one\n  line two"}}],"policy_path_used":"'"$used"'"}}'
      exit 1 ;;
  esac
  echo '{{"findings":[],"policy_path_used":"'"$used"'"}}' ;;
esac"#
        ),
    );
}

/// A `cupcake` that scaffolds what `init` checks for, denies the two health
/// canaries, asks for `askme`, and fails or prints nothing for `crash` and
/// `emptyout`.
fn fake_cupcake(sb: &Sandbox) {
    let cat = real("cat").display().to_string();
    let mkdir = real("mkdir").display().to_string();
    sb.tool(
        "cupcake",
        &format!(
            r#"case "$1" in
init)
  case "$*" in
    *--global*) {mkdir} -p "$XDG_CONFIG_HOME/cupcake/policies/claude" ;;
    *) {mkdir} -p .cupcake/policies/claude ;;
  esac ;;
eval)
  input=$({cat})
  case "$input" in
    *'rm -rf /"'*|*sandbox-integrity.rhai*)
      echo '{{"hookSpecificOutput":{{"permissionDecision":"deny","permissionDecisionReason":"CERB-POL-004: fake"}}}}' ;;
    *askme*) echo '{{"hookSpecificOutput":{{"permissionDecision":"ask","permissionDecisionReason":"CERB-POL-002: fake"}}}}' ;;
    *crash*) exit 1 ;;
    *emptyout*) ;;
    *) echo '{{"hookSpecificOutput":{{"permissionDecision":"allow"}}}}' ;;
  esac ;;
esac"#
        ),
    );
}

fn guard_call(sb: &Sandbox, cwd: &Path, command: &str) -> String {
    let payload = format!(
        r#"{{"session_id":"s1","cwd":"{}","tool_name":"Bash","tool_input":{{"command":"{command}"}}}}"#,
        cwd.display()
    );
    stdout(&sb.run_with_stdin(&["guard"], &payload))
}

#[test]
fn guard_runs_risk_and_policy_through_the_tools_it_finds() {
    let sb = Sandbox::new("toolchain-guard");
    fake_tirith(&sb);
    fake_cupcake(&sb);
    sb.tool("opa", "exit 0");
    assert_eq!(sb.run(&["init"]).status.code(), Some(0));
    let cwd = &sb.root;

    // risk: tirith's finding, with its severity, title, tidy description and rule id.
    let risk = guard_call(&sb, cwd, "do danger now");
    assert!(
        risk.contains("Blocked by tirith: [CRITICAL] Danger"),
        "{risk}"
    );
    assert!(risk.contains("line one line two"), "{risk}");
    assert!(risk.contains("(rule: curl_pipe_shell)"), "{risk}");
    // tirith failing without any JSON still blocks, with the generic reason.
    assert!(guard_call(&sb, cwd, "opaque").contains("Blocked by tirith: dangerous command"));
    // A custom rule is named by its own id, not tirith's generic one.
    assert!(guard_call(&sb, cwd, "fire:team-rule").contains("(rule: team-rule)"));
    // An overlay that tirith reports not using is recomposed, then the verdict stands.
    assert!(guard_call(&sb, cwd, "drift").trim().is_empty());

    // A repo with its own tirith policy is judged by that, not cerberus's overlay.
    let repo = sb.root.join("repo");
    fs::create_dir_all(repo.join(".tirith")).unwrap();
    fs::write(repo.join(".tirith/policy.yaml"), "paranoia: 1\n").unwrap();
    assert!(guard_call(&sb, &repo, "do danger now").contains("Blocked by tirith"));

    // policy: cupcake's verdict is passed through when it isn't an allow.
    assert!(guard_call(&sb, cwd, "askme").contains("CERB-POL-002"));
    assert!(guard_call(&sb, cwd, "crash").trim().is_empty());
    assert!(guard_call(&sb, cwd, "emptyout").trim().is_empty());
    assert!(guard_call(&sb, cwd, "ls").trim().is_empty());
}

#[test]
fn doctor_passes_when_every_canary_is_blocked_and_names_each_one_that_is_not() {
    let sb = Sandbox::new("toolchain-doctor");
    fake_tirith(&sb);
    fake_cupcake(&sb);
    sb.tool("opa", "exit 0");
    sb.run(&["init"]);
    let healthy = sb.run(&["doctor", "--json"]);
    let report = json(&healthy);
    assert_eq!(report["healthy"], true, "{report}");
    assert_eq!(healthy.status.code(), Some(0));
    assert!(sb.run(&["health"]).status.success());

    // A tirith that blocks nothing and a cupcake that allows everything.
    sb.tool("tirith", "echo '{\"findings\":[]}'");
    let cat = real("cat").display().to_string();
    sb.tool(
        "cupcake",
        &format!(
            r#"{cat} > /dev/null; echo '{{"hookSpecificOutput":{{"permissionDecision":"allow"}}}}'"#
        ),
    );
    let sick = sb.run(&["doctor"]);
    assert_eq!(sick.status.code(), Some(1));
    let text = format!("{}{}", stdout(&sick), stderr(&sick));
    assert!(text.contains("tirith overlay did not block"), "{text}");
    assert!(text.contains("cupcake did not block"), "{text}");
}

#[test]
fn source_content_is_validated_by_opa_and_tirith_before_it_installs() {
    let sb = Sandbox::new("toolchain-source");
    fake_tirith(&sb);
    sb.tool(
        "opa",
        "case \"$*\" in *reject*) echo 'rego error' >&2; exit 1 ;; esac; exit 0",
    );
    std::os::unix::fs::symlink(real("git"), sb.root.join("bin/git")).unwrap();
    std::os::unix::fs::symlink(real("sh"), sb.root.join("bin/sh")).unwrap();

    let make_repo = |name: &str, fragment: &str, rego: &str| -> String {
        let repo = sb.root.join(name);
        fs::create_dir_all(repo.join("tirith")).unwrap();
        fs::create_dir_all(repo.join("policies")).unwrap();
        fs::write(repo.join("tirith/frag.yaml"), fragment).unwrap();
        fs::write(repo.join("policies/p.rego"), rego).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "init"]);
        repo.to_str().unwrap().to_string()
    };

    // A rule that fires for its own example installs quietly; one that never
    // does installs with a warning saying it enforces nothing.
    let good = make_repo(
        "good",
        "custom_rules:\n  - id: fires\n    context: [exec]\n    pattern: 'a'\n    examples_bad: ['fire:team-fires']\n  - id: silent\n    context: [exec]\n    pattern: 'b'\n    examples_bad: ['nothing']\n",
        "package team\n",
    );
    let added = sb.run(&["source", "add", &good, "--name", "team"]);
    assert!(added.status.success(), "{}", stderr(&added));
    let warnings = stderr(&added);
    assert!(
        warnings.contains("rule 'team-silent' did not fire"),
        "{warnings}"
    );
    assert!(!warnings.contains("team-fires"), "{warnings}");
    assert!(!warnings.contains("unvalidated"), "both validators ran");

    // A policy opa rejects, or a tirith fragment tirith rejects, aborts the add.
    let bad_rego = make_repo("badrego", "custom_rules: []\n", "package reject\n");
    let rejected = sb.run(&["source", "add", &bad_rego, "--name", "reject"]);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(
        stderr(&rejected).contains("failed opa validation"),
        "{}",
        stderr(&rejected)
    );
    let bad_yaml = make_repo(
        "badyaml",
        "custom_rules:\n  - id: INVALID\n    context: [exec]\n    pattern: 'x'\n",
        "package ok\n",
    );
    let rejected = sb.run(&["source", "add", &bad_yaml, "--name", "badyaml"]);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(
        stderr(&rejected).contains("failed tirith validation"),
        "{}",
        stderr(&rejected)
    );

    // A fragment that tries to loosen the base policy is refused up front.
    let loosen = make_repo(
        "loosen",
        "fail_mode: closed\ncustom_rules: []\n",
        "package ok\n",
    );
    let refused = sb.run(&["source", "add", &loosen, "--name", "loosen"]);
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
}
