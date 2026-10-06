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
        self.root.join("state/guard/degraded")
    }

    fn plant_sentinel(&self, reason: &str) {
        let path = self.sentinel();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, reason).unwrap();
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
