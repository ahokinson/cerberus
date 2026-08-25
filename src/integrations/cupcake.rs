use crate::hook::permission_decision;
use crate::process::command_exists;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

/// cupcake needs a project `.cupcake/` in the working directory; the real
/// rules live in the global store and apply on top. Spawns
/// `cupcake eval --harness claude` from the stub, feeding it the raw hook
/// event JSON. Returns `None` on any failure (missing binary, non-zero
/// exit, empty output), so a broken layer never blocks work.
fn spawn_eval(stub_dir: &Path, input_json: &str) -> Option<String> {
    let mut child = Command::new("cupcake")
        .args(["eval", "--harness", "claude"])
        .current_dir(stub_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    child.stdin.take()?.write_all(input_json.as_bytes()).ok()?;

    let mut out = String::new();
    child.stdout.take()?.read_to_string(&mut out).ok()?;
    let status = child.wait().ok()?;

    if !status.success() || out.is_empty() {
        return None;
    }
    Some(out)
}

/// True if `stub_dir` has a real cupcake project set up for the `claude`
/// harness (i.e. `cupcake init --harness claude` has been run there).
/// Shared by [`evaluate`], `health`'s problem collection, and `init`'s
/// bootstrap check, so there's exactly one definition of "installed."
pub fn stub_installed(stub_dir: &Path) -> bool {
    stub_dir.join(".cupcake/policies/claude").is_dir()
}

/// True if `root` has a real cupcake **global** project for the `claude`
/// harness (i.e. `cupcake init --global --harness claude` has been run).
/// Mirrors [`stub_installed`]'s shape but checks the global store's layout
/// (`policies/claude/`, no `.cupcake/` prefix) rather than the project
/// stub's. Shared by `init`'s bootstrap check and `health`'s canary.
pub fn global_installed(root: &Path) -> bool {
    root.join("policies/claude").is_dir()
}

/// True if `output`'s decision is present and isn't `"allow"`, meaning
/// cupcake wants Claude Code to see this response (`deny`, `ask`, or any
/// future decision kind) rather than a mechanical no-op that `guard` should
/// silently move past on its way to the next head.
fn wants_to_respond(output: &str) -> bool {
    permission_decision(output).is_some_and(|d| d != "allow")
}

/// The `policy` part of `guard`: policy evaluation via the `cupcake`
/// binary. Returns cupcake's own output verbatim whenever it wants to
/// respond (deny or ask); `None` (missing binary, stub not installed, eval
/// failure, or an explicit/absent allow) means `guard` moves on to the next
/// head.
pub fn evaluate(stub_dir: &Path, raw_input: &str) -> Option<String> {
    if !command_exists("cupcake") {
        return None;
    }
    if !stub_installed(stub_dir) {
        return None;
    }
    let out = spawn_eval(stub_dir, raw_input)?;
    if wants_to_respond(&out) {
        Some(out)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::is_deny;
    use serde_json::json;
    use std::env::temp_dir;
    use std::fs;

    /// Cheap syntax check for every shipped policy: only needs `opa`, not a
    /// full cupcake project. Complements the end-to-end test below, which
    /// needs `cupcake` too and is far more expensive to run.
    #[test]
    fn shipped_cupcake_policies_pass_opa_check() {
        if !command_exists("opa") {
            eprintln!("skipping: opa not on PATH");
            return;
        }
        let policies_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("policies/cupcake");
        for (name, _) in crate::embedded::CUPCAKE_POLICIES {
            let status = Command::new("opa")
                .arg("check")
                .arg(policies_dir.join(name))
                .status()
                .expect("failed to run opa check");
            assert!(status.success(), "opa check failed for {name}");
        }
    }

    /// End-to-end: real `cupcake init --global`, real `cupcake eval`, real
    /// `opa`/WASM compilation, fully isolated from the developer's actual
    /// `~/.config/cupcake` via a scratch `XDG_CONFIG_HOME` and a decoy
    /// `HOME` (mirrors `init::ensure_cupcake_global`'s own isolation, for
    /// the same reason: `cupcake init --global` auto-wires its own hook
    /// into `$HOME/.claude/settings.json` otherwise). One deny event and
    /// one clearly-benign counterpart per shipped policy, asserted against
    /// the real `permissionDecisionReason` text rather than mocked.
    #[test]
    fn shipped_cupcake_policies_evaluate_correctly_end_to_end() {
        if !command_exists("cupcake") || !command_exists("opa") {
            eprintln!("skipping: cupcake and/or opa not on PATH");
            return;
        }

        let root = temp_dir().join(format!("cerberus-cupcake-e2e-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let xdg_config_home = root.join("config");
        let decoy_home = root.join("decoy-home");
        let project_dir = root.join("project");
        fs::create_dir_all(&xdg_config_home).unwrap();
        fs::create_dir_all(&decoy_home).unwrap();
        fs::create_dir_all(&project_dir).unwrap();

        let global_init = Command::new("cupcake")
            .args(["init", "--global", "--harness", "claude"])
            .env("HOME", &decoy_home)
            .env("XDG_CONFIG_HOME", &xdg_config_home)
            .status()
            .expect("failed to run cupcake init --global");
        assert!(global_init.success(), "cupcake init --global failed");

        let custom_dir = xdg_config_home.join("cupcake/policies/claude/custom/cerberus");
        fs::create_dir_all(&custom_dir).unwrap();
        for (name, contents) in crate::embedded::CUPCAKE_POLICIES {
            fs::write(custom_dir.join(name), contents).unwrap();
        }

        let project_init = Command::new("cupcake")
            .args(["init", "--harness", "claude"])
            .current_dir(&project_dir)
            .env("HOME", &decoy_home)
            .status()
            .expect("failed to run cupcake init (project)");
        assert!(project_init.success(), "cupcake init (project) failed");

        let run_eval = |event: &serde_json::Value| -> String {
            let mut child = Command::new("cupcake")
                .args(["eval", "--harness", "claude", "--log-level", "error"])
                .current_dir(&project_dir)
                .env("XDG_CONFIG_HOME", &xdg_config_home)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("failed to spawn cupcake eval");
            child
                .stdin
                .take()
                .unwrap()
                .write_all(event.to_string().as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            String::from_utf8(out.stdout).unwrap()
        };

        let event = |tool: &str, tool_input: serde_json::Value| {
            json!({
                "session_id": "t",
                "transcript_path": "/dev/null",
                "cwd": project_dir.to_string_lossy(),
                "hook_event_name": "PreToolUse",
                "tool_name": tool,
                "tool_input": tool_input,
            })
        };

        // CERB-POL-001: sandbox-integrity.rego
        let out = run_eval(&event(
            "Bash",
            json!({"command": "ls", "dangerouslyDisableSandbox": true}),
        ));
        assert!(
            is_deny(&out) && out.contains("dangerouslyDisableSandbox"),
            "{out}"
        );
        let out = run_eval(&event("Bash", json!({"command": "ls -la"})));
        assert!(!is_deny(&out), "expected allow, got {out}");

        // CERB-POL-002: webfetch-ssrf.rego
        let out = run_eval(&event(
            "WebFetch",
            json!({"url": "http://169.254.169.254/latest/meta-data/"}),
        ));
        assert!(is_deny(&out) && out.contains("SSRF"), "{out}");
        let out = run_eval(&event("WebFetch", json!({"url": "https://example.com"})));
        assert!(!is_deny(&out), "expected allow, got {out}");

        // CERB-POL-003: ci-trust-boundary.rego
        let out = run_eval(&event(
            "Write",
            json!({"file_path": "/repo/.github/workflows/ci.yml"}),
        ));
        assert!(is_deny(&out) && out.contains("CI/CD"), "{out}");
        let out = run_eval(&event("Write", json!({"file_path": "/repo/src/main.rs"})));
        assert!(!is_deny(&out), "expected allow, got {out}");

        // CERB-POL-004: guard-self-protection.rego
        let out = run_eval(&event(
            "Write",
            json!({"file_path": "/home/x/.config/cerberus/rules/sandbox-integrity.rhai"}),
        ));
        assert!(
            is_deny(&out) && out.contains("cerberus's, tirith's, or cupcake's"),
            "{out}"
        );
        let out = run_eval(&event("Write", json!({"file_path": "/repo/src/lib.rs"})));
        assert!(!is_deny(&out), "expected allow, got {out}");

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn wants_to_respond_true_for_deny_and_ask() {
        assert!(wants_to_respond(
            r#"{"hookSpecificOutput":{"permissionDecision":"deny"}}"#
        ));
        assert!(wants_to_respond(
            r#"{"hookSpecificOutput":{"permissionDecision":"ask"}}"#
        ));
    }

    #[test]
    fn wants_to_respond_false_for_allow_or_absent_decision() {
        assert!(!wants_to_respond(
            r#"{"hookSpecificOutput":{"permissionDecision":"allow"}}"#
        ));
        assert!(!wants_to_respond(r#"{"hookSpecificOutput":{}}"#));
        assert!(!wants_to_respond("not json"));
        assert!(!wants_to_respond(""));
    }

    #[test]
    fn stub_installed_false_when_missing() {
        let dir = temp_dir().join(format!(
            "cerberus-cupcake-test-{}-missing",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        assert!(!stub_installed(&dir));
    }

    #[test]
    fn stub_installed_true_when_policies_dir_present() {
        let dir = temp_dir().join(format!(
            "cerberus-cupcake-test-{}-present",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(".cupcake/policies/claude")).unwrap();
        assert!(stub_installed(&dir));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn global_installed_false_when_missing() {
        let dir = temp_dir().join(format!(
            "cerberus-cupcake-global-test-{}-missing",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        assert!(!global_installed(&dir));
    }

    #[test]
    fn global_installed_true_when_policies_dir_present() {
        let dir = temp_dir().join(format!(
            "cerberus-cupcake-global-test-{}-present",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("policies/claude")).unwrap();
        assert!(global_installed(&dir));
        fs::remove_dir_all(&dir).ok();
    }
}
