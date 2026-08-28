use crate::hook::permission_decision;
use crate::paths::Paths;
use crate::process::command_exists;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

/// Spawns `cupcake eval` against cerberus's own project and policy store,
/// feeding it the raw hook event JSON. Returns `None` on any failure
/// (missing binary, non-zero exit, empty output), so a broken layer never
/// blocks work.
///
/// Both locations are passed explicitly rather than inherited from the
/// process environment. cerberus used to run this with `current_dir` set to
/// a stub project because cupcake discovered its project from the cwd;
/// `--policy-dir` removes that need, and `--global-config` points cupcake
/// at cerberus's own store instead of the user's `~/.config/cupcake`.
///
/// Both flags were confirmed against cupcake 0.5.2 rather than taken from
/// `--help`, which is misleading on both:
///
/// - `--policy-dir` wants the project root's `.cupcake` directory, not the
///   `policies` directory inside it. cupcake derives the project root as
///   this path's *parent* and re-joins `.cupcake/policies/<harness>`, so
///   passing the deeper path makes it look for `.cupcake/.cupcake/policies/
///   claude` and fail to initialize. See `Paths::cupcake_policy_dir`.
/// - `--global-config` is described as a "file path" but must be an
///   absolute *directory* that already exists. It's honored here by `eval`,
///   but silently ignored by `cupcake verify`/`inspect` — so neither of
///   those can be used to check what cerberus's store actually contains.
fn spawn_eval(paths: &Paths, input_json: &str) -> Option<String> {
    let mut child = Command::new("cupcake")
        .args(["eval", "--harness", "claude"])
        .arg("--policy-dir")
        .arg(paths.cupcake_policy_dir())
        .arg("--global-config")
        .arg(paths.cupcake_global_root())
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

/// True if `root` has a real cupcake project set up for the `claude`
/// harness (i.e. `cupcake init --harness claude` has been run there).
/// Shared by [`evaluate`], `health`'s problem collection, and `init`'s
/// bootstrap check, so there's exactly one definition of "installed."
pub fn project_installed(root: &Path) -> bool {
    root.join(".cupcake/policies/claude").is_dir()
}

/// True if `root` has a real cupcake **global** store for the `claude`
/// harness (i.e. `cupcake init --global --harness claude` has been run).
/// Mirrors [`project_installed`]'s shape but checks the global store's
/// layout (`policies/claude/`, no `.cupcake/` prefix). Shared by `init`'s
/// bootstrap check and `health`'s canary.
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
/// respond (deny or ask); `None` (missing binary, project not installed,
/// eval failure, or an explicit/absent allow) means `guard` moves on to the
/// next head.
pub fn evaluate(paths: &Paths, raw_input: &str) -> Option<String> {
    if !command_exists("cupcake") {
        return None;
    }
    if !project_installed(&paths.cupcake_project_root()) {
        return None;
    }
    let out = spawn_eval(paths, raw_input)?;
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

    /// End-to-end through the real [`evaluate`], not a re-implementation of
    /// it: real `cupcake init`, real `cupcake eval`, real `opa`/WASM
    /// compilation, one deny event and one clearly-benign counterpart per
    /// shipped policy, asserted against the actual
    /// `permissionDecisionReason` text rather than mocked.
    ///
    /// Going through `evaluate` is what makes this cover the invocation
    /// itself — that `--policy-dir` gets the `.cupcake` directory and
    /// `--global-config` gets cerberus's store. Those two flags replaced a
    /// `current_dir` and an inherited `XDG_CONFIG_HOME`, and getting either
    /// wrong fails *open* (cupcake finds no policies and allows), which no
    /// assertion on a hand-rolled subprocess would have caught.
    ///
    /// Isolation is now structural rather than environmental: a scratch
    /// `Paths` puts both the project and the policy store under a temp
    /// directory, so the developer's real `~/.config/cupcake` is untouched
    /// without needing to override `XDG_CONFIG_HOME` for the eval at all.
    /// The decoy `HOME` is still needed for `init`, which auto-wires its own
    /// hook into `$HOME/.claude/settings.json` otherwise.
    #[test]
    fn shipped_cupcake_policies_evaluate_correctly_end_to_end() {
        if !command_exists("cupcake") || !command_exists("opa") {
            eprintln!("skipping: cupcake and/or opa not on PATH");
            return;
        }

        let root = temp_dir().join(format!("cerberus-cupcake-e2e-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let paths = Paths {
            state_home: root.join("state"),
            data_home: root.join("data"),
            config_home: root.join("config"),
            cache_home: root.join("cache"),
            home: root.join("home"),
        };
        let decoy_home = paths.cupcake_init_decoy_home();
        fs::create_dir_all(&decoy_home).unwrap();
        fs::create_dir_all(paths.cupcake_project_root()).unwrap();

        let global_init = Command::new("cupcake")
            .args(["init", "--global", "--harness", "claude"])
            .env("HOME", &decoy_home)
            .env("XDG_CONFIG_HOME", paths.cupcake_init_xdg_config_home())
            .status()
            .expect("failed to run cupcake init --global");
        assert!(global_init.success(), "cupcake init --global failed");
        assert!(
            global_installed(&paths.cupcake_global_root()),
            "the XDG_CONFIG_HOME redirect must land the store at {}",
            paths.cupcake_global_root().display()
        );

        let policies_dir = paths.cupcake_policies_dir();
        fs::create_dir_all(&policies_dir).unwrap();
        for (name, contents) in crate::embedded::CUPCAKE_POLICIES {
            fs::write(policies_dir.join(name), contents).unwrap();
        }

        let project_init = Command::new("cupcake")
            .args(["init", "--harness", "claude"])
            .current_dir(paths.cupcake_project_root())
            .env("HOME", &decoy_home)
            .status()
            .expect("failed to run cupcake init (project)");
        assert!(project_init.success(), "cupcake init (project) failed");

        let event = |tool: &str, tool_input: serde_json::Value| {
            json!({
                "session_id": "t",
                "transcript_path": "/dev/null",
                "cwd": "/repo",
                "hook_event_name": "PreToolUse",
                "tool_name": tool,
                "tool_input": tool_input,
            })
            .to_string()
        };
        let denial = |tool: &str, tool_input: serde_json::Value| -> String {
            let out = evaluate(&paths, &event(tool, tool_input))
                .unwrap_or_else(|| panic!("expected {tool} to be denied, got an allow"));
            assert!(is_deny(&out), "{out}");
            out
        };
        let allows = |tool: &str, tool_input: serde_json::Value| {
            let out = evaluate(&paths, &event(tool, tool_input));
            assert!(out.is_none(), "expected an allow, got {out:?}");
        };

        // CERB-POL-001: sandbox-integrity.rego
        let out = denial(
            "Bash",
            json!({"command": "ls", "dangerouslyDisableSandbox": true}),
        );
        assert!(out.contains("dangerouslyDisableSandbox"), "{out}");
        allows("Bash", json!({"command": "ls -la"}));

        // CERB-POL-002: webfetch-ssrf.rego
        let out = denial(
            "WebFetch",
            json!({"url": "http://169.254.169.254/latest/meta-data/"}),
        );
        assert!(out.contains("SSRF"), "{out}");
        allows("WebFetch", json!({"url": "https://example.com"}));

        // CERB-POL-003: ci-trust-boundary.rego
        let out = denial(
            "Write",
            json!({"file_path": "/repo/.github/workflows/ci.yml"}),
        );
        assert!(out.contains("CI/CD"), "{out}");
        allows("Write", json!({"file_path": "/repo/src/main.rs"}));

        // CERB-POL-004: guard-self-protection.rego. The denied path is built
        // from the scratch `Paths` rather than hardcoded, so this stays
        // honest about what the policy's regex actually has to match.
        let out = denial(
            "Write",
            json!({"file_path": paths.rule_scripts_dir().join("sandbox-integrity.rhai")}),
        );
        assert!(out.contains("cerberus's, tirith's, or cupcake's"), "{out}");
        allows("Write", json!({"file_path": "/repo/src/lib.rs"}));

        // The relocated store is covered too: cerberus's own policy
        // directory has to be self-protected at its new path, not the old
        // `custom/cerberus/` one.
        denial(
            "Write",
            json!({"file_path": paths.cupcake_policies_dir().join("sandbox-integrity.rego")}),
        );

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
        assert!(!project_installed(&dir));
    }

    #[test]
    fn stub_installed_true_when_policies_dir_present() {
        let dir = temp_dir().join(format!(
            "cerberus-cupcake-test-{}-present",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(".cupcake/policies/claude")).unwrap();
        assert!(project_installed(&dir));
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
