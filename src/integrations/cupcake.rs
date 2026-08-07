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
    use std::env::temp_dir;
    use std::fs;

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
}
