use crate::hook::pretooluse_deny;
use std::fs;
use std::io::Write;
use std::path::Path;

/// `gate`, the fail-closed backstop. The SessionStart health check
/// (`crate::health`) writes `sentinel` when the risk head (tirith) or
/// the policy head (cupcake) is degraded; under bypassPermissions those
/// heads are the only boundary, and both fail open, so a broken one means
/// no protection at all. While the sentinel exists this denies every call
/// that reaches it: it can't cherry-pick "safe" ones to allow, because
/// judging that is the policy head's job, and the policy head is the thing
/// that's broken. Runs first inside `guard`, ahead of every other head, so
/// it wins.
///
/// Which tools that covers is decided entirely by `settings::GUARD_MATCHER`,
/// not here — a tool cerberus isn't wired for never invokes `guard` at all.
/// That's deliberate: the matcher leaves the read-only tools out, so a
/// degraded guard blocks everything that could change something while still
/// letting the agent read enough to explain what broke. It's also why this
/// runs before stdin is ever read (see `guard::run`) and doesn't name the
/// tool in its message.
pub fn evaluate(sentinel: &Path) -> Option<String> {
    if !sentinel.is_file() {
        return None;
    }
    let reason = fs::read_to_string(sentinel).unwrap_or_default();
    let message = format!(
        "Agent tool guards are degraded, so this tool is blocked fail-closed: under \
        bypassPermissions the guards are the only protection and they are not currently \
        enforcing. Cause: {}. Repair with `cerberus init`, then restart the session.",
        reason.trim()
    );
    Some(pretooluse_deny(&message))
}

pub fn run(sentinel: &Path) {
    print_result(sentinel, &mut std::io::stdout());
}

fn print_result(sentinel: &Path, out: &mut impl Write) {
    if let Some(output) = evaluate(sentinel) {
        let _ = writeln!(out, "{output}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::env::temp_dir;

    fn tempfile(name: &str) -> std::path::PathBuf {
        temp_dir().join(format!("cerberus-gate-test-{}-{name}", std::process::id()))
    }

    #[test]
    fn prints_nothing_when_sentinel_missing() {
        let mut out = Vec::new();
        print_result(&tempfile("missing"), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn denies_with_the_sentinel_reason_embedded() {
        let path = tempfile("present");
        fs::write(&path, "  tirith not on PATH  \n").unwrap();
        let mut out = Vec::new();
        print_result(&path, &mut out);
        let printed = String::from_utf8(out).unwrap();
        let parsed: Value = serde_json::from_str(printed.trim()).unwrap();
        let reason = parsed["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert_eq!(parsed["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            reason.contains("Cause: tirith not on PATH."),
            "reason was: {reason}"
        );
        fs::remove_file(&path).ok();
    }
}
