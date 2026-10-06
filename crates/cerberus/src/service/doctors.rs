use crate::config;
use crate::config::Paths;
use crate::domain::{Check, Status};
use crate::harnesses;
use crate::service::healths;
use serde_json::json;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

/// `cerberus doctor`: diagnose why the guards are (or would be) degraded,
/// then retest.
///
/// It runs every health probe, prints each outcome with the exact fix, and
/// hands the result to [`healths::report`], the same code SessionStart uses.
/// That is the only thing that ever clears the sentinel, and it only does so
/// when every probe passes. There is deliberately no way to remove the
/// sentinel without the guards enforcing (see SECURITY.md).
///
/// A human runs this in a terminal: while degraded, `gate` blocks the agent's
/// own Bash tool.
pub fn run(paths: &Paths, json: bool) -> i32 {
    let sentinel = paths.degraded_sentinel();
    let before = sentinel_state(&sentinel);

    let mut checks = healths::collect_checks(paths, &healths::System(paths));
    checks.extend(extra_checks(paths));
    let problems = healths::problems_of(&checks);

    // Same write-or-clear logic as SessionStart. Its stdout is the hook JSON,
    // which belongs to the harness, not to a person at a terminal.
    healths::report(
        &sentinel,
        &problems,
        &mut std::io::sink(),
        &mut std::io::sink(),
    );

    let mut out = std::io::stdout();
    if json {
        render_json(&before, &checks, &problems, &mut out);
    } else {
        render(&before, &checks, &problems, &mut out);
    }
    i32::from(!problems.is_empty())
}

/// What the sentinel looked like before this run.
fn sentinel_state(sentinel: &Path) -> Option<(String, Option<u64>)> {
    if !sentinel.is_file() {
        return None;
    }
    let reason = fs::read_to_string(sentinel).unwrap_or_default();
    let age = fs::metadata(sentinel)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .map(|d| d.as_secs());
    Some((reason.trim().to_string(), age))
}

fn human_age(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86400),
    }
}

/// Checks that never degrade the guard but explain a guard that isn't
/// reached at all: `health` can't notice any of these because it only runs
/// when the hooks are already wired.
fn extra_checks(paths: &Paths) -> Vec<Check> {
    let mut checks = Vec::new();

    checks.push(match config::parse_error(paths) {
        Some(e) => Check::warn(
            None,
            "config",
            "config.toml does not parse; defaults are in effect",
        )
        .detail(format!("{}: {e}", paths.config_file().display()))
        .fix("fix the TOML. Every head stays enabled meanwhile, so this never weakens the guard"),
        None => Check::ok(None, "config", "config.toml parses (or is absent)"),
    });

    checks.extend(harnesses::all().iter().map(|harness| harness.check(paths)));
    checks
}

fn tag(status: Status) -> &'static str {
    match status {
        Status::Ok => "ok  ",
        Status::Fail => "FAIL",
        Status::Warn => "warn",
        Status::Skip => "skip",
    }
}

fn render(
    before: &Option<(String, Option<u64>)>,
    checks: &[Check],
    problems: &[String],
    out: &mut impl Write,
) {
    match before {
        Some((reason, age)) => {
            let when = age
                .map(|a| format!(" (set {})", human_age(a)))
                .unwrap_or_default();
            let _ = writeln!(out, "sentinel: PRESENT{when}\n  recorded: {reason}\n");
        }
        None => {
            let _ = writeln!(out, "sentinel: absent\n");
        }
    }

    for check in checks {
        let _ = writeln!(
            out,
            "{} {:<24} {}",
            tag(check.status),
            check.id,
            check.short_summary()
        );
        if matches!(check.status, Status::Fail | Status::Warn) {
            if let Some(detail) = &check.detail {
                let _ = writeln!(out, "{:29}{detail}", "");
            }
            if let Some(fix) = &check.fix {
                let _ = writeln!(out, "{:29}fix: {fix}", "");
            }
        }
    }

    let _ = writeln!(out);
    if problems.is_empty() {
        let note = if before.is_some() {
            "sentinel cleared"
        } else {
            "sentinel not set"
        };
        let _ = writeln!(
            out,
            "All guards enforcing; {note}. Restart the agent session."
        );
    } else {
        let _ = writeln!(
            out,
            "Still degraded ({} problem{}); sentinel {}. Fix the above, then run `cerberus doctor` again.",
            problems.len(),
            if problems.len() == 1 { "" } else { "s" },
            if before.is_some() {
                "kept, reason refreshed"
            } else {
                "written"
            },
        );
    }
}

fn render_json(
    before: &Option<(String, Option<u64>)>,
    checks: &[Check],
    problems: &[String],
    out: &mut impl Write,
) {
    let status = |s: Status| match s {
        Status::Ok => "ok",
        Status::Fail => "fail",
        Status::Warn => "warn",
        Status::Skip => "skip",
    };
    let value = json!({
        "healthy": problems.is_empty(),
        "sentinel_before": before.as_ref().map(|(reason, age)| json!({
            "reason": reason,
            "age_seconds": age,
        })),
        "checks": checks.iter().map(|c| json!({
            "id": c.id,
            "head": c.head.map(|h| h.name()),
            "status": status(c.status),
            "summary": c.summary,
            "detail": c.detail,
            "fix": c.fix,
        })).collect::<Vec<_>>(),
    });
    let _ = writeln!(out, "{value}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Head;

    fn rendered(before: Option<(String, Option<u64>)>, checks: &[Check]) -> String {
        let problems = healths::problems_of(checks);
        let mut out = Vec::new();
        render(&before, checks, &problems, &mut out);
        String::from_utf8(out).unwrap()
    }

    fn failing() -> Vec<Check> {
        vec![
            Check::ok(Some(Head::Risk), "risk.tirith", "tirith on PATH"),
            Check {
                head: Some(Head::Policy),
                id: "policy.opa",
                status: Status::Fail,
                summary: "policy (x): opa not on PATH".into(),
                detail: Some("looked on PATH".into()),
                fix: Some("install opa".into()),
            },
            Check::warn(None, "config", "config.toml does not parse"),
        ]
    }

    #[test]
    fn render_shows_each_failure_with_its_fix_and_says_still_degraded() {
        let text = rendered(Some(("old reason".into(), Some(120))), &failing());
        assert!(text.contains("sentinel: PRESENT (set 2m ago)"), "{text}");
        assert!(text.contains("FAIL"), "{text}");
        assert!(text.contains("fix: install opa"), "{text}");
        assert!(text.contains("Still degraded (1 problem)"), "{text}");
    }

    #[test]
    fn warnings_do_not_count_as_problems() {
        let checks = vec![Check::warn(None, "config", "bad toml")];
        let text = rendered(Some(("old".into(), None)), &checks);
        assert!(
            text.contains("All guards enforcing; sentinel cleared"),
            "{text}"
        );
    }

    #[test]
    fn json_output_reports_health_and_checks() {
        let checks = failing();
        let problems = healths::problems_of(&checks);
        let mut out = Vec::new();
        render_json(&None, &checks, &problems, &mut out);
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["healthy"], false);
        assert_eq!(value["checks"][1]["status"], "fail");
        assert_eq!(value["checks"][1]["fix"], "install opa");
    }

    #[test]
    fn a_failing_run_keeps_the_sentinel_and_a_clean_run_clears_it() {
        let dir = std::env::temp_dir().join(format!("cerberus-doctor-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let sentinel = dir.join("cerberus/degraded");
        let sink = &mut std::io::sink();

        healths::report(&sentinel, &["boom".to_string()], sink, &mut std::io::sink());
        assert_eq!(fs::read_to_string(&sentinel).unwrap(), "boom");

        healths::report(
            &sentinel,
            &["new reason".to_string()],
            sink,
            &mut std::io::sink(),
        );
        assert_eq!(fs::read_to_string(&sentinel).unwrap(), "new reason");

        healths::report(&sentinel, &[], sink, &mut std::io::sink());
        assert!(!sentinel.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
