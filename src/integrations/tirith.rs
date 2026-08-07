use crate::hook::{pretooluse_deny, tool_input_command};
use crate::process::command_exists;
use serde::Deserialize;
use serde_json::Value;
use std::process::{Command, Stdio};

const DENY_REASON_FALLBACK: &str = "Blocked by tirith: dangerous command pattern (e.g. \
pipe-to-shell, homograph URL, terminal injection, data exfiltration). Run \
`tirith check -- '<command>'` to see the findings.";

#[derive(Deserialize, Default)]
struct Finding {
    severity: Option<String>,
    title: Option<String>,
    description: Option<String>,
}

#[derive(Deserialize, Default)]
struct CheckOutput {
    #[serde(default)]
    findings: Vec<Finding>,
}

/// tirith's exit code is the verdict: 1 means deny, anything else (0, a
/// missing binary spawning nothing, a crash) means allow. A broken scanner
/// fails open rather than blocking everything. `--format json` is requested
/// alongside so a deny can carry tirith's actual finding text instead of
/// telling the user to go run `tirith check` themselves; if that JSON is
/// missing or unparsable, [`DENY_REASON_FALLBACK`] still denies with the
/// old generic message rather than failing open or crashing.
fn check(cmd: &str) -> (bool, Vec<Finding>) {
    let output = Command::new("tirith")
        .args(["check", "--non-interactive", "--format", "json", "--", cmd])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    let Ok(output) = output else {
        return (false, Vec::new());
    };
    let denied = output.status.code() == Some(1);
    if !denied {
        return (false, Vec::new());
    }
    let findings = serde_json::from_slice::<CheckOutput>(&output.stdout)
        .map(|o| o.findings)
        .unwrap_or_default();
    (true, findings)
}

fn format_finding(finding: &Finding) -> String {
    let title = finding
        .title
        .as_deref()
        .unwrap_or("dangerous command pattern");
    let mut segment = match finding.severity.as_deref() {
        Some(severity) => format!("[{severity}] {title}"),
        None => title.to_string(),
    };
    if let Some(description) = finding.description.as_deref() {
        let normalized = description.split_whitespace().collect::<Vec<_>>().join(" ");
        if !normalized.is_empty() {
            segment.push_str(" — ");
            segment.push_str(&normalized);
        }
    }
    segment
}

fn build_reason(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return DENY_REASON_FALLBACK.to_string();
    }
    let segments: Vec<String> = findings.iter().map(format_finding).collect();
    format!("Blocked by tirith: {}", segments.join(" | "))
}

/// The `risk` part of `guard`: command-pattern scanning via the `tirith`
/// binary. Returns the full ready-to-print `PreToolUse` deny JSON, or
/// `None` to allow (missing binary, no command, or tirith itself allows).
pub fn evaluate(input: &Value) -> Option<String> {
    if !command_exists("tirith") {
        return None;
    }
    let cmd = tool_input_command(input)?;

    let (denied, findings) = check(cmd);
    if !denied {
        return None;
    }

    Some(pretooluse_deny(&build_reason(&findings)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Option<&str>, title: Option<&str>, description: Option<&str>) -> Finding {
        Finding {
            severity: severity.map(String::from),
            title: title.map(String::from),
            description: description.map(String::from),
        }
    }

    #[test]
    fn format_finding_includes_severity_title_and_description() {
        let f = finding(
            Some("HIGH"),
            Some("Pipe to interpreter: curl | bash"),
            Some("Downloaded content will run."),
        );
        assert_eq!(
            format_finding(&f),
            "[HIGH] Pipe to interpreter: curl | bash — Downloaded content will run."
        );
    }

    #[test]
    fn format_finding_normalizes_embedded_newlines_and_indentation() {
        let f = finding(
            Some("HIGH"),
            Some("Title"),
            Some("Line one.\n  Safer: do the other thing."),
        );
        assert_eq!(
            format_finding(&f),
            "[HIGH] Title — Line one. Safer: do the other thing."
        );
    }

    #[test]
    fn format_finding_falls_back_when_fields_are_missing() {
        let f = finding(None, None, None);
        assert_eq!(format_finding(&f), "dangerous command pattern");
    }

    #[test]
    fn build_reason_joins_multiple_findings() {
        let findings = vec![
            finding(Some("HIGH"), Some("A"), None),
            finding(Some("MEDIUM"), Some("B"), None),
        ];
        assert_eq!(
            build_reason(&findings),
            "Blocked by tirith: [HIGH] A | [MEDIUM] B"
        );
    }

    #[test]
    fn build_reason_falls_back_to_generic_message_when_findings_empty() {
        assert_eq!(build_reason(&[]), DENY_REASON_FALLBACK);
    }

    #[test]
    fn parses_the_real_curl_pipe_shell_finding_shape() {
        let raw = r#"{
            "schema_version":3,"action":"block",
            "findings":[{"rule_id":"curl_pipe_shell","severity":"HIGH",
                "title":"Pipe to interpreter: curl | bash",
                "description":"Command pipes output from 'curl' directly to interpreter 'bash'. Downloaded content will be executed without inspection.\n  Safer: tirith run https://example.com/install.sh",
                "evidence":[],"mitre_id":"T1059.004","remediation":"Download first."}],
            "tier_reached":3
        }"#;
        let parsed: CheckOutput = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.findings.len(), 1);
        let reason = build_reason(&parsed.findings);
        assert!(
            reason.starts_with("Blocked by tirith: [HIGH] Pipe to interpreter: curl | bash — ")
        );
        assert!(reason.contains("Downloaded content will be executed without inspection."));
        assert!(reason.contains("Safer: tirith run https://example.com/install.sh"));
    }
}
