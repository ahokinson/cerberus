pub mod compose;

use crate::hook::{bash_command, pretooluse_deny};
use crate::paths::Paths;
use crate::process::command_exists;
use serde::Deserialize;
use serde_json::Value;
use std::path::Path;
use std::process::{Command, Stdio};

const DENY_REASON_FALLBACK: &str = "Blocked by tirith: dangerous command pattern (e.g. \
pipe-to-shell, homograph URL, terminal injection, data exfiltration). Run \
`tirith check -- '<command>'` to see the findings.";

#[derive(Deserialize, Default)]
struct Finding {
    severity: Option<String>,
    title: Option<String>,
    description: Option<String>,
    /// Which `custom_rules[].id` produced this finding. tirith reports every
    /// custom-rule hit under the generic `rule_id: "custom_rule_match"`, so
    /// this is the only field that attributes one to a specific rule — which
    /// is what [`rules_that_never_fire`] needs.
    custom_rule_id: Option<String>,
}

#[derive(Deserialize, Default)]
struct CheckOutput {
    #[serde(default)]
    findings: Vec<Finding>,
    policy_path_used: Option<String>,
}

/// True if `cwd` (walking up to a `.git` boundary, mirroring tirith's own
/// documented repo-policy discovery) already has its own
/// `.tirith/policy.yaml`. Cerberus's overlay must never silently override a
/// policy a repo or team already maintains: `TIRITH_POLICY_ROOT` was
/// confirmed (against the real binary, not just docs) to take full
/// precedence over an ambient repo policy — scope becomes `org` with "all
/// fields honored (nothing neutralized)", not merely layered on top — so
/// without this check cerberus's overlay would silently replace a team's
/// real posture instead of only supplementing tirith's built-ins in repos
/// that have none of their own.
fn has_repo_policy(cwd: &Path) -> bool {
    let mut dir = cwd;
    loop {
        if dir.join(".tirith/policy.yaml").is_file() {
            return true;
        }
        if dir.join(".git").exists() {
            return false;
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => return false,
        }
    }
}

/// tirith's exit code is the verdict: 1 means deny, anything else (0, a
/// missing binary spawning nothing, a crash) means allow. A broken scanner
/// fails open rather than blocking everything. `--format json` is requested
/// alongside so a deny can carry tirith's actual finding text instead of
/// telling the user to go run `tirith check` themselves; if that JSON is
/// missing or unparsable, [`DENY_REASON_FALLBACK`] still denies with the
/// old generic message rather than failing open or crashing.
///
/// `policy_root_override`, when set, is applied via `TIRITH_POLICY_ROOT` on
/// this specific subprocess call only — never the user's own shell or
/// environment — so cerberus's overlay policy never leaks outside the one
/// `tirith check` invocation it's meant for.
fn check(cmd: &str, policy_root_override: Option<&Path>) -> (bool, Vec<Finding>, Option<String>) {
    let mut command = Command::new("tirith");
    command.args(["check", "--non-interactive", "--format", "json", "--", cmd]);
    if let Some(root) = policy_root_override {
        command.env("TIRITH_POLICY_ROOT", root);
    }
    let output = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    let Ok(output) = output else {
        return (false, Vec::new(), None);
    };
    let parsed = serde_json::from_slice::<CheckOutput>(&output.stdout).unwrap_or_default();
    let denied = output.status.code() == Some(1);
    if !denied {
        return (false, Vec::new(), parsed.policy_path_used);
    }
    (true, parsed.findings, parsed.policy_path_used)
}

/// Runs `check` against `root` and, if tirith's own report shows the
/// override didn't actually apply (`policy_path_used` isn't
/// `tirith_overlay_policy_file` — tirith reports `NotRegularFile` for a
/// policy file that's a symlink, e.g. one deployed via a nix-store
/// symlink, and silently falls back to "fail-closed", its own built-ins
/// only, dropping every custom rule with no error at guard time),
/// self-heals by recomposing the overlay (see [`compose`]) and retries
/// once. Still not applied after that just returns what `check` gave —
/// this must never become a new way to fail closed.
///
/// Recomposing rather than rewriting a fixed blob is load-bearing: the file
/// this repairs to must be the one `init` would write, fragments and
/// sources included, or a self-heal would silently strip a team's injected
/// rules for the rest of the session.
fn check_with_overlay(cmd: &str, paths: &Paths, root: &Path) -> (bool, Vec<Finding>) {
    let (denied, findings, policy_path_used) = check(cmd, Some(root));
    let overlay_file = paths.tirith_overlay_policy_file();
    if policy_path_used.as_deref() == Some(overlay_file.to_string_lossy().as_ref()) {
        return (denied, findings);
    }
    if crate::init::write_tirith_overlay(paths).is_err() {
        return (denied, findings);
    }
    let (denied, findings, _) = check(cmd, Some(root));
    (denied, findings)
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
/// `None` to allow (missing binary, not a Bash call, or tirith itself
/// allows).
///
/// This head stays Bash-only by design even though `guard` now runs on
/// every mutating tool: tirith scans shell command strings, and there is no
/// meaningful command to hand it for a `Write` or a `WebFetch`. See
/// [`bash_command`] for why the tool is checked by name rather than by
/// whether a `command` field happens to be present.
///
/// Applies cerberus's own overlay policy (`paths.tirith_overlay_policy_file`,
/// self-healed by recomposing it if missing or unreadable — see
/// [`check_with_overlay`]) by pointing `TIRITH_POLICY_ROOT` at it, but only
/// when `cwd` has no `.tirith/policy.yaml` of its own — see
/// [`has_repo_policy`]. A repo or team's real tirith policy always wins;
/// cerberus never overrides it.
pub fn evaluate(paths: &Paths, cwd: &Path, input: &Value) -> Option<String> {
    if !command_exists("tirith") {
        return None;
    }
    let cmd = bash_command(input)?;

    let (denied, findings) = if has_repo_policy(cwd) {
        let (denied, findings, _) = check(cmd, None);
        (denied, findings)
    } else {
        check_with_overlay(cmd, paths, &paths.tirith_overlay_root())
    };
    if !denied {
        return None;
    }

    Some(pretooluse_deny(&build_reason(&findings)))
}

/// Checks that each rule in a composed policy can actually fire, and names
/// the ones that can't.
///
/// This exists because of a trap that is very easy to walk into and very
/// hard to notice: `tirith check` — what `risk` actually runs — only
/// evaluates `custom_rules` once tirith's *own* built-in tier-1 detections
/// have already escalated analysis past tier 1. A rule whose pattern has no
/// overlap with tirith's ~150 built-in categories is never consulted in
/// production, no matter the `paranoia` setting, even though
/// `tirith rule validate` and `tirith rule test` both report it as fine.
/// Confirmed live: cerberus's own `cerberus-guard-self-tamper` reaches
/// tier 3 and blocks, while an otherwise-identical rule matching
/// `brew uninstall <some tool>` stops at tier 1 and never runs.
///
/// Layering makes that far worse than it was. cerberus's own single rule
/// was verified by hand once; a source repo can ship any number, and
/// "cerberus installed your team's rules and they silently enforce nothing"
/// is precisely the failure this codebase exists to prevent. So a rule may
/// declare `examples_bad:` — commands it is supposed to catch — and this
/// runs each one through the real `tirith check` against the real composed
/// policy, reporting any rule that never fires.
///
/// Only rules that declare examples are checked. A rule without them isn't
/// reported as broken, just unverified: cerberus has no way to guess a
/// command that ought to trip it.
pub(crate) fn rules_that_never_fire(composed_yaml: &str, scratch_root: &Path) -> Vec<String> {
    if !command_exists("tirith") {
        return Vec::new();
    }
    let policy_file = scratch_root.join(".tirith/policy.yaml");
    if std::fs::create_dir_all(policy_file.parent().unwrap_or(scratch_root)).is_err()
        || std::fs::write(&policy_file, composed_yaml).is_err()
    {
        return Vec::new();
    }

    compose::rules_with_examples(composed_yaml)
        .into_iter()
        .filter(|(id, examples)| {
            !examples
                .iter()
                .any(|example| fires_for(id, example, scratch_root))
        })
        .map(|(id, _)| id)
        .collect()
}

/// Whether `rule_id` produces a finding for `command` under the policy at
/// `policy_root`. Deliberately goes through [`check`] — the same function
/// `evaluate` uses in production — rather than `tirith rule test`, which
/// bypasses tirith's tiering and would report success for exactly the rules
/// this is trying to catch.
fn fires_for(rule_id: &str, command: &str, policy_root: &Path) -> bool {
    let (_, findings, _) = check(command, Some(policy_root));
    findings
        .iter()
        .any(|f| f.custom_rule_id.as_deref() == Some(rule_id))
}

/// `health`'s canary for this head's shipped overlay content: forces
/// cerberus's overlay regardless of `cwd` (unlike [`evaluate`], which
/// defers to a repo's own policy), so a pass here is attributable
/// specifically to cerberus's own `policies/tirith/policy.yaml` being
/// present, valid, and live — not just that tirith itself is installed.
pub(crate) fn overlay_blocks(paths: &Paths, cmd: &str) -> bool {
    check_with_overlay(cmd, paths, &paths.tirith_overlay_root()).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cerberus-tirith-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A scratch root with cerberus's shipped overlay installed as
    /// `.tirith/policy.yaml`, ready to hand to [`check`] via
    /// `policy_root_override` — the same mechanism `evaluate`/
    /// `overlay_blocks` use in production, deliberately not
    /// `tirith rule test`'s cwd-based auto-discovery (no `.git` boundary
    /// needed here, since `check` never walks for one).
    fn overlay_root_with_shipped_policy() -> std::path::PathBuf {
        let dir = tempdir("overlay-root");
        fs::create_dir_all(dir.join(".tirith")).unwrap();
        fs::write(
            dir.join(".tirith/policy.yaml"),
            crate::embedded::TIRITH_POLICY,
        )
        .unwrap();
        dir
    }

    /// Syntax/shape validation for the shipped overlay: only needs
    /// `tirith`, not a full repo setup beyond what `tirith rule validate`
    /// itself requires.
    #[test]
    fn shipped_tirith_overlay_validates() {
        if !command_exists("tirith") {
            eprintln!("skipping: tirith not on PATH");
            return;
        }
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("policies/tirith/policy.yaml");
        let status = Command::new("tirith")
            .args(["rule", "validate", "--path"])
            .arg(&path)
            .status()
            .expect("failed to run tirith rule validate");
        assert!(status.success(), "tirith rule validate failed for {path:?}");
    }

    fn scratch_paths(name: &str) -> Paths {
        let root = tempdir(name);
        Paths {
            state_home: root.join("state"),
            data_home: root.join("data"),
            config_home: root.join("config"),
            cache_home: root.join("cache"),
            home: root.join("home"),
        }
    }

    /// Reproduces the real outage: a deployment that symlinks the overlay
    /// into some other location (a nix-store path, in production) instead
    /// of writing a regular file there. tirith refuses to read it
    /// ("NotRegularFile") and reports `policy_path_used: "fail-closed"`,
    /// silently dropping every custom rule — `check_with_overlay` has to
    /// notice that and self-heal, not just check `overlay.is_file()`
    /// (which a symlink to a real file still satisfies).
    #[test]
    fn check_with_overlay_self_heals_a_symlinked_overlay() {
        if !command_exists("tirith") {
            eprintln!("skipping: tirith not on PATH");
            return;
        }
        let paths = scratch_paths("self-heal-symlink");
        let elsewhere = overlay_root_with_shipped_policy();

        let overlay_file = paths.tirith_overlay_policy_file();
        let target = elsewhere.join(".tirith/policy.yaml");
        fs::create_dir_all(overlay_file.parent().unwrap()).unwrap();
        #[cfg(unix)]
        {
            // Read-only target, matching production: a symlink into a nix
            // store path. Proves self-heal replaces the symlink itself
            // rather than trying to write through it - fs::write follows a
            // symlink to its target and would just fail here otherwise.
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o444)).unwrap();
            std::os::unix::fs::symlink(&target, &overlay_file).unwrap();
        }

        let (denied, findings) = check_with_overlay(
            "cargo uninstall cerberus",
            &paths,
            &paths.tirith_overlay_root(),
        );
        assert!(
            denied,
            "self-heal should have rewritten the overlay and retried"
        );
        assert!(
            findings.iter().any(|f| f.title.as_deref()
                == Some("Removing or uninstalling the guard's own tooling/config")),
            "expected a guard-self-tamper finding after self-heal, got: {}",
            build_reason(&findings)
        );
        assert!(
            !overlay_file.is_symlink(),
            "self-heal should have replaced the symlink with a real file"
        );

        fs::remove_dir_all(&elsewhere).ok();
    }

    /// A totally missing overlay (never provisioned at all, not just
    /// broken) must self-heal the same way — `evaluate`/`overlay_blocks`
    /// used to require `overlay.is_file()` before ever trying, which meant
    /// a missing file silently skipped cerberus's own rules forever with
    /// no error and no repair.
    #[test]
    fn check_with_overlay_self_heals_a_missing_overlay() {
        if !command_exists("tirith") {
            eprintln!("skipping: tirith not on PATH");
            return;
        }
        let paths = scratch_paths("self-heal-missing");
        assert!(!paths.tirith_overlay_policy_file().exists());

        let (denied, _) = check_with_overlay(
            "cargo uninstall cerberus",
            &paths,
            &paths.tirith_overlay_root(),
        );
        assert!(
            denied,
            "self-heal should have written the overlay from scratch"
        );
        assert!(paths.tirith_overlay_policy_file().is_file());
    }

    /// The one shipped custom rule fires on the input it's meant to catch
    /// and stays silent on a benign counterpart — exercised through
    /// [`check`], the exact function `evaluate`/`overlay_blocks` call in
    /// production, deliberately **not** `tirith rule test`. That
    /// distinction is load-bearing: `tirith rule test` evaluates a named
    /// rule directly regardless of tirith's own tiered analysis, but
    /// `tirith check` (what `check` — and therefore `guard` — actually
    /// runs) only evaluates `custom_rules` once tirith's own built-in
    /// tier-1 detections have already escalated past tier 1. A rule that
    /// only "fires" under `tirith rule test` can still never fire in
    /// production; see `policies/tirith/policy.yaml`'s header for the full
    /// story and why only one rule ships.
    #[test]
    fn shipped_tirith_overlay_rule_fires_through_the_real_check_path() {
        if !command_exists("tirith") {
            eprintln!("skipping: tirith not on PATH");
            return;
        }
        let root = overlay_root_with_shipped_policy();

        let (denied, findings, _) = check("rm -rf /home/x/.config/cerberus", Some(&root));
        assert!(denied, "expected cerberus-guard-self-tamper to fire");
        assert!(
            findings.iter().any(|f| f.title.as_deref()
                == Some("Removing or uninstalling the guard's own tooling/config")),
            "expected a guard-self-tamper finding, got: {}",
            build_reason(&findings)
        );

        let (denied, _, _) = check("cargo uninstall cerberus", Some(&root));
        assert!(denied, "expected the uninstall branch to fire too");

        let (denied, _, _) = check("rm -rf ./build", Some(&root));
        assert!(!denied, "expected an unrelated rm -rf to stay silent");

        fs::remove_dir_all(&root).ok();
    }

    /// The tiering trap, pinned as a test rather than a comment: two rules
    /// that both validate cleanly, one matching a command tirith's built-ins
    /// already escalate and one that doesn't. Only the first can ever fire
    /// in production, and `rules_that_never_fire` has to say so — that
    /// distinction is invisible to `tirith rule validate` and is actively
    /// misreported by `tirith rule test`.
    #[test]
    fn rules_that_never_fire_names_the_rule_that_cannot_escalate() {
        if !command_exists("tirith") {
            eprintln!("skipping: tirith not on PATH");
            return;
        }
        let dir = tempdir("never-fire");
        let composed = crate::integrations::tirith::compose::compose(
            crate::embedded::TIRITH_POLICY,
            &[compose::Layer {
                label: "test".to_string(),
                namespace: None,
                yaml: "custom_rules:\n\
                       \x20 - id: escalates\n\
                       \x20   context: [exec]\n\
                       \x20   pattern: '/srv/never-fire-probe'\n\
                       \x20   severity: CRITICAL\n\
                       \x20   action: block\n\
                       \x20   title: Escalating rule\n\
                       \x20   examples_bad: ['rm -rf /srv/never-fire-probe']\n\
                       \x20 - id: stays-at-tier-one\n\
                       \x20   context: [exec]\n\
                       \x20   pattern: 'zzz-inert-probe'\n\
                       \x20   severity: CRITICAL\n\
                       \x20   action: block\n\
                       \x20   title: Inert rule\n\
                       \x20   examples_bad: ['echo zzz-inert-probe']\n"
                    .to_string(),
            }],
        );

        let never_fire = rules_that_never_fire(&composed.yaml, &dir);
        assert!(
            never_fire.contains(&"stays-at-tier-one".to_string()),
            "a rule matching nothing tirith escalates on must be reported, got {never_fire:?}"
        );
        assert!(
            !never_fire.contains(&"escalates".to_string()),
            "a rule that does fire must not be reported, got {never_fire:?}"
        );
        assert!(
            !never_fire.contains(&"cerberus-guard-self-tamper".to_string()),
            "cerberus's own rule declares no examples, so it is unverifiable rather than \
             broken and must not be reported: {never_fire:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn has_repo_policy_true_when_cwd_itself_has_one() {
        let dir = tempdir("cwd-has-policy");
        fs::create_dir_all(dir.join(".tirith")).unwrap();
        fs::write(dir.join(".tirith/policy.yaml"), "schema_version: 1\n").unwrap();
        assert!(has_repo_policy(&dir));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn has_repo_policy_true_when_found_walking_up_to_repo_root() {
        let dir = tempdir("nested-has-policy");
        fs::create_dir_all(dir.join(".tirith")).unwrap();
        fs::write(dir.join(".tirith/policy.yaml"), "schema_version: 1\n").unwrap();
        fs::create_dir_all(dir.join(".git")).unwrap();
        let nested = dir.join("src/deeply/nested");
        fs::create_dir_all(&nested).unwrap();
        assert!(has_repo_policy(&nested));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn has_repo_policy_false_when_repo_root_has_no_policy() {
        let dir = tempdir("repo-no-policy");
        fs::create_dir_all(dir.join(".git")).unwrap();
        let nested = dir.join("src");
        fs::create_dir_all(&nested).unwrap();
        assert!(!has_repo_policy(&nested));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn has_repo_policy_false_when_no_git_boundary_or_policy_found() {
        let dir = tempdir("no-git-no-policy");
        assert!(!has_repo_policy(&dir));
        fs::remove_dir_all(&dir).ok();
    }

    fn finding(severity: Option<&str>, title: Option<&str>, description: Option<&str>) -> Finding {
        Finding {
            severity: severity.map(String::from),
            title: title.map(String::from),
            description: description.map(String::from),
            custom_rule_id: None,
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
