use crate::paths::Paths;
use serde_json::{Value, json};
use std::fs;
use std::io;

const BASH_MATCHER: &str = "Bash";
const GUARD_COMMAND: &str = "cerberus guard";
const HEALTH_COMMAND: &str = "cerberus health";

/// What [`merge`] actually changed, so `init` can report it to the user.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub pretooluse_bash_changed: bool,
    pub sessionstart_health_inserted: bool,
}

fn command_hook(command: &str) -> Value {
    json!({ "type": "command", "command": command })
}

/// Merges cerberus's own hook entries into an existing (or fresh)
/// `settings.json` value. Pure function: no I/O, so it's fully testable
/// against fabricated `Value`s shaped like the real file.
///
/// - `hooks.PreToolUse`'s `Bash`-matcher entry is wholesale-replaced with a
///   single `cerberus guard` command; every other matcher entry is left
///   untouched. Cerberus owns that one matcher slot outright, no matter
///   what was previously wired into it.
/// - `hooks.SessionStart` is not matcher-scoped and may hold unrelated
///   commands, so it's only ever idempotently appended to: `cerberus
///   health` is inserted if no entry already runs it, and nothing else in
///   that array is touched or removed.
pub fn merge(settings: Value) -> (Value, MergeReport) {
    let mut settings = if settings.is_object() {
        settings
    } else {
        json!({})
    };
    let mut report = MergeReport::default();

    let obj = settings
        .as_object_mut()
        .expect("settings coerced to object above");
    let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let hooks_obj = hooks
        .as_object_mut()
        .expect("hooks coerced to object above");

    let pretooluse = hooks_obj.entry("PreToolUse").or_insert_with(|| json!([]));
    if !pretooluse.is_array() {
        *pretooluse = json!([]);
    }
    let pretooluse_arr = pretooluse
        .as_array_mut()
        .expect("PreToolUse coerced to array above");

    let desired_hooks = vec![command_hook(GUARD_COMMAND)];

    let existing_bash_entry = pretooluse_arr
        .iter_mut()
        .find(|entry| entry.get("matcher").and_then(Value::as_str) == Some(BASH_MATCHER));

    match existing_bash_entry {
        Some(entry) => {
            let current = entry.get("hooks").cloned().unwrap_or(json!([]));
            let desired = Value::Array(desired_hooks);
            if current != desired {
                entry["hooks"] = desired;
                report.pretooluse_bash_changed = true;
            }
        }
        None => {
            pretooluse_arr.push(json!({ "matcher": BASH_MATCHER, "hooks": desired_hooks }));
            report.pretooluse_bash_changed = true;
        }
    }

    let sessionstart = hooks_obj.entry("SessionStart").or_insert_with(|| json!([]));
    if !sessionstart.is_array() {
        *sessionstart = json!([]);
    }
    let sessionstart_arr = sessionstart
        .as_array_mut()
        .expect("SessionStart coerced to array above");

    let already_present = sessionstart_arr.iter().any(|entry| {
        entry
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|hooks| {
                hooks
                    .iter()
                    .any(|h| h.get("command").and_then(Value::as_str) == Some(HEALTH_COMMAND))
            })
    });

    if !already_present {
        match sessionstart_arr.first_mut() {
            Some(entry) => {
                let entry_obj = entry
                    .as_object_mut()
                    .expect("SessionStart entries are objects");
                let hooks_list = entry_obj.entry("hooks").or_insert_with(|| json!([]));
                if !hooks_list.is_array() {
                    *hooks_list = json!([]);
                }
                hooks_list
                    .as_array_mut()
                    .expect("hooks coerced to array above")
                    .push(command_hook(HEALTH_COMMAND));
            }
            None => {
                sessionstart_arr.push(json!({ "hooks": [command_hook(HEALTH_COMMAND)] }));
            }
        }
        report.sessionstart_health_inserted = true;
    }

    (settings, report)
}

/// Reads `paths.claude_settings_json()` (treating a missing file as `{}`),
/// backs it up to a sibling `.bak-pre-cerberus-init` file if it existed,
/// merges in cerberus's hook entries, and writes the result back.
pub fn install_hooks(paths: &Paths) -> io::Result<MergeReport> {
    let settings_path = paths.claude_settings_json();

    let existing = match fs::read_to_string(&settings_path) {
        Ok(raw) => {
            if let Some(parent) = settings_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(
                settings_path.with_file_name("settings.json.bak-pre-cerberus-init"),
                &raw,
            )?;
            serde_json::from_str(&raw).unwrap_or_else(|_| json!({}))
        }
        Err(_) => json!({}),
    };

    let (merged, report) = merge(existing);

    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&settings_path, serde_json::to_string_pretty(&merged)?)?;

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realistic_settings() -> Value {
        json!({
            "permissions": { "defaultMode": "bypassPermissions" },
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            { "type": "command", "command": "zsh ~/.claude/hooks/guard-gate.zsh" },
                            { "type": "command", "command": "zsh ~/.claude/hooks/guard-tirith.zsh" },
                            { "type": "command", "command": "zsh ~/.claude/hooks/guard-cupcake.zsh" },
                            { "type": "command", "command": "zsh ~/.claude/hooks/guard-context.zsh" }
                        ]
                    },
                    {
                        "matcher": "Read|Grep|Glob|WebFetch",
                        "hooks": [{ "type": "command", "command": "zsh ~/.claude/hooks/guard-cupcake.zsh" }]
                    },
                    {
                        "matcher": ".*",
                        "hooks": [{ "type": "command", "command": "pharos tmux dispatch tool" }]
                    },
                    {
                        "matcher": "AskUserQuestion",
                        "hooks": [{ "type": "command", "command": "pharos tmux dispatch ask" }]
                    }
                ],
                "SessionStart": [
                    {
                        "hooks": [
                            { "type": "command", "command": "zsh ~/.claude/hooks/guard-health.zsh" },
                            { "type": "command", "command": "psyche --format claude ~/SOUL.md" },
                            { "type": "command", "command": "pharos tmux dispatch off" }
                        ]
                    }
                ]
            },
            "theme": "dark-ansi"
        })
    }

    #[test]
    fn replaces_the_bash_matcher_with_a_single_guard_command() {
        let (merged, report) = merge(realistic_settings());
        assert!(report.pretooluse_bash_changed);

        let pretooluse = merged["hooks"]["PreToolUse"].as_array().unwrap();
        let bash_entry = pretooluse
            .iter()
            .find(|e| e["matcher"] == "Bash")
            .expect("Bash matcher entry present");
        let commands: Vec<&str> = bash_entry["hooks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["command"].as_str().unwrap())
            .collect();
        assert_eq!(commands, vec!["cerberus guard"]);
    }

    #[test]
    fn leaves_other_pretooluse_matchers_untouched() {
        let (merged, _) = merge(realistic_settings());
        let pretooluse = merged["hooks"]["PreToolUse"].as_array().unwrap();

        let unrelated = pretooluse
            .iter()
            .find(|e| e["matcher"] == "Read|Grep|Glob|WebFetch")
            .unwrap();
        assert_eq!(
            unrelated["hooks"][0]["command"],
            "zsh ~/.claude/hooks/guard-cupcake.zsh"
        );

        let dotstar = pretooluse.iter().find(|e| e["matcher"] == ".*").unwrap();
        assert_eq!(dotstar["hooks"][0]["command"], "pharos tmux dispatch tool");

        let ask = pretooluse
            .iter()
            .find(|e| e["matcher"] == "AskUserQuestion")
            .unwrap();
        assert_eq!(ask["hooks"][0]["command"], "pharos tmux dispatch ask");

        assert_eq!(pretooluse.len(), 4, "no matcher entries added or removed");
    }

    #[test]
    fn sessionstart_keeps_unrelated_commands_and_gains_health() {
        let (merged, report) = merge(realistic_settings());
        assert!(report.sessionstart_health_inserted);

        let commands: Vec<&str> = merged["hooks"]["SessionStart"][0]["hooks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["command"].as_str().unwrap())
            .collect();

        assert!(commands.contains(&"zsh ~/.claude/hooks/guard-health.zsh"));
        assert!(commands.contains(&"psyche --format claude ~/SOUL.md"));
        assert!(commands.contains(&"pharos tmux dispatch off"));
        assert!(commands.contains(&"cerberus health"));
        assert_eq!(commands.len(), 4);
    }

    #[test]
    fn unrelated_top_level_keys_survive() {
        let (merged, _) = merge(realistic_settings());
        assert_eq!(merged["theme"], "dark-ansi");
        assert_eq!(merged["permissions"]["defaultMode"], "bypassPermissions");
    }

    #[test]
    fn second_merge_is_a_no_op() {
        let (once, _) = merge(realistic_settings());
        let (twice, report) = merge(once.clone());
        assert!(!report.pretooluse_bash_changed);
        assert!(!report.sessionstart_health_inserted);
        assert_eq!(once, twice);
    }

    #[test]
    fn builds_hooks_from_scratch_when_settings_is_empty() {
        let (merged, report) = merge(json!({}));
        assert!(report.pretooluse_bash_changed);
        assert!(report.sessionstart_health_inserted);

        let pretooluse = merged["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pretooluse.len(), 1);
        assert_eq!(pretooluse[0]["matcher"], "Bash");
        assert_eq!(pretooluse[0]["hooks"][0]["command"], "cerberus guard");

        let sessionstart = merged["hooks"]["SessionStart"].as_array().unwrap();
        assert_eq!(sessionstart.len(), 1);
        assert_eq!(sessionstart[0]["hooks"][0]["command"], "cerberus health");
    }
}
