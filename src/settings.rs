use crate::paths::Paths;
use serde_json::{Value, json};
use std::fs;
use std::io;

/// The tools `cerberus guard` is wired to judge: the ones that change state
/// or reach the network. The read-only tools (Read, Grep, Glob) are
/// deliberately absent — nothing they do is worth denying, and keeping the
/// hook off the hottest tools in a session is what lets `guard` stay a
/// subprocess-per-call design without a cache.
const GUARD_MATCHER: &str = "Bash|Write|Edit|NotebookEdit|WebFetch|mcp__.*";
const GUARD_COMMAND: &str = "cerberus guard";
const HEALTH_COMMAND: &str = "cerberus health";

/// What [`merge`] actually changed, so `init` can report it to the user.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub pretooluse_changed: bool,
    pub sessionstart_changed: bool,
}

fn command_hook(command: &str) -> Value {
    json!({ "type": "command", "command": command })
}

/// Coerces `parent[key]` to an array and hands it back, replacing whatever
/// was there if it wasn't one.
fn array_entry<'a>(parent: &'a mut Value, key: &str) -> &'a mut Vec<Value> {
    let slot = parent
        .as_object_mut()
        .expect("caller coerced parent to an object")
        .entry(key)
        .or_insert_with(|| json!([]));
    if !slot.is_array() {
        *slot = json!([]);
    }
    slot.as_array_mut().expect("coerced to array above")
}

/// Strips every hook running `command` out of a hook-event array, dropping
/// any entry left with no hooks at all.
///
/// The remove half of cerberus's remove-then-prepend wiring. It's keyed on
/// the command string, never on the matcher, which is what keeps the
/// invariant honest: the only hooks cerberus can possibly touch are ones
/// running a cerberus command, i.e. ones cerberus wrote. An entry it shares
/// with somebody else's hooks survives, minus cerberus's own.
fn remove_command(entries: &mut Vec<Value>, command: &str) {
    for entry in entries.iter_mut() {
        let Some(hooks) = entry.get_mut("hooks").and_then(Value::as_array_mut) else {
            continue;
        };
        hooks.retain(|hook| hook.get("command").and_then(Value::as_str) != Some(command));
    }
    entries.retain(|entry| match entry.get("hooks").and_then(Value::as_array) {
        Some(hooks) => !hooks.is_empty(),
        // An entry with no `hooks` key at all isn't ours to judge.
        None => true,
    });
}

/// Merges cerberus's own hook entries into an existing (or fresh)
/// `settings.json` value. Pure function: no I/O, so it's fully testable
/// against fabricated `Value`s shaped like the real file.
///
/// **cerberus owns no hook slot.** It never removes or modifies a hook it
/// didn't write; the only hooks it touches are the ones running
/// `cerberus guard` or `cerberus health`. Both events get the same
/// remove-then-prepend treatment:
///
/// 1. strip cerberus's command from every entry in the array, dropping any
///    entry left empty, then
/// 2. prepend cerberus's own single-hook entry at index 0, so the guard
///    runs first in the slot.
///
/// That shape buys three things. It's idempotent by construction (the
/// second run removes and re-adds exactly what the first left). It makes
/// changing [`GUARD_MATCHER`] a free migration, since the old entry is
/// found by its command rather than by a matcher string that just changed.
/// And it can't clobber a third party: an unrelated `.*` entry, or a
/// SessionStart entry cerberus happens to share, keeps everything except
/// cerberus's own hook.
pub fn merge(settings: Value) -> (Value, MergeReport) {
    let mut settings = if settings.is_object() {
        settings
    } else {
        json!({})
    };

    let obj = settings
        .as_object_mut()
        .expect("settings coerced to object above");
    let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }

    let pretooluse = array_entry(hooks, "PreToolUse");
    let before_pretooluse = pretooluse.clone();
    remove_command(pretooluse, GUARD_COMMAND);
    pretooluse.insert(
        0,
        json!({ "matcher": GUARD_MATCHER, "hooks": [command_hook(GUARD_COMMAND)] }),
    );
    let pretooluse_changed = *pretooluse != before_pretooluse;

    let sessionstart = array_entry(hooks, "SessionStart");
    let before_sessionstart = sessionstart.clone();
    remove_command(sessionstart, HEALTH_COMMAND);
    sessionstart.insert(0, json!({ "hooks": [command_hook(HEALTH_COMMAND)] }));
    let sessionstart_changed = *sessionstart != before_sessionstart;

    let report = MergeReport {
        pretooluse_changed,
        sessionstart_changed,
    };
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

    /// The shape `cerberus init` leaves behind, as it looked before this
    /// wiring was self-managing: guard under a bare `Bash` matcher, health
    /// buried inside the shared SessionStart entry.
    fn already_installed_the_old_way() -> Value {
        json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Bash", "hooks": [{ "type": "command", "command": "cerberus guard" }] },
                    { "matcher": ".*", "hooks": [{ "type": "command", "command": "pharos tmux dispatch tool" }] }
                ],
                "SessionStart": [
                    {
                        "hooks": [
                            { "type": "command", "command": "cerberus health" },
                            { "type": "command", "command": "psyche --format claude ~/SOUL.md" }
                        ]
                    }
                ]
            }
        })
    }

    fn commands_in(entry: &Value) -> Vec<&str> {
        entry["hooks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["command"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn guard_runs_first_on_pretooluse_with_the_wide_matcher() {
        let (merged, report) = merge(realistic_settings());
        assert!(report.pretooluse_changed);

        let first = &merged["hooks"]["PreToolUse"][0];
        assert_eq!(first["matcher"], GUARD_MATCHER);
        assert_eq!(commands_in(first), vec!["cerberus guard"]);
    }

    #[test]
    fn health_runs_first_on_sessionstart_in_its_own_entry() {
        let (merged, report) = merge(realistic_settings());
        assert!(report.sessionstart_changed);

        let first = &merged["hooks"]["SessionStart"][0];
        assert_eq!(commands_in(first), vec!["cerberus health"]);
    }

    #[test]
    fn leaves_other_pretooluse_matchers_untouched() {
        let before = realistic_settings();
        let (merged, _) = merge(before.clone());
        let pretooluse = merged["hooks"]["PreToolUse"].as_array().unwrap();

        // Every entry the input had, byte-identical, still present.
        for original in before["hooks"]["PreToolUse"].as_array().unwrap() {
            assert!(
                pretooluse.contains(original),
                "entry was modified or dropped: {original}"
            );
        }
        // Notably the `.*` entry, which the old matcher-keyed merge would
        // have clobbered the moment GUARD_MATCHER stopped being "Bash".
        let dotstar = pretooluse.iter().find(|e| e["matcher"] == ".*").unwrap();
        assert_eq!(dotstar["hooks"][0]["command"], "pharos tmux dispatch tool");

        assert_eq!(pretooluse.len(), 5, "exactly one entry added");
    }

    #[test]
    fn sessionstart_keeps_unrelated_commands() {
        let (merged, _) = merge(realistic_settings());
        let shared = &merged["hooks"]["SessionStart"][1];
        assert_eq!(
            commands_in(shared),
            vec![
                "zsh ~/.claude/hooks/guard-health.zsh",
                "psyche --format claude ~/SOUL.md",
                "pharos tmux dispatch off",
            ]
        );
    }

    #[test]
    fn an_old_install_is_migrated_rather_than_orphaned() {
        let (merged, report) = merge(already_installed_the_old_way());
        assert!(report.pretooluse_changed);
        assert!(report.sessionstart_changed);

        let pretooluse = merged["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(
            pretooluse.len(),
            2,
            "the old Bash entry was reused, not left behind"
        );
        assert_eq!(pretooluse[0]["matcher"], GUARD_MATCHER);
        assert!(
            !pretooluse.iter().any(|e| e["matcher"] == "Bash"),
            "a stale Bash entry would run guard twice: {pretooluse:?}"
        );
        assert_eq!(
            pretooluse[1]["hooks"][0]["command"],
            "pharos tmux dispatch tool"
        );

        // health is hoisted out of the shared entry, which keeps psyche.
        let sessionstart = merged["hooks"]["SessionStart"].as_array().unwrap();
        assert_eq!(commands_in(&sessionstart[0]), vec!["cerberus health"]);
        assert_eq!(
            commands_in(&sessionstart[1]),
            vec!["psyche --format claude ~/SOUL.md"]
        );
    }

    #[test]
    fn an_entry_left_empty_by_removal_is_dropped() {
        // cerberus's own entry from a previous install, alone in the array.
        // Removing its hook empties it, so it must not linger as `{}`.
        let (merged, _) = merge(json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash", "hooks": [{ "type": "command", "command": "cerberus guard" }] }
            ]}
        }));
        let pretooluse = merged["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pretooluse.len(), 1);
        assert_eq!(pretooluse[0]["matcher"], GUARD_MATCHER);
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
        assert!(!report.pretooluse_changed);
        assert!(!report.sessionstart_changed);
        assert_eq!(once, twice);
    }

    #[test]
    fn builds_hooks_from_scratch_when_settings_is_empty() {
        let (merged, report) = merge(json!({}));
        assert!(report.pretooluse_changed);
        assert!(report.sessionstart_changed);

        let pretooluse = merged["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pretooluse.len(), 1);
        assert_eq!(pretooluse[0]["matcher"], GUARD_MATCHER);
        assert_eq!(pretooluse[0]["hooks"][0]["command"], "cerberus guard");

        let sessionstart = merged["hooks"]["SessionStart"].as_array().unwrap();
        assert_eq!(sessionstart.len(), 1);
        assert_eq!(sessionstart[0]["hooks"][0]["command"], "cerberus health");
    }

    #[test]
    fn the_guard_matcher_covers_the_mutating_tools_and_not_the_read_only_ones() {
        // Guarding by matcher is what keeps guard off the hot read path, so
        // the split is load-bearing, not cosmetic.
        for tool in ["Bash", "Write", "Edit", "NotebookEdit", "WebFetch"] {
            assert!(
                GUARD_MATCHER.split('|').any(|alt| alt == tool),
                "{tool} should be guarded"
            );
        }
        for tool in ["Read", "Grep", "Glob", "Task", "TodoWrite", "WebSearch"] {
            assert!(
                !GUARD_MATCHER.split('|').any(|alt| alt == tool),
                "{tool} should not be guarded"
            );
        }
        assert!(GUARD_MATCHER.split('|').any(|alt| alt == "mcp__.*"));
    }
}
