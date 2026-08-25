//! Cursor's own hook mechanism: subprocess/JSON like Claude Code and
//! Codex, but split across two events with two different payload shapes
//! (`beforeShellExecution`, `beforeMCPExecution`) instead of one unified
//! `tool_name`/`tool_input` envelope, and a different response vocabulary
//! (`permission` rather than `permissionDecision`). Every Cursor hook
//! payload carries a `hook_event_name` field cerberus dispatches on
//! directly (see `guard::run`), so no `--harness` flag is needed.
//!
//! Cursor has no pre-write file hook (only the post-hoc `afterFileEdit`),
//! so cerberus can only guard Cursor's Bash and MCP tool calls, never
//! Write/Edit/NotebookEdit. That's a permanent limit of Cursor's current
//! hook surface, not a gap in cerberus.
//!
//! Cursor's `hooks.json` is additive across scope layers (enterprise/team/
//! project/user all run), unlike Claude's single contested array, so
//! [`install_hooks`] only needs idempotent add-if-missing, not the
//! remove-then-prepend dance `settings::merge` does, though it still
//! prepends to keep cerberus first defensively.

use crate::hook::permission_decision;
use crate::settings::{GUARD_COMMAND, array_entry, install_into};
use serde_json::{Value, json};
use std::io;
use std::path::Path;

const BEFORE_SHELL_EXECUTION: &str = "beforeShellExecution";
const BEFORE_MCP_EXECUTION: &str = "beforeMCPExecution";

/// Reshapes a Cursor hook payload into the Claude-Code-shaped envelope
/// every existing head already understands, so `rules::engine`, `tirith`,
/// and `cupcake` need no Cursor awareness at all. `None` for any event
/// cerberus doesn't recognize (defensive: `init` only ever wires the two
/// above).
pub fn to_canonical(input: &Value) -> Option<Value> {
    match input.get("hook_event_name").and_then(Value::as_str) {
        Some(BEFORE_SHELL_EXECUTION) => Some(json!({
            "session_id": input.get("conversation_id"),
            "cwd": input.get("cwd"),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": input.get("command") },
        })),
        Some(BEFORE_MCP_EXECUTION) => Some(json!({
            "session_id": input.get("conversation_id"),
            "cwd": input.get("cwd").or_else(|| input.get("workspace_roots")?.get(0)),
            "hook_event_name": "PreToolUse",
            "tool_name": input.get("tool_name"),
            "tool_input": input.get("tool_input"),
        })),
        _ => None,
    }
}

/// Reshapes cerberus's Claude-shaped decision (whatever a head's
/// `pretooluse_deny`-style output was) into Cursor's own
/// `{"permission", "user_message", "agent_message"}` response. `None`
/// means allow: nothing to print, same convention as the Claude/Codex
/// path.
pub fn from_decision(decision_output: &str) -> Option<String> {
    let permission = match permission_decision(decision_output)?.as_str() {
        "deny" => "deny",
        "ask" => "ask",
        _ => return None,
    };
    let reason = serde_json::from_str::<Value>(decision_output)
        .ok()
        .and_then(|v| {
            v.get("hookSpecificOutput")?
                .get("permissionDecisionReason")?
                .as_str()
                .map(String::from)
        })
        .unwrap_or_default();
    Some(
        json!({
            "permission": permission,
            "user_message": reason,
            "agent_message": reason,
        })
        .to_string(),
    )
}

/// What [`merge`] changed, mirroring `settings::MergeReport`'s role for
/// Claude/Codex.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub before_shell_execution_changed: bool,
    pub before_mcp_execution_changed: bool,
}

fn merge_event(hooks: &mut Value, event: &str) -> bool {
    let entries = array_entry(hooks, event);
    let before = entries.clone();
    entries.retain(|h| h.get("command").and_then(Value::as_str) != Some(GUARD_COMMAND));
    entries.insert(0, json!({ "command": GUARD_COMMAND }));
    *entries != before
}

/// Merges cerberus's own entries into an existing (or fresh) Cursor
/// `hooks.json` value. Pure function, same testability rationale as
/// `settings::merge`.
fn merge(hooks_json: Value) -> (Value, MergeReport) {
    let mut hooks_json = if hooks_json.is_object() {
        hooks_json
    } else {
        json!({})
    };

    let obj = hooks_json.as_object_mut().expect("coerced to object above");
    obj.entry("version").or_insert(json!(1));
    let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }

    let before_shell_execution_changed = merge_event(hooks, BEFORE_SHELL_EXECUTION);
    let before_mcp_execution_changed = merge_event(hooks, BEFORE_MCP_EXECUTION);

    (
        hooks_json,
        MergeReport {
            before_shell_execution_changed,
            before_mcp_execution_changed,
        },
    )
}

/// Installs cerberus's hooks into Cursor's `hooks.json`. See
/// `settings::install_into` for the shared file-handling contract.
pub fn install_hooks(hooks_path: &Path) -> io::Result<MergeReport> {
    install_into(hooks_path, merge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_execution_becomes_a_bash_envelope() {
        let input = json!({
            "hook_event_name": "beforeShellExecution",
            "conversation_id": "conv-1",
            "command": "rm -rf /",
            "cwd": "/repo",
            "sandbox": false,
        });
        let canonical = to_canonical(&input).unwrap();
        assert_eq!(canonical["session_id"], "conv-1");
        assert_eq!(canonical["cwd"], "/repo");
        assert_eq!(canonical["tool_name"], "Bash");
        assert_eq!(canonical["tool_input"]["command"], "rm -rf /");
    }

    #[test]
    fn mcp_execution_carries_tool_name_and_input_through() {
        let input = json!({
            "hook_event_name": "beforeMCPExecution",
            "conversation_id": "conv-2",
            "tool_name": "mcp__fs__write",
            "tool_input": { "file_path": "/repo/x" },
            "mcp_server_name": "fs",
            "workspace_roots": ["/repo"],
        });
        let canonical = to_canonical(&input).unwrap();
        assert_eq!(canonical["tool_name"], "mcp__fs__write");
        assert_eq!(canonical["tool_input"]["file_path"], "/repo/x");
        // No top-level cwd on this event: falls back to workspace_roots[0].
        assert_eq!(canonical["cwd"], "/repo");
    }

    #[test]
    fn mcp_execution_prefers_an_explicit_cwd_over_workspace_roots() {
        let input = json!({
            "hook_event_name": "beforeMCPExecution",
            "cwd": "/explicit",
            "workspace_roots": ["/repo"],
            "tool_name": "mcp__fs__write",
            "tool_input": {},
        });
        let canonical = to_canonical(&input).unwrap();
        assert_eq!(canonical["cwd"], "/explicit");
    }

    #[test]
    fn unrecognized_events_are_not_translated() {
        assert!(to_canonical(&json!({ "hook_event_name": "afterFileEdit" })).is_none());
        assert!(to_canonical(&json!({})).is_none());
    }

    #[test]
    fn from_decision_maps_deny_to_cursor_permission_shape() {
        let deny = crate::hook::pretooluse_deny("dangerous command");
        let output = from_decision(&deny).unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["permission"], "deny");
        assert_eq!(parsed["user_message"], "dangerous command");
        assert_eq!(parsed["agent_message"], "dangerous command");
    }

    #[test]
    fn from_decision_maps_ask_and_passes_through_allow_as_none() {
        let ask = json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": "needs confirmation",
            }
        })
        .to_string();
        let output = from_decision(&ask).unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["permission"], "ask");

        assert_eq!(
            from_decision(r#"{"hookSpecificOutput":{"permissionDecision":"allow"}}"#),
            None
        );
        assert_eq!(from_decision("not json"), None);
    }

    #[test]
    fn merge_adds_both_events_and_is_idempotent() {
        let (once, report) = merge(json!({}));
        assert!(report.before_shell_execution_changed);
        assert!(report.before_mcp_execution_changed);
        assert_eq!(once["version"], 1);
        assert_eq!(
            once["hooks"]["beforeShellExecution"][0]["command"],
            GUARD_COMMAND
        );
        assert_eq!(
            once["hooks"]["beforeMCPExecution"][0]["command"],
            GUARD_COMMAND
        );

        let (twice, report2) = merge(once.clone());
        assert!(!report2.before_shell_execution_changed);
        assert!(!report2.before_mcp_execution_changed);
        assert_eq!(once, twice);
    }

    #[test]
    fn merge_leaves_other_entries_and_layers_alone() {
        let existing = json!({
            "version": 1,
            "hooks": {
                "beforeShellExecution": [
                    { "command": "./hooks/log-shell.sh" }
                ],
                "afterFileEdit": [
                    { "command": "./hooks/format.sh" }
                ]
            }
        });
        let (merged, _) = merge(existing);
        let shell = merged["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(shell.len(), 2, "cerberus prepends, doesn't replace");
        assert_eq!(shell[0]["command"], GUARD_COMMAND);
        assert_eq!(shell[1]["command"], "./hooks/log-shell.sh");
        assert_eq!(
            merged["hooks"]["afterFileEdit"][0]["command"],
            "./hooks/format.sh"
        );
    }
}
