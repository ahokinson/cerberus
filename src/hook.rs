use serde_json::{Value, json};
use std::io::Read;

/// Reads stdin to a raw string. `guard` needs this form (not just parsed
/// JSON) because `cupcake::evaluate` forwards the hook event to the
/// `cupcake` subprocess verbatim rather than re-serializing it.
pub fn read_stdin_raw() -> String {
    let mut buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut buf);
    buf
}

/// Parses a raw hook event string as JSON per Claude Code's hook input
/// contract. Empty or invalid input returns `Value::Null`, not an error, so
/// callers fall through their normal "field missing" handling rather than
/// erroring.
pub fn parse_json(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or(Value::Null)
}

pub fn str_field<'a>(input: &'a Value, field: &str) -> Option<&'a str> {
    input
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

pub fn tool_input_command(input: &Value) -> Option<&str> {
    input
        .get("tool_input")
        .and_then(|t| t.get("command"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// The tool this hook event is about, e.g. `"Bash"`, `"Write"`,
/// `"mcp__foo__bar"`. cerberus is wired to more than Bash now, so heads that
/// only make sense for one tool have to say so rather than inferring it from
/// which `tool_input` fields happen to be present.
pub fn tool_name(input: &Value) -> Option<&str> {
    str_field(input, "tool_name")
}

/// `tool_input.command`, but only for the Bash tool.
///
/// The `tool_name` gate is not cosmetic. An MCP tool may carry its own
/// `tool_input.command` meaning something entirely non-shell (`"deploy"`,
/// say); handing that to tirith's command-pattern scanner or to
/// `shell::tokenize` would invent findings out of a string that was never a
/// shell command. A missing `tool_name` is treated as Bash so hand-fed
/// events and the synthetic health canaries keep working.
pub fn bash_command(input: &Value) -> Option<&str> {
    match tool_name(input) {
        Some("Bash") | None => tool_input_command(input),
        Some(_) => None,
    }
}

pub fn pretooluse_deny(reason: &str) -> String {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    })
    .to_string()
}

pub fn sessionstart_context(context: &str) -> String {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context,
        }
    })
    .to_string()
}

/// Pulls `hookSpecificOutput.permissionDecision` out of any head's output
/// JSON (a `pretooluse_deny` result, or cupcake's own forwarded output).
/// Shared home for this since it's about the hook JSON shape itself, not
/// any one head.
pub fn permission_decision(output: &str) -> Option<String> {
    serde_json::from_str::<Value>(output).ok().and_then(|v| {
        v.get("hookSpecificOutput")?
            .get("permissionDecision")?
            .as_str()
            .map(String::from)
    })
}

pub fn is_deny(output: &str) -> bool {
    permission_decision(output).as_deref() == Some("deny")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_field_returns_none_for_missing_or_empty() {
        let v = json!({ "a": "", "b": "x" });
        assert_eq!(str_field(&v, "a"), None);
        assert_eq!(str_field(&v, "b"), Some("x"));
        assert_eq!(str_field(&v, "missing"), None);
    }

    #[test]
    fn tool_input_command_extraction() {
        assert_eq!(
            tool_input_command(&json!({ "tool_input": { "command": "ls" } })),
            Some("ls")
        );
        assert_eq!(tool_input_command(&json!({})), None);
        assert_eq!(
            tool_input_command(&json!({ "tool_input": { "command": "" } })),
            None
        );
    }

    #[test]
    fn bash_command_reads_the_command_for_the_bash_tool() {
        let v = json!({ "tool_name": "Bash", "tool_input": { "command": "ls" } });
        assert_eq!(bash_command(&v), Some("ls"));
    }

    #[test]
    fn bash_command_is_none_for_other_tools() {
        // A Write event has no command at all.
        let write = json!({ "tool_name": "Write", "tool_input": { "file_path": "/x" } });
        assert_eq!(bash_command(&write), None);
        // An MCP tool may have a `command` that isn't a shell command. It must
        // never reach tirith or the tokenizer.
        let mcp = json!({ "tool_name": "mcp__deploy__run", "tool_input": { "command": "deploy" } });
        assert_eq!(bash_command(&mcp), None);
    }

    #[test]
    fn bash_command_treats_a_missing_tool_name_as_bash() {
        let v = json!({ "tool_input": { "command": "ls" } });
        assert_eq!(bash_command(&v), Some("ls"));
    }

    #[test]
    fn tool_name_extraction() {
        assert_eq!(tool_name(&json!({ "tool_name": "Write" })), Some("Write"));
        assert_eq!(tool_name(&json!({ "tool_name": "" })), None);
        assert_eq!(tool_name(&json!({})), None);
    }

    #[test]
    fn pretooluse_deny_shape() {
        let out: Value = serde_json::from_str(&pretooluse_deny("nope")).unwrap();
        assert_eq!(out["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            out["hookSpecificOutput"]["permissionDecisionReason"],
            "nope"
        );
    }

    #[test]
    fn permission_decision_extracts_any_decision_kind() {
        assert_eq!(
            permission_decision(r#"{"hookSpecificOutput":{"permissionDecision":"ask"}}"#),
            Some("ask".to_string())
        );
        assert_eq!(
            permission_decision(r#"{"hookSpecificOutput":{"permissionDecision":"allow"}}"#),
            Some("allow".to_string())
        );
        assert_eq!(permission_decision(r#"{"hookSpecificOutput":{}}"#), None);
        assert_eq!(permission_decision("not json"), None);
        assert_eq!(permission_decision(""), None);
    }

    #[test]
    fn is_deny_true_only_for_deny_decision() {
        assert!(is_deny(
            r#"{"hookSpecificOutput":{"permissionDecision":"deny"}}"#
        ));
        assert!(!is_deny(
            r#"{"hookSpecificOutput":{"permissionDecision":"ask"}}"#
        ));
        assert!(!is_deny(
            r#"{"hookSpecificOutput":{"permissionDecision":"allow"}}"#
        ));
        assert!(!is_deny(r#"{"hookSpecificOutput":{}}"#));
        assert!(!is_deny("not json"));
        assert!(!is_deny(""));
    }
}
