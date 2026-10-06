use serde_json::{Value, json};

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

/// Pulls `hookSpecificOutput.permissionDecisionReason` out of any head's
/// output JSON, mirroring [`permission_decision`]. Used by the audit log
/// (`src/audit.rs`) to record *why* a call was denied, not just that it was.
pub fn permission_reason(output: &str) -> Option<String> {
    serde_json::from_str::<Value>(output).ok().and_then(|v| {
        v.get("hookSpecificOutput")?
            .get("permissionDecisionReason")?
            .as_str()
            .map(String::from)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn permission_reason_extracts_the_reason_string() {
        assert_eq!(
            permission_reason(
                r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"nope"}}"#
            ),
            Some("nope".to_string())
        );
        assert_eq!(
            permission_reason(r#"{"hookSpecificOutput":{"permissionDecision":"deny"}}"#),
            None
        );
        assert_eq!(permission_reason("not json"), None);
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
