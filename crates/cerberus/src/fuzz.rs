//! Narrow entry points compiled only for coverage-guided fuzzing.

use crate::domain::{
    bash_command, is_deny, parse_json, permission_decision, permission_reason, str_field, tool_name,
};
use crate::harnesses::cursor;
use crate::heads::judgement::shell;

/// Exercises everything cerberus does with bytes it doesn't control: the hook
/// event a harness sends, the decision JSON a head sends back, Cursor's
/// payload translation, and the shell tokenizer the rules lean on.
pub fn hook_event(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);

    let _ = permission_decision(&text);
    let _ = permission_reason(&text);
    let _ = is_deny(&text);
    let _ = cursor::from_decision(&text);

    let event = parse_json(&text);
    let _ = tool_name(&event);
    let _ = str_field(&event, "cwd");
    let _ = str_field(&event, "session_id");
    let _ = cursor::to_canonical(&event);
    if let Some(command) = bash_command(&event) {
        let _ = shell::tokenize(command);
    }

    // A raw byte string is as plausible a shell command as one nested in JSON.
    let _ = shell::tokenize(&text);
}
