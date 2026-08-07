pub mod engine;
mod environment;
mod git;
mod shell;

use crate::hook::{pretooluse_deny, tool_input_command};
use serde_json::Value;
use std::path::Path;

/// The `judgement` part of `guard`: loads every `*.rhai` rule script in
/// `rules_dir` and runs each one's `check(cmd, cwd, input)` in turn,
/// denying on the first one that returns a string. The scripts do the
/// situational judgement (git state, kubectl/terraform context, the hook
/// payload itself); `engine::build_engine` is what exposes those queries and
/// command tokenizing to them. See `CONTRIBUTING.md` for the native
/// function API and how to add a rule.
pub fn evaluate(rules_dir: &Path, input: &Value, cwd: &Path) -> Option<String> {
    let cmd = tool_input_command(input)?;
    let reason = engine::evaluate(rules_dir, cmd, cwd, input)?;
    Some(pretooluse_deny(&reason))
}
