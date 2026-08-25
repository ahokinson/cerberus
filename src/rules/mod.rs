pub mod engine;
mod environment;
mod git;
mod shell;
pub mod tool;

use crate::hook::{bash_command, pretooluse_deny};
use serde_json::Value;
use std::path::Path;

/// The `judgement` part of `guard`: loads every `*.rhai` rule script in
/// `rules_dir` and runs each one's `check(cmd, cwd, input)` in turn,
/// denying on the first one that returns a string. The scripts do the
/// situational judgement (git state, kubectl/terraform context, the hook
/// payload itself); `engine::build_engine` is what exposes those queries and
/// command tokenizing to them. See `CONTRIBUTING.md` for the native
/// function API and how to add a rule.
///
/// This is the only head that runs on every tool `guard` is wired for, so
/// `cmd` is `""` rather than absent for a non-Bash call: a script reaches
/// the tool it's actually looking at through `input.tool_name` and
/// `tool_paths(input)`. Bailing out here on a missing command (as this used
/// to) would silently no-op every rule on every `Write`, `Edit`, and
/// `WebFetch`.
pub fn evaluate(rules_dir: &Path, input: &Value, cwd: &Path) -> Option<String> {
    let cmd = bash_command(input).unwrap_or("");
    let reason = engine::evaluate(rules_dir, cmd, cwd, input)?;
    Some(pretooluse_deny(&reason))
}
