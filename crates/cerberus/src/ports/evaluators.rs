use crate::domain::Head;
use serde_json::Value;
use std::path::Path;

/// One tool call as the heads see it, after any harness translation.
pub struct ToolCall<'a> {
    /// The canonical (Claude-shaped) hook event.
    pub input: &'a Value,
    /// The event text cupcake gets verbatim; differs from `input` only for
    /// harnesses whose payload was translated.
    pub raw: &'a str,
    pub cwd: &'a Path,
}

/// What `guard` asks of each head: look at a call and either stay silent
/// (`None`, allow) or answer with the hook output JSON (deny or ask).
/// Implemented by `risk`, `policy` and `judgement` in `heads`.
pub trait HeadEvaluator {
    fn head(&self) -> Head;
    fn evaluate(&self, call: &ToolCall) -> Option<String>;
}
