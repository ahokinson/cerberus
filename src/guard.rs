use crate::config;
use crate::gate;
use crate::head::Head;
use crate::hook::{parse_json, read_stdin_raw, str_field};
use crate::integrations::{cupcake, tirith};
use crate::paths::Paths;
use crate::rules;
use crate::violations;
use std::path::PathBuf;

/// Walks `heads` in order, calling `evaluate_head`, and returns the first
/// one that responds along with its output. `None` means every enabled
/// head allowed. Kept separate from `run` so it's testable with fake
/// per-head decisions instead of real stdin/subprocesses.
fn dispatch(
    heads: &[Head],
    mut evaluate_head: impl FnMut(Head) -> Option<String>,
) -> Option<(Head, String)> {
    for &head in heads {
        if let Some(output) = evaluate_head(head) {
            return Some((head, output));
        }
    }
    None
}

/// The single `PreToolUse` command Claude Code calls for Bash: `gate` runs
/// first, unconditionally; if it allows, the heads enabled in
/// `config::enabled_heads` run in their fixed order, stopping at the first
/// one that responds (deny or ask).
pub fn run(paths: &Paths) {
    if let Some(output) = gate::evaluate(&paths.degraded_sentinel()) {
        println!("{output}");
        return;
    }

    let raw = read_stdin_raw();
    let input = parse_json(&raw);
    let cwd: PathBuf = str_field(&input, "cwd")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let session_id = str_field(&input, "session_id");

    let heads = config::enabled_heads(paths);
    let result = dispatch(&heads, |head| match head {
        Head::Risk => tirith::evaluate(paths, &cwd, &input),
        Head::Policy => cupcake::evaluate(&paths.cupcake_stub(), &raw),
        Head::Judgement => rules::evaluate(&paths.rule_scripts_dir(), &input, &cwd),
    });

    if let Some((head, output)) = result {
        violations::respond(paths, session_id, head, &output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stops_at_the_first_head_that_responds() {
        let heads = [Head::Risk, Head::Policy, Head::Judgement];
        let mut called = Vec::new();
        let result = dispatch(&heads, |head| {
            called.push(head);
            if head == Head::Policy {
                Some("denied by policy".to_string())
            } else {
                None
            }
        });
        assert_eq!(result, Some((Head::Policy, "denied by policy".to_string())));
        assert_eq!(called, vec![Head::Risk, Head::Policy]);
    }

    #[test]
    fn returns_none_when_every_head_allows() {
        let heads = [Head::Risk, Head::Policy, Head::Judgement];
        let result = dispatch(&heads, |_| None);
        assert_eq!(result, None);
    }

    #[test]
    fn only_walks_the_heads_it_is_given() {
        let heads = [Head::Judgement];
        let mut called = Vec::new();
        let result = dispatch(&heads, |head| {
            called.push(head);
            Some("denied".to_string())
        });
        assert_eq!(called, vec![Head::Judgement]);
        assert_eq!(result, Some((Head::Judgement, "denied".to_string())));
    }
}
