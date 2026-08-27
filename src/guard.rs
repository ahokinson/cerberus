use crate::config;
use crate::gate;
use crate::harness::cursor;
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

/// The single `PreToolUse`-equivalent command every wired harness calls:
/// `gate` runs first, unconditionally; if it allows, the heads enabled in
/// `config::enabled_heads` run in their fixed order, stopping at the first
/// one that responds (deny or ask).
///
/// Cursor's payload shape differs enough from Claude/Codex's that it needs
/// translating into their shared envelope before anything downstream sees
/// it (`harness::cursor::to_canonical`). Every other harness takes today's
/// path completely unchanged, including Codex, whose shape already
/// matches Claude's byte-for-byte. Dispatch is self-describing from the
/// payload's own `hook_event_name`, so `cerberus guard` needs no
/// `--harness` flag: the identical command line works verbatim in every
/// harness's hook config.
pub fn run(paths: &Paths) {
    if let Some(output) = gate::evaluate(&paths.degraded_sentinel()) {
        println!("{output}");
        return;
    }

    let raw = read_stdin_raw();
    let parsed = parse_json(&raw);

    let canonical = cursor::to_canonical(&parsed);
    let is_cursor = canonical.is_some();
    let input = canonical.unwrap_or(parsed);
    // cupcake forwards its input verbatim; for a translated payload
    // "verbatim" has to mean the canonical envelope, since that's the only
    // shape cerberus's own Rego policies (and cupcake's `--harness claude`
    // store) understand.
    let raw_for_policy = if is_cursor { input.to_string() } else { raw };

    let cwd: PathBuf = str_field(&input, "cwd")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let session_id = str_field(&input, "session_id");

    let heads = config::enabled_heads(paths);
    let result = dispatch(&heads, |head| match head {
        Head::Risk => tirith::evaluate(paths, &cwd, &input),
        Head::Policy => cupcake::evaluate(&paths.cupcake_stub(), &raw_for_policy),
        Head::Judgement => rules::evaluate(paths, &input, &cwd),
    });

    if let Some((head, output)) = result {
        violations::record_if_denied(paths, session_id, head, &output);
        let printed = if is_cursor {
            cursor::from_decision(&output)
        } else {
            Some(output)
        };
        if let Some(text) = printed {
            println!("{text}");
        }
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
