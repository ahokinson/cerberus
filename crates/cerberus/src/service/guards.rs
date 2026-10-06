use crate::config;
use crate::config::Paths;
use crate::domain::Head;
use crate::domain::{parse_json, read_stdin_raw, str_field};
use crate::harnesses::cursor;
use crate::heads;
use crate::ports::{HeadEvaluator, ToolCall};
use crate::service::gates;
use crate::state::audits as audit;
use crate::state::violations;
use std::path::PathBuf;

/// Walks `heads` in order and returns the first one that responds along
/// with its output. `None` means every enabled head allowed. Kept separate
/// from `run` so it's testable with fake heads instead of real
/// stdin/subprocesses.
fn dispatch(heads: &[Box<dyn HeadEvaluator + '_>], call: &ToolCall) -> Option<(Head, String)> {
    heads
        .iter()
        .find_map(|head| head.evaluate(call).map(|output| (head.head(), output)))
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
    if let Some(output) = gates::evaluate(&paths.degraded_sentinel()) {
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

    let heads = heads::evaluators(paths, &config::enabled_heads(paths));
    let call = ToolCall {
        input: &input,
        raw: &raw_for_policy,
        cwd: &cwd,
    };
    let result = dispatch(&heads, &call);

    if let Some((head, output)) = result {
        violations::record_if_denied(paths, session_id, head, &output);
        audit::record(paths, head, &input, &output, is_cursor);
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
    use serde_json::Value;
    use std::cell::RefCell;
    use std::path::Path;
    use std::rc::Rc;

    /// A head that answers with a canned decision and logs that it was asked.
    struct Fake {
        head: Head,
        answer: Option<&'static str>,
        asked: Rc<RefCell<Vec<Head>>>,
    }

    impl HeadEvaluator for Fake {
        fn head(&self) -> Head {
            self.head
        }

        fn evaluate(&self, _call: &ToolCall) -> Option<String> {
            self.asked.borrow_mut().push(self.head);
            self.answer.map(String::from)
        }
    }

    type AskedLog = Rc<RefCell<Vec<Head>>>;

    fn fakes(script: &[(Head, Option<&'static str>)]) -> (Vec<Box<dyn HeadEvaluator>>, AskedLog) {
        let asked = Rc::new(RefCell::new(Vec::new()));
        let heads = script
            .iter()
            .map(|&(head, answer)| -> Box<dyn HeadEvaluator> {
                Box::new(Fake {
                    head,
                    answer,
                    asked: Rc::clone(&asked),
                })
            })
            .collect();
        (heads, asked)
    }

    fn call() -> (Value, std::path::PathBuf) {
        (Value::Null, Path::new("/").to_path_buf())
    }

    #[test]
    fn stops_at_the_first_head_that_responds() {
        let (heads, asked) = fakes(&[
            (Head::Risk, None),
            (Head::Policy, Some("denied by policy")),
            (Head::Judgement, Some("never reached")),
        ]);
        let (input, cwd) = call();
        let result = dispatch(
            &heads,
            &ToolCall {
                input: &input,
                raw: "",
                cwd: &cwd,
            },
        );
        assert_eq!(result, Some((Head::Policy, "denied by policy".to_string())));
        assert_eq!(*asked.borrow(), vec![Head::Risk, Head::Policy]);
    }

    #[test]
    fn returns_none_when_every_head_allows() {
        let (heads, _) = fakes(&[
            (Head::Risk, None),
            (Head::Policy, None),
            (Head::Judgement, None),
        ]);
        let (input, cwd) = call();
        let result = dispatch(
            &heads,
            &ToolCall {
                input: &input,
                raw: "",
                cwd: &cwd,
            },
        );
        assert_eq!(result, None);
    }

    #[test]
    fn only_walks_the_heads_it_is_given() {
        let (heads, asked) = fakes(&[(Head::Judgement, Some("denied"))]);
        let (input, cwd) = call();
        let result = dispatch(
            &heads,
            &ToolCall {
                input: &input,
                raw: "",
                cwd: &cwd,
            },
        );
        assert_eq!(*asked.borrow(), vec![Head::Judgement]);
        assert_eq!(result, Some((Head::Judgement, "denied".to_string())));
    }
}
