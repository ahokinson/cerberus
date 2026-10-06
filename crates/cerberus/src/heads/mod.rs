pub mod judgement;
pub mod policy;
pub mod risk;

use crate::config::Paths;
use crate::domain::Head;
use crate::ports::{HeadEvaluator, ToolCall};

struct Risk<'a>(&'a Paths);
struct Policy<'a>(&'a Paths);
struct Judgement<'a>(&'a Paths);

impl HeadEvaluator for Risk<'_> {
    fn head(&self) -> Head {
        Head::Risk
    }

    fn evaluate(&self, call: &ToolCall) -> Option<String> {
        risk::evaluate(self.0, call.cwd, call.input)
    }
}

impl HeadEvaluator for Policy<'_> {
    fn head(&self) -> Head {
        Head::Policy
    }

    fn evaluate(&self, call: &ToolCall) -> Option<String> {
        policy::evaluate(self.0, call.raw)
    }
}

impl HeadEvaluator for Judgement<'_> {
    fn head(&self) -> Head {
        Head::Judgement
    }

    fn evaluate(&self, call: &ToolCall) -> Option<String> {
        judgement::evaluate(self.0, call.input, call.cwd)
    }
}

/// The evaluator for each of `heads`, in the order given.
pub fn evaluators<'a>(paths: &'a Paths, heads: &[Head]) -> Vec<Box<dyn HeadEvaluator + 'a>> {
    heads
        .iter()
        .map(|head| -> Box<dyn HeadEvaluator + 'a> {
            match head {
                Head::Risk => Box::new(Risk(paths)),
                Head::Policy => Box::new(Policy(paths)),
                Head::Judgement => Box::new(Judgement(paths)),
            }
        })
        .collect()
}
