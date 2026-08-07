/// The three heads `guard` runs, in the fixed order they always run in
/// (config only controls inclusion, not order). `gate` isn't a head: it
/// always runs first, unconditionally, ahead of anything here.
///
/// Each head exists to catch a different *kind* of bad outcome, which is
/// why they stay separate instead of folding into one scanner:
///
/// - `Risk` (**general risk avoidance**): dangerous no matter who's running
///   it or why. Command-pattern scanning via tirith.
/// - `Policy` (**governance policy**): breaks a rule the org has decided
///   on. Policy evaluation via cupcake.
/// - `Judgement` (**contextual bad decisions**): only bad because of state
///   nothing in the command line itself reveals. Rhai-scripted situational
///   checks.
///
/// The single canonical `Head` type. Everywhere else in the codebase that
/// needs to know what the three heads are and why (`config`, `violations`,
/// `guard`, `health`, `init`) uses this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Head {
    Risk,
    Policy,
    Judgement,
}

impl Head {
    /// Fixed run order: `gate` first (not a head, handled separately),
    /// then these three.
    pub const ORDER: [Head; 3] = [Head::Risk, Head::Policy, Head::Judgement];

    /// Mechanism-facing short name: `config.toml` keys, CLI text, log
    /// lines. For the concept, see [`Head::purpose`].
    pub fn name(self) -> &'static str {
        match self {
            Head::Risk => "risk",
            Head::Policy => "policy",
            Head::Judgement => "judgement",
        }
    }

    /// The kind of bad outcome this head exists to catch. Used in the
    /// README, `--help`, and health/init/deny messaging, anywhere the *why*
    /// matters as much as the *how*.
    pub fn purpose(self) -> &'static str {
        match self {
            Head::Risk => "general risk avoidance",
            Head::Policy => "governance policy",
            Head::Judgement => "contextual bad decisions",
        }
    }

    /// One-line description of *how* this head evaluates a command.
    pub fn mechanism(self) -> &'static str {
        match self {
            Head::Risk => "command-pattern scanning via tirith",
            Head::Policy => "policy evaluation via cupcake",
            Head::Judgement => "Rhai-scripted situational checks",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_is_risk_policy_judgement() {
        assert_eq!(Head::ORDER, [Head::Risk, Head::Policy, Head::Judgement]);
    }

    #[test]
    fn every_head_has_distinct_names_purposes_and_mechanisms() {
        let heads = Head::ORDER;
        let names: Vec<_> = heads.iter().map(|h| h.name()).collect();
        let purposes: Vec<_> = heads.iter().map(|h| h.purpose()).collect();
        let mechanisms: Vec<_> = heads.iter().map(|h| h.mechanism()).collect();
        for v in [&names, &purposes, &mechanisms] {
            let mut sorted = v.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(sorted.len(), 3, "expected 3 distinct values, got {v:?}");
        }
    }
}
