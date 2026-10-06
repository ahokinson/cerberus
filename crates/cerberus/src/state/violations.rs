use super::stores;
use crate::config::Paths;
use crate::domain::Head;
use crate::domain::is_deny;

/// A session's deny count per head. Field names match [`Head::name`], which
/// is also what `cerberus violations` prints as keys.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Counts {
    pub risk: u32,
    pub policy: u32,
    pub judgement: u32,
}

/// The session's counts, zero for a head that never denied (or a session
/// that was never seen).
pub fn read_counts(paths: &Paths, session_id: &str) -> stores::Result<Counts> {
    let mut counts = Counts::default();
    for (head, n) in stores::violations(paths, session_id)? {
        let n = n as u32;
        match head.as_str() {
            h if h == Head::Risk.name() => counts.risk = n,
            h if h == Head::Policy.name() => counts.policy = n,
            h if h == Head::Judgement.name() => counts.judgement = n,
            _ => {}
        }
    }
    Ok(counts)
}

/// Increments `head`'s count for the session. Fails silently: a broken write
/// must never affect a guard's deny decision.
pub fn record(paths: &Paths, session_id: &str, head: Head) {
    let _ = stores::bump_violation(
        paths,
        session_id,
        head.name(),
        crate::state::audits::now_secs(),
    );
}

/// Records a violation against the session if `output` (the Claude-shaped
/// hook JSON a head's `evaluate` produced) is an actual deny rather than
/// e.g. cupcake's `ask`, and a session id was present on the hook event.
/// `guard::run` calls this directly rather than printing `output` itself,
/// since a harness whose response needs reshaping before it's printed
/// (see `harness::cursor::from_decision`) still needs the same counting
/// behavior against the pre-translation, Claude-shaped decision.
///
/// Unlike the audit record this is always on: a count holds no command text.
pub fn record_if_denied(paths: &Paths, session_id: Option<&str>, head: Head, output: &str) {
    if is_deny(output)
        && let Some(session_id) = session_id
    {
        record(paths, session_id, head);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch_paths(name: &str) -> Paths {
        let root = std::env::temp_dir().join(format!(
            "cerberus-violations-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        Paths {
            state_home: root.join("state"),
            data_home: root.join("data"),
            config_home: root.join("config"),
            cache_home: root.join("cache"),
            home: root.join("home"),
        }
    }

    #[test]
    fn read_counts_defaults_to_zero_for_an_unseen_session() {
        let paths = scratch_paths("missing");
        assert_eq!(read_counts(&paths, "s1").unwrap(), Counts::default());
    }

    #[test]
    fn record_increments_only_the_given_head_for_only_that_session() {
        let paths = scratch_paths("record");
        record(&paths, "s1", Head::Policy);
        record(&paths, "s1", Head::Policy);
        record(&paths, "s1", Head::Risk);
        record(&paths, "s2", Head::Judgement);
        assert_eq!(
            read_counts(&paths, "s1").unwrap(),
            Counts {
                risk: 1,
                policy: 2,
                judgement: 0
            }
        );
        assert_eq!(
            read_counts(&paths, "s2").unwrap(),
            Counts {
                risk: 0,
                policy: 0,
                judgement: 1
            }
        );
    }

    #[test]
    fn only_a_deny_with_a_session_is_counted() {
        let paths = scratch_paths("deny-only");
        let deny = r#"{"hookSpecificOutput":{"permissionDecision":"deny"}}"#;
        let ask = r#"{"hookSpecificOutput":{"permissionDecision":"ask"}}"#;
        record_if_denied(&paths, Some("s1"), Head::Risk, ask);
        record_if_denied(&paths, None, Head::Risk, deny);
        assert_eq!(read_counts(&paths, "s1").unwrap(), Counts::default());
        record_if_denied(&paths, Some("s1"), Head::Risk, deny);
        assert_eq!(read_counts(&paths, "s1").unwrap().risk, 1);
    }
}
