use crate::head::Head;
use crate::hook::is_deny;
use crate::paths::Paths;
use std::fs;
use std::io::Write;
use std::path::Path;

/// The per-session violation counter written for pharos's statusline.
/// Field names (`risk`/`policy`/`judgement`) and the on-disk state-file
/// keys (see [`read_counts`]/[`write_counts`]) both match [`Head::name`].
/// This is the single source of truth for that format.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Counts {
    pub risk: u32,
    pub policy: u32,
    pub judgement: u32,
}

pub fn read_counts(path: &Path) -> Counts {
    let mut counts = Counts::default();
    let Ok(text) = fs::read_to_string(path) else {
        return counts;
    };
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Ok(n) = value.trim().parse::<u32>() else {
            continue;
        };
        match key.trim() {
            k if k == Head::Risk.name() => counts.risk = n,
            k if k == Head::Policy.name() => counts.policy = n,
            k if k == Head::Judgement.name() => counts.judgement = n,
            _ => {}
        }
    }
    counts
}

fn write_counts(path: &Path, counts: &Counts) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::File::create(path)?;
    write!(
        file,
        "{}={}\n{}={}\n{}={}\n",
        Head::Risk.name(),
        counts.risk,
        Head::Policy.name(),
        counts.policy,
        Head::Judgement.name(),
        counts.judgement
    )
}

/// Reads the current counts, increments `head`, and rewrites the file.
/// Fails silently: a broken write must never affect a guard's deny
/// decision.
pub fn record(path: &Path, head: Head) {
    let mut counts = read_counts(path);
    match head {
        Head::Risk => counts.risk += 1,
        Head::Policy => counts.policy += 1,
        Head::Judgement => counts.judgement += 1,
    }
    let _ = write_counts(path, &counts);
}

/// Records a violation against the session if `output` (the Claude-shaped
/// hook JSON a head's `evaluate` produced) is an actual deny rather than
/// e.g. cupcake's `ask`, and a session id was present on the hook event.
/// `guard::run` calls this directly rather than printing `output` itself,
/// since a harness whose response needs reshaping before it's printed
/// (see `harness::cursor::from_decision`) still needs the same counting
/// behavior against the pre-translation, Claude-shaped decision.
pub fn record_if_denied(paths: &Paths, session_id: Option<&str>, head: Head, output: &str) {
    if is_deny(output)
        && let Some(session_id) = session_id
    {
        record(&paths.violations_file(session_id), head);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempfile(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cerberus-test-{}-{}", std::process::id(), name));
        fs::create_dir_all(&dir).unwrap();
        dir.join("violations.state")
    }

    #[test]
    fn read_counts_defaults_to_zero_when_missing() {
        let path = tempfile("missing");
        assert_eq!(read_counts(&path), Counts::default());
    }

    #[test]
    fn read_counts_parses_key_value_lines() {
        let path = tempfile("parse");
        fs::write(&path, "risk=2\npolicy=0\njudgement=1\n").unwrap();
        assert_eq!(
            read_counts(&path),
            Counts {
                risk: 2,
                policy: 0,
                judgement: 1
            }
        );
    }

    #[test]
    fn record_increments_only_the_given_head_and_preserves_others() {
        let path = tempfile("record");
        fs::write(&path, "risk=1\npolicy=1\njudgement=1\n").unwrap();
        record(&path, Head::Policy);
        assert_eq!(
            read_counts(&path),
            Counts {
                risk: 1,
                policy: 2,
                judgement: 1
            }
        );
    }

    #[test]
    fn record_creates_parent_directory_and_file_when_absent() {
        let dir = std::env::temp_dir().join(format!("cerberus-test-{}-newdir", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("guard").join("violations-x.state");
        record(&path, Head::Risk);
        assert_eq!(
            read_counts(&path),
            Counts {
                risk: 1,
                policy: 0,
                judgement: 0
            }
        );
    }
}
