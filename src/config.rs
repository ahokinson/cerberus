use crate::head::Head;
use crate::paths::Paths;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Deserialize, Serialize, Default)]
struct HeadSettings {
    #[serde(default)]
    disabled: bool,
}

#[derive(Deserialize, Serialize, Default)]
struct HeadsTable {
    #[serde(default)]
    risk: HeadSettings,
    #[serde(default)]
    policy: HeadSettings,
    #[serde(default)]
    judgement: HeadSettings,
}

/// A named, independently syncable external rule/policy bundle (see
/// `src/sources`). `pinned` is the resolved commit SHA actually installed —
/// written by `source add`/`source sync`, never hand-edited — so a plain
/// `cerberus init` can reapply from the cache without touching the network.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct SourceConfig {
    pub name: String,
    pub git: String,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<String>,
}

/// The full shape of `config.toml`. Writing this back out (see
/// [`upsert_source`]/[`remove_source`]) round-trips through a typed
/// deserialize-mutate-reserialize cycle rather than a generic TOML-value
/// patch: simpler and type-safe, at the accepted cost that a write drops any
/// comments and any top-level key this struct doesn't model. Since this file
/// is cerberus's own (unlike, say, Codex's shared `config.toml`, which
/// `init::ensure_codex_hooks_enabled` patches surgically instead), that's a
/// deliberate trade a user's own `README`/`CONTRIBUTING.md` documentation
/// covers instead of the file itself.
#[derive(Deserialize, Serialize, Default)]
struct RawConfig {
    #[serde(default)]
    heads: HeadsTable,
    #[serde(default)]
    sources: Vec<SourceConfig>,
}

fn disabled(table: &HeadsTable, head: Head) -> bool {
    match head {
        Head::Risk => table.risk.disabled,
        Head::Policy => table.policy.disabled,
        Head::Judgement => table.judgement.disabled,
    }
}

/// Parses `path` as a `RawConfig`, defaulting on any read or parse problem.
/// The single read path for every setting in this file: each field's own
/// `Default` already encodes the right fail-direction per setting — heads
/// default to *enabled*, since a config problem must never silently turn
/// off enforcement.
fn read_config(path: &Path) -> RawConfig {
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| toml::from_str(&raw).ok())
        .unwrap_or_default()
}

fn write_config(path: &Path, config: &RawConfig) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = toml::to_string_pretty(config)
        .map_err(|e| io::Error::other(format!("couldn't serialize config: {e}")))?;
    fs::write(path, text)
}

/// A source `name` is used to build directories inside a security tool
/// (`Paths::source_rules_dir`, `Paths::cupcake_source_custom_dir`), so it's
/// restricted to a safe slug before it's ever trusted for a path join — a
/// hand-edited `config.toml` is untrusted input here the same way any other
/// external content cerberus reads is. Applied both when writing a new
/// source ([`upsert_source`]) and when reading ([`sources`]), so a bad name
/// already present in the file is simply dropped rather than acted on.
pub fn valid_source_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Which heads `guard` runs, in fixed order (see [`Head::ORDER`]). A missing
/// file, a missing `[heads]` table, or a head simply absent from it all mean
/// enabled.
pub fn enabled_heads(paths: &Paths) -> Vec<Head> {
    let table = read_config(&paths.config_file()).heads;
    Head::ORDER
        .into_iter()
        .filter(|&head| !disabled(&table, head))
        .collect()
}

/// Every configured policy source with a valid name, in file order. See
/// [`valid_source_name`].
pub fn sources(paths: &Paths) -> Vec<SourceConfig> {
    read_config(&paths.config_file())
        .sources
        .into_iter()
        .filter(|s| valid_source_name(&s.name))
        .collect()
}

/// Adds `source` to `config.toml`, replacing any existing entry with the
/// same `name`.
pub fn upsert_source(config_path: &Path, source: SourceConfig) -> io::Result<()> {
    let mut config = read_config(config_path);
    match config.sources.iter_mut().find(|s| s.name == source.name) {
        Some(existing) => *existing = source,
        None => config.sources.push(source),
    }
    write_config(config_path, &config)
}

/// Removes the source named `name` from `config.toml`. Returns whether a
/// matching entry was actually found and removed.
pub fn remove_source(config_path: &Path, name: &str) -> io::Result<bool> {
    let mut config = read_config(config_path);
    let before = config.sources.len();
    config.sources.retain(|s| s.name != name);
    let removed = config.sources.len() != before;
    if removed {
        write_config(config_path, &config)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;
    use std::path::PathBuf;

    fn paths_with_config(name: &str, contents: Option<&str>) -> Paths {
        let dir = temp_dir().join(format!(
            "cerberus-config-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let paths = Paths {
            state_home: PathBuf::from("/dev/null/unused"),
            data_home: PathBuf::from("/dev/null/unused"),
            config_home: dir,
            cache_home: PathBuf::from("/dev/null/unused"),
            home: PathBuf::from("/dev/null/unused"),
        };
        if let Some(contents) = contents {
            fs::create_dir_all(paths.config_file().parent().unwrap()).unwrap();
            fs::write(paths.config_file(), contents).unwrap();
        }
        paths
    }

    #[test]
    fn all_heads_enabled_when_file_missing() {
        let paths = paths_with_config("missing", None);
        assert_eq!(
            enabled_heads(&paths),
            vec![Head::Risk, Head::Policy, Head::Judgement]
        );
    }

    #[test]
    fn all_heads_enabled_when_heads_table_missing() {
        let paths = paths_with_config("no-table", Some("# nothing here\n"));
        assert_eq!(
            enabled_heads(&paths),
            vec![Head::Risk, Head::Policy, Head::Judgement]
        );
    }

    #[test]
    fn head_absent_from_table_is_enabled() {
        let paths = paths_with_config("partial", Some("[heads]\nrisk = { disabled = true }\n"));
        assert_eq!(enabled_heads(&paths), vec![Head::Policy, Head::Judgement]);
    }

    #[test]
    fn explicit_disable_removes_a_head() {
        let paths = paths_with_config(
            "disable-one",
            Some(
                "[heads]\nrisk = { disabled = false }\npolicy = { disabled = true }\njudgement = { disabled = false }\n",
            ),
        );
        assert_eq!(enabled_heads(&paths), vec![Head::Risk, Head::Judgement]);
    }

    #[test]
    fn malformed_toml_falls_back_to_all_enabled() {
        let paths = paths_with_config("malformed", Some("this is not valid toml {{{"));
        assert_eq!(
            enabled_heads(&paths),
            vec![Head::Risk, Head::Policy, Head::Judgement]
        );
    }

    #[test]
    fn output_order_is_fixed_regardless_of_file_key_order() {
        let paths = paths_with_config(
            "order",
            Some("[heads]\njudgement = { disabled = false }\nrisk = { disabled = false }\n"),
        );
        assert_eq!(
            enabled_heads(&paths),
            vec![Head::Risk, Head::Policy, Head::Judgement]
        );
    }

    #[test]
    fn valid_source_name_accepts_lowercase_slug_rejects_path_like_names() {
        assert!(valid_source_name("team"));
        assert!(valid_source_name("cerberus-examples_2"));
        assert!(!valid_source_name(""));
        assert!(!valid_source_name("../escape"));
        assert!(!valid_source_name("has/slash"));
        assert!(!valid_source_name("Has.Dot"));
        assert!(!valid_source_name("Uppercase"));
    }

    #[test]
    fn sources_empty_when_file_missing() {
        let paths = paths_with_config("sources-missing", None);
        assert_eq!(sources(&paths), vec![]);
    }

    #[test]
    fn sources_reads_configured_entries() {
        let paths = paths_with_config(
            "sources-read",
            Some(
                "[[sources]]\nname = \"team\"\ngit = \"git@example.com:org/repo.git\"\nref = \"main\"\npinned = \"abc123\"\n",
            ),
        );
        assert_eq!(
            sources(&paths),
            vec![SourceConfig {
                name: "team".into(),
                git: "git@example.com:org/repo.git".into(),
                git_ref: Some("main".into()),
                pinned: Some("abc123".into()),
            }]
        );
    }

    #[test]
    fn sources_drops_entries_with_an_invalid_name() {
        let paths = paths_with_config(
            "sources-invalid-name",
            Some("[[sources]]\nname = \"../escape\"\ngit = \"git@example.com:org/repo.git\"\n"),
        );
        assert_eq!(sources(&paths), vec![]);
    }

    #[test]
    fn upsert_source_adds_then_updates_by_name() {
        let paths = paths_with_config("upsert", None);
        let path = paths.config_file();
        upsert_source(
            &path,
            SourceConfig {
                name: "team".into(),
                git: "git@example.com:org/repo.git".into(),
                git_ref: Some("main".into()),
                pinned: None,
            },
        )
        .unwrap();
        assert_eq!(sources(&paths).len(), 1);

        upsert_source(
            &path,
            SourceConfig {
                name: "team".into(),
                git: "git@example.com:org/repo.git".into(),
                git_ref: Some("main".into()),
                pinned: Some("resolved-sha".into()),
            },
        )
        .unwrap();
        let all = sources(&paths);
        assert_eq!(all.len(), 1, "same name replaces rather than duplicates");
        assert_eq!(all[0].pinned.as_deref(), Some("resolved-sha"));
    }

    #[test]
    fn upsert_source_preserves_other_settings() {
        let paths = paths_with_config(
            "upsert-preserve",
            Some("[heads]\npolicy = { disabled = true }\n"),
        );
        upsert_source(
            &paths.config_file(),
            SourceConfig {
                name: "examples".into(),
                git: "https://example.com/examples.git".into(),
                git_ref: None,
                pinned: None,
            },
        )
        .unwrap();
        assert_eq!(enabled_heads(&paths), vec![Head::Risk, Head::Judgement]);
        assert_eq!(sources(&paths).len(), 1);
    }

    #[test]
    fn remove_source_deletes_a_matching_entry_and_reports_whether_one_existed() {
        let paths = paths_with_config("remove", None);
        let path = paths.config_file();
        upsert_source(
            &path,
            SourceConfig {
                name: "team".into(),
                git: "git@example.com:org/repo.git".into(),
                git_ref: None,
                pinned: None,
            },
        )
        .unwrap();

        assert!(remove_source(&path, "team").unwrap());
        assert_eq!(sources(&paths), vec![]);
        assert!(!remove_source(&path, "team").unwrap(), "already removed");
    }
}
