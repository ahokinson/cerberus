use crate::config::Paths;
use crate::domain::Head;
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

/// A repo whose `.cerberus/` a human approved with `cerberus trust`. `path`
/// is the repo root the approval applies to; `id` names the snapshot of the
/// approved content (`Paths::repo_snapshot_dir`), so the heads enforce what
/// was reviewed, not whatever the directory holds now.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct RepoConfig {
    pub path: String,
    pub id: String,
}

#[derive(Deserialize, Serialize, Default)]
struct AuditSettings {
    #[serde(default)]
    enabled: bool,
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
    #[serde(default)]
    repos: Vec<RepoConfig>,
    #[serde(default)]
    audit: AuditSettings,
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
/// default to *enabled* (a config problem must never silently turn off
/// enforcement) while audit logging defaults to *disabled* (a config
/// problem must never silently start persisting command text to disk).
fn read_config(path: &Path) -> RawConfig {
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| toml::from_str(&raw).ok())
        .unwrap_or_default()
}

/// Why `config.toml` is being ignored, if it is. [`read_config`] falls back
/// to defaults silently by design; `doctor` uses this to say so out loud.
pub fn parse_error(paths: &Paths) -> Option<String> {
    let raw = fs::read_to_string(paths.config_file()).ok()?;
    toml::from_str::<RawConfig>(&raw)
        .err()
        .map(|e| e.to_string())
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

/// A repo `id` becomes a directory name under cerberus's data home, so it is
/// held to hex digits before it is ever joined into a path, applied on read
/// as well as write for the same reason as [`valid_source_name`].
pub fn valid_repo_id(id: &str) -> bool {
    !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Every repo a human has approved, in file order. See [`valid_repo_id`].
pub fn repos(paths: &Paths) -> Vec<RepoConfig> {
    read_config(&paths.config_file())
        .repos
        .into_iter()
        .filter(|r| valid_repo_id(&r.id))
        .collect()
}

/// Whether the structured audit log (`src/audit.rs`) is enabled. Off by
/// default and on any config-read problem: unlike the heads, "fail open"
/// here would mean writing more sensitive data (raw command/tool-input
/// text) to disk than intended.
pub fn audit_enabled(paths: &Paths) -> bool {
    read_config(&paths.config_file()).audit.enabled
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

/// Records `repo` as approved, replacing any entry for the same path.
pub fn upsert_repo(config_path: &Path, repo: RepoConfig) -> io::Result<()> {
    let mut config = read_config(config_path);
    match config.repos.iter_mut().find(|r| r.path == repo.path) {
        Some(existing) => *existing = repo,
        None => config.repos.push(repo),
    }
    write_config(config_path, &config)
}

/// Withdraws the approval for the repo at `path`, returning the removed
/// entry.
pub fn remove_repo(config_path: &Path, path: &str) -> io::Result<Option<RepoConfig>> {
    let mut config = read_config(config_path);
    let Some(index) = config.repos.iter().position(|r| r.path == path) else {
        return Ok(None);
    };
    let removed = config.repos.remove(index);
    write_config(config_path, &config)?;
    Ok(Some(removed))
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
    fn audit_disabled_by_default_and_on_malformed_config() {
        assert!(!audit_enabled(&paths_with_config("audit-missing", None)));
        assert!(!audit_enabled(&paths_with_config(
            "audit-malformed",
            Some("not valid toml {{{")
        )));
    }

    #[test]
    fn audit_enabled_when_explicitly_set() {
        let paths = paths_with_config("audit-on", Some("[audit]\nenabled = true\n"));
        assert!(audit_enabled(&paths));
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

    /// An approved repo's `id` becomes a directory name, so a hand-edited
    /// `config.toml` can't smuggle a path through it.
    #[test]
    fn repos_round_trip_and_drop_ids_that_are_not_hex() {
        let paths = paths_with_config("repos", None);
        let config = paths.config_file();
        let repo = RepoConfig {
            path: "/work/app".into(),
            id: "0123abcd".into(),
        };
        upsert_repo(&config, repo.clone()).unwrap();
        upsert_repo(
            &config,
            RepoConfig {
                path: "/work/evil".into(),
                id: "../escape".into(),
            },
        )
        .unwrap();
        assert_eq!(repos(&paths), vec![repo.clone()]);

        let moved = RepoConfig {
            id: "ffff".into(),
            ..repo.clone()
        };
        upsert_repo(&config, moved.clone()).unwrap();
        assert_eq!(repos(&paths), vec![moved.clone()], "same path, replaced");

        assert_eq!(remove_repo(&config, "/work/app").unwrap(), Some(moved));
        assert_eq!(remove_repo(&config, "/work/app").unwrap(), None);
    }
}
