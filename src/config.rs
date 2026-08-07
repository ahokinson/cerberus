use crate::head::Head;
use crate::paths::Paths;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Default)]
struct HeadSettings {
    #[serde(default)]
    disabled: bool,
}

#[derive(Deserialize, Default)]
struct HeadsTable {
    #[serde(default)]
    risk: HeadSettings,
    #[serde(default)]
    policy: HeadSettings,
    #[serde(default)]
    judgement: HeadSettings,
}

#[derive(Deserialize, Default)]
struct RawConfig {
    #[serde(default)]
    heads: HeadsTable,
}

fn disabled(table: &HeadsTable, head: Head) -> bool {
    match head {
        Head::Risk => table.risk.disabled,
        Head::Policy => table.policy.disabled,
        Head::Judgement => table.judgement.disabled,
    }
}

/// Which heads `guard` runs, in fixed order (see [`Head::ORDER`]). Reads
/// `paths.config_file()`; a missing file, a missing `[heads]` table, or a
/// head simply absent from it all mean enabled. Malformed TOML also falls
/// back to all-enabled: a config problem should never silently turn off
/// enforcement.
pub fn enabled_heads(paths: &Paths) -> Vec<Head> {
    let table = fs::read_to_string(paths.config_file())
        .ok()
        .and_then(|raw| toml::from_str::<RawConfig>(&raw).ok())
        .map(|c| c.heads)
        .unwrap_or_default();

    Head::ORDER
        .into_iter()
        .filter(|&head| !disabled(&table, head))
        .collect()
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
}
