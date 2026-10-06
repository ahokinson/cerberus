use super::plugin_check;
use crate::config::Paths;
use crate::domain::Check;
use crate::embedded;
use crate::ports::HarnessInstaller;
use crate::process::command_exists;
use std::fs;
use std::io;
use std::path::Path;

/// Writes cerberus's shipped Hermes Agent plugin (`embedded::HERMES_PLUGIN`)
/// into `dir`, creating it if needed. Same always-overwrite-the-known-files
/// contract as [`write_rule_scripts`]/[`write_cupcake_policies`]: this
/// directory is reserved to cerberus alone.
fn write_hermes_plugin(dir: &Path) -> io::Result<usize> {
    fs::create_dir_all(dir)?;
    for (name, contents) in embedded::HERMES_PLUGIN {
        fs::write(dir.join(name), contents)?;
    }
    Ok(embedded::HERMES_PLUGIN.len())
}

/// Hermes Agent: a reserved plugin directory under `~/.hermes/plugins`.
pub struct Hermes;

impl HarnessInstaller for Hermes {
    fn detected(&self, _paths: &Paths) -> bool {
        command_exists("hermes")
    }

    fn skipped(&self) -> &'static str {
        "hermes: not on PATH, skipping plugin install"
    }

    fn install(&self, paths: &Paths) -> Vec<String> {
        let plugin_dir = paths.hermes_plugin_dir();
        match write_hermes_plugin(&plugin_dir) {
            Ok(n) => {
                println!(
                    "hermes plugin: wrote {n} file(s) to {}. Verify with `hermes hooks list` or \
                    `hermes doctor`; this plugin's manifest is a best effort against Hermes's \
                    documented format, not verified against the real binary",
                    plugin_dir.display()
                );
                Vec::new()
            }
            Err(e) => vec![format!(
                "couldn't write hermes plugin to {}: {e}",
                plugin_dir.display()
            )],
        }
    }

    fn check(&self, paths: &Paths) -> Check {
        plugin_check(
            "plugin.hermes",
            "hermes plugin",
            self.expected(paths),
            &paths.hermes_plugin_dir(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cerberus-init-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn writes_all_shipped_hermes_plugin_files() {
        let dir = tempdir("hermes-writes-all");
        let count = write_hermes_plugin(&dir).unwrap();
        assert_eq!(count, embedded::HERMES_PLUGIN.len());
        for (name, contents) in embedded::HERMES_PLUGIN {
            assert_eq!(fs::read_to_string(dir.join(name)).unwrap(), *contents);
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_hermes_plugin_is_idempotent() {
        let dir = tempdir("hermes-idempotent");
        write_hermes_plugin(&dir).unwrap();
        let first: Vec<_> = embedded::HERMES_PLUGIN
            .iter()
            .map(|(name, _)| fs::read_to_string(dir.join(name)).unwrap())
            .collect();
        write_hermes_plugin(&dir).unwrap();
        let second: Vec<_> = embedded::HERMES_PLUGIN
            .iter()
            .map(|(name, _)| fs::read_to_string(dir.join(name)).unwrap())
            .collect();
        assert_eq!(first, second);
        fs::remove_dir_all(&dir).ok();
    }
}
