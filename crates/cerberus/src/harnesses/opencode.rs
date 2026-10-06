use super::plugin_check;
use crate::config::Paths;
use crate::domain::Check;
use crate::embedded;
use crate::ports::HarnessInstaller;
use crate::process::command_exists;
use std::fs;
use std::io;
use std::path::Path;

/// Writes cerberus's shipped opencode plugin (`embedded::OPENCODE_PLUGIN`)
/// as a single file into `dir`, creating it if needed. Always overwritten,
/// same canonical-content contract as the rule scripts/policies. The
/// filename is distinctive because, unlike Hermes's reserved per-plugin
/// subdirectory, opencode's plugin directory is shared with every other
/// plugin a user has installed.
fn write_opencode_plugin(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::write(dir.join("cerberus-guard.ts"), embedded::OPENCODE_PLUGIN)
}

/// opencode: one plugin file in its shared global plugin directory.
pub struct Opencode;

impl HarnessInstaller for Opencode {
    fn detected(&self, _paths: &Paths) -> bool {
        command_exists("opencode")
    }

    fn skipped(&self) -> &'static str {
        "opencode: not on PATH, skipping plugin install"
    }

    fn install(&self, paths: &Paths) -> Vec<String> {
        let plugin_dir = paths.opencode_plugin_dir();
        match write_opencode_plugin(&plugin_dir) {
            Ok(()) => {
                println!(
                    "opencode plugin: wrote cerberus-guard.ts to {}. Best effort against opencode's \
                    documented plugin API (tool.execute.before, no per-tool matcher of its own), not \
                    verified against the real binary",
                    plugin_dir.display()
                );
                Vec::new()
            }
            Err(e) => vec![format!(
                "couldn't write opencode plugin to {}: {e}",
                plugin_dir.display()
            )],
        }
    }

    fn check(&self, paths: &Paths) -> Check {
        plugin_check(
            "plugin.opencode",
            "opencode plugin",
            self.expected(paths),
            &paths.opencode_plugin_dir().join("cerberus-guard.ts"),
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
    fn writes_the_shipped_opencode_plugin() {
        let dir = tempdir("opencode-writes");
        write_opencode_plugin(&dir).unwrap();
        assert_eq!(
            fs::read_to_string(dir.join("cerberus-guard.ts")).unwrap(),
            embedded::OPENCODE_PLUGIN
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_opencode_plugin_is_idempotent() {
        let dir = tempdir("opencode-idempotent");
        write_opencode_plugin(&dir).unwrap();
        let first = fs::read_to_string(dir.join("cerberus-guard.ts")).unwrap();
        write_opencode_plugin(&dir).unwrap();
        let second = fs::read_to_string(dir.join("cerberus-guard.ts")).unwrap();
        assert_eq!(first, second);
        fs::remove_dir_all(&dir).ok();
    }
}
