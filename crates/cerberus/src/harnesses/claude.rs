use super::{hooks_check, settings};
use crate::config::Paths;
use crate::domain::Check;
use crate::ports::HarnessInstaller;
use crate::process::command_exists;

/// Claude Code: hooks merged into `~/.claude/settings.json`.
pub struct Claude;

impl HarnessInstaller for Claude {
    fn detected(&self, _paths: &Paths) -> bool {
        command_exists("claude")
    }

    fn skipped(&self) -> &'static str {
        "claude: not on PATH, skipping settings.json wiring"
    }

    /// The hooks matter whenever Claude Code reads this settings.json, even
    /// from a shell where the binary isn't on PATH.
    fn expected(&self, _paths: &Paths) -> bool {
        true
    }

    fn install(&self, paths: &Paths) -> Vec<String> {
        match settings::install_hooks(&paths.claude_settings_json()) {
            Ok(report) => {
                if report.pretooluse_changed {
                    println!("settings.json: `cerberus guard` now runs first on PreToolUse");
                } else {
                    println!("settings.json: PreToolUse entry already up to date");
                }
                if report.sessionstart_changed {
                    println!("settings.json: `cerberus health` now runs first on SessionStart");
                } else {
                    println!("settings.json: SessionStart entry already up to date");
                }
                Vec::new()
            }
            Err(e) => vec![format!(
                "couldn't update {}: {e}",
                paths.claude_settings_json().display()
            )],
        }
    }

    fn check(&self, paths: &Paths) -> Check {
        hooks_check(
            "hooks.claude",
            "Claude Code settings.json",
            &paths.claude_settings_json(),
            self.expected(paths),
        )
    }
}
