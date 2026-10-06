use super::{hooks_check, settings};
use crate::config::Paths;
use crate::domain::Check;
use crate::ports::HarnessInstaller;
use crate::process::command_exists;
use std::fs;
use std::path::Path;

enum CodexFeatureOutcome {
    Enabled,
    AlreadyEnabled,
    ExplicitlyDisabled,
    Failed(String),
}

/// Ensures `[features] codex_hooks = true` in `config_path` (Codex's own
/// `config.toml`). Codex's hook engine is `Stage::UnderDevelopment`, so
/// writing `hooks.json` alone does nothing until this flag is also set;
/// without it, hooks are documented to be silent no-ops, the same
/// "quietly stopped working" failure mode cerberus's own `health` exists
/// to catch elsewhere. Merges into any existing `config.toml`, preserving
/// every other key and feature flag, the same non-destructive spirit as
/// `settings::merge`.
///
/// Only ever sets the flag when it's absent. If a user explicitly set
/// `codex_hooks = false` themselves, that's respected: reported as a
/// problem instead of silently overridden, since cerberus's hooks won't
/// fire until it's removed.
fn ensure_codex_hooks_enabled(config_path: &Path) -> CodexFeatureOutcome {
    let mut doc: toml::Value = fs::read_to_string(config_path)
        .ok()
        .and_then(|raw| toml::from_str(&raw).ok())
        .unwrap_or_else(|| toml::Value::Table(Default::default()));
    if !doc.is_table() {
        doc = toml::Value::Table(Default::default());
    }

    let table = doc.as_table_mut().expect("coerced to table above");
    let features = table
        .entry("features")
        .or_insert_with(|| toml::Value::Table(Default::default()));
    if !features.is_table() {
        *features = toml::Value::Table(Default::default());
    }
    let features_table = features.as_table_mut().expect("coerced to table above");

    match features_table.get("codex_hooks") {
        Some(toml::Value::Boolean(true)) => return CodexFeatureOutcome::AlreadyEnabled,
        Some(toml::Value::Boolean(false)) => return CodexFeatureOutcome::ExplicitlyDisabled,
        _ => {
            features_table.insert("codex_hooks".to_string(), toml::Value::Boolean(true));
        }
    }

    if let Some(parent) = config_path.parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        return CodexFeatureOutcome::Failed(format!("couldn't create {}: {e}", parent.display()));
    }
    let text = match toml::to_string_pretty(&doc) {
        Ok(text) => text,
        Err(e) => return CodexFeatureOutcome::Failed(format!("couldn't serialize config: {e}")),
    };
    match fs::write(config_path, text) {
        Ok(()) => CodexFeatureOutcome::Enabled,
        Err(e) => {
            CodexFeatureOutcome::Failed(format!("couldn't write {}: {e}", config_path.display()))
        }
    }
}

/// Codex CLI: hooks in `~/.codex/hooks.json`, plus the `codex_hooks`
/// feature flag in its `config.toml` that makes them fire at all.
pub struct Codex;

impl HarnessInstaller for Codex {
    fn detected(&self, _paths: &Paths) -> bool {
        command_exists("codex")
    }

    fn skipped(&self) -> &'static str {
        "codex: not on PATH, skipping hooks.json wiring"
    }

    fn install(&self, paths: &Paths) -> Vec<String> {
        let mut problems = Vec::new();
        match settings::install_hooks(&paths.codex_hooks_json()) {
            Ok(report) => {
                if report.pretooluse_changed {
                    println!("codex hooks.json: `cerberus guard` now runs first on PreToolUse");
                } else {
                    println!("codex hooks.json: PreToolUse entry already up to date");
                }
                if report.sessionstart_changed {
                    println!("codex hooks.json: `cerberus health` now runs first on SessionStart");
                } else {
                    println!("codex hooks.json: SessionStart entry already up to date");
                }
            }
            Err(e) => problems.push(format!(
                "couldn't update {}: {e}",
                paths.codex_hooks_json().display()
            )),
        }
        match ensure_codex_hooks_enabled(&paths.codex_config_toml()) {
            CodexFeatureOutcome::Enabled => println!(
                "codex config.toml: enabled `[features] codex_hooks` (hooks are a silent \
                no-op without it)"
            ),
            CodexFeatureOutcome::AlreadyEnabled => {
                println!("codex config.toml: `[features] codex_hooks` already enabled")
            }
            CodexFeatureOutcome::ExplicitlyDisabled => problems.push(format!(
                "{} has `[features] codex_hooks = false` set explicitly. cerberus's Codex \
                hooks are installed but will not fire until that line is removed (left alone \
                since you set it, not cerberus)",
                paths.codex_config_toml().display()
            )),
            CodexFeatureOutcome::Failed(e) => problems.push(format!(
                "couldn't enable codex_hooks in {}: {e}",
                paths.codex_config_toml().display()
            )),
        }
        problems
    }

    fn check(&self, paths: &Paths) -> Check {
        hooks_check(
            "hooks.codex",
            "Codex hooks.json",
            &paths.codex_hooks_json(),
            self.expected(paths),
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
    fn ensure_codex_hooks_enabled_creates_config_when_missing() {
        let dir = tempdir("codex-hooks-missing");
        let config_path = dir.join("config.toml");
        let outcome = ensure_codex_hooks_enabled(&config_path);
        assert!(matches!(outcome, CodexFeatureOutcome::Enabled));
        let written = fs::read_to_string(&config_path).unwrap();
        let parsed: toml::Value = toml::from_str(&written).unwrap();
        assert_eq!(parsed["features"]["codex_hooks"].as_bool(), Some(true));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ensure_codex_hooks_enabled_preserves_other_content_and_is_idempotent() {
        let dir = tempdir("codex-hooks-preserve");
        fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        fs::write(
            &config_path,
            "model = \"gpt-5\"\n\n[features]\nother_feature = true\n",
        )
        .unwrap();

        let outcome = ensure_codex_hooks_enabled(&config_path);
        assert!(matches!(outcome, CodexFeatureOutcome::Enabled));
        let parsed: toml::Value =
            toml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(parsed["model"].as_str(), Some("gpt-5"));
        assert_eq!(parsed["features"]["other_feature"].as_bool(), Some(true));
        assert_eq!(parsed["features"]["codex_hooks"].as_bool(), Some(true));

        let second = ensure_codex_hooks_enabled(&config_path);
        assert!(matches!(second, CodexFeatureOutcome::AlreadyEnabled));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ensure_codex_hooks_enabled_respects_an_explicit_false() {
        let dir = tempdir("codex-hooks-explicit-false");
        fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        fs::write(&config_path, "[features]\ncodex_hooks = false\n").unwrap();

        let outcome = ensure_codex_hooks_enabled(&config_path);
        assert!(matches!(outcome, CodexFeatureOutcome::ExplicitlyDisabled));
        let unchanged = fs::read_to_string(&config_path).unwrap();
        assert_eq!(unchanged, "[features]\ncodex_hooks = false\n");
        fs::remove_dir_all(&dir).ok();
    }
}
