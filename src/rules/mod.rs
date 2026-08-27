pub mod engine;
mod environment;
mod git;
mod shell;
pub mod tool;

use crate::config;
use crate::hook::{bash_command, pretooluse_deny};
use crate::paths::Paths;
use serde_json::Value;
use std::path::Path;

/// The `judgement` part of `guard`: loads every `*.rhai` rule script in
/// `paths.rule_scripts_dir()` and runs each one's `check(cmd, cwd, input)` in
/// turn, denying on the first one that returns a string. The scripts do the
/// situational judgement (git state, kubectl/terraform context, the hook
/// payload itself); `engine::build_engine` is what exposes those queries and
/// command tokenizing to them. See `CONTRIBUTING.md` for the native
/// function API and how to add a rule.
///
/// Each configured policy source (`config::sources`, see `src/sources`) is
/// then checked the same way against its own installed directory
/// (`Paths::source_rules_dir`), stacking as an additive OR-of-denials layer:
/// any source that denies, denies, same as the top-level rules. A machine
/// with no sources configured pays no extra cost —
/// `engine::evaluate` on a missing/empty directory already returns `None`.
///
/// This is the only head that runs on every tool `guard` is wired for, so
/// `cmd` is `""` rather than absent for a non-Bash call: a script reaches
/// the tool it's actually looking at through `input.tool_name` and
/// `tool_paths(input)`. Bailing out here on a missing command (as this used
/// to) would silently no-op every rule on every `Write`, `Edit`, and
/// `WebFetch`.
pub fn evaluate(paths: &Paths, input: &Value, cwd: &Path) -> Option<String> {
    let cmd = bash_command(input).unwrap_or("");

    let reason = engine::evaluate(&paths.rule_scripts_dir(), cmd, cwd, input).or_else(|| {
        config::sources(paths)
            .iter()
            .find_map(|s| engine::evaluate(&paths.source_rules_dir(&s.name), cmd, cwd, input))
    })?;
    Some(pretooluse_deny(&reason))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SourceConfig;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;

    fn scratch_paths(name: &str) -> Paths {
        let root = std::env::temp_dir().join(format!(
            "cerberus-rules-mod-test-{}-{name}",
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

    fn write_denying_rule(dir: &std::path::Path, reason: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("rule.rhai"),
            format!("fn check(cmd, cwd, input) {{ return \"{reason}\"; }}"),
        )
        .unwrap();
    }

    fn add_source(paths: &Paths, name: &str) {
        crate::config::upsert_source(
            &paths.config_file(),
            SourceConfig {
                name: name.to_string(),
                git: "https://example.com/repo.git".to_string(),
                git_ref: None,
                pinned: None,
            },
        )
        .unwrap();
    }

    fn input() -> Value {
        json!({"tool_input": {"command": "irrelevant"}})
    }

    #[test]
    fn allows_when_no_rules_and_no_sources_configured() {
        let paths = scratch_paths("none");
        let cwd = PathBuf::from("/tmp");
        assert_eq!(evaluate(&paths, &input(), &cwd), None);
    }

    #[test]
    fn denies_from_a_configured_source_when_top_level_is_silent() {
        let paths = scratch_paths("source-denies");
        write_denying_rule(&paths.source_rules_dir("team"), "denied by source");
        add_source(&paths, "team");

        let cwd = PathBuf::from("/tmp");
        let result = evaluate(&paths, &input(), &cwd).expect("source rule should deny");
        assert!(result.contains("denied by source"));
    }

    #[test]
    fn top_level_rules_take_precedence_over_sources() {
        let paths = scratch_paths("top-level-wins");
        write_denying_rule(&paths.rule_scripts_dir(), "denied by top level");
        write_denying_rule(&paths.source_rules_dir("team"), "denied by source");
        add_source(&paths, "team");

        let cwd = PathBuf::from("/tmp");
        let result = evaluate(&paths, &input(), &cwd).unwrap();
        assert!(result.contains("denied by top level"));
        assert!(!result.contains("denied by source"));
    }

    #[test]
    fn an_unconfigured_source_directory_is_never_consulted() {
        let paths = scratch_paths("no-config-entry");
        // A rule exists on disk under a source-shaped path, but nothing in
        // config.toml names it as a source: it must never run.
        write_denying_rule(&paths.source_rules_dir("stray"), "should never fire");

        let cwd = PathBuf::from("/tmp");
        assert_eq!(evaluate(&paths, &input(), &cwd), None);
    }
}
