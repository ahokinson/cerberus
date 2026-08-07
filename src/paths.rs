use std::env;
use std::path::PathBuf;

/// Resolved once at startup and threaded explicitly into every head, rather
/// than read from the environment deep inside each function. Keeps the
/// logic testable without env-var races between parallel tests.
pub struct Paths {
    pub state_home: PathBuf,
    pub data_home: PathBuf,
    pub config_home: PathBuf,
    pub home: PathBuf,
}

impl Paths {
    pub fn from_env() -> Self {
        let home = PathBuf::from(env::var("HOME").unwrap_or_default());
        let state_home = env::var("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".local/state"));
        let data_home = env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".local/share"));
        let config_home = env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".config"));
        Self {
            state_home,
            data_home,
            config_home,
            home,
        }
    }

    pub fn violations_file(&self, session_id: &str) -> PathBuf {
        self.state_home
            .join("guard")
            .join(format!("violations-{session_id}.state"))
    }

    pub fn degraded_sentinel(&self) -> PathBuf {
        self.state_home.join("guard").join("degraded")
    }

    pub fn cupcake_stub(&self) -> PathBuf {
        self.data_home.join("cupcake-stub")
    }

    /// Where Rhai rule scripts (`*.rhai`) are loaded from at runtime,
    /// deliberately outside the compiled binary, so adding or editing a
    /// rule doesn't need a rebuild. See `rules::engine`.
    pub fn rule_scripts_dir(&self) -> PathBuf {
        self.config_home.join("cerberus/rules")
    }

    /// Claude Code's global settings file: where `cerberus init` wires up
    /// the `PreToolUse`/`SessionStart` hook entries.
    pub fn claude_settings_json(&self) -> PathBuf {
        self.home.join(".claude/settings.json")
    }

    /// Which heads `cerberus guard` runs. See `config::enabled_heads`.
    pub fn config_file(&self) -> PathBuf {
        self.config_home.join("cerberus/config.toml")
    }
}
