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

    /// cupcake's own machine-wide global config root
    /// (`$XDG_CONFIG_HOME/cupcake`, confirmed against a real cupcake
    /// install), where `cupcake init --global` scaffolds every harness's
    /// policies and where they layer on top of the per-project stub above.
    /// cerberus only ever writes beneath [`Self::cupcake_global_custom_dir`].
    pub fn cupcake_global_root(&self) -> PathBuf {
        self.config_home.join("cupcake")
    }

    /// The one subdirectory cerberus ever writes to inside cupcake's global
    /// store. Reserved so cerberus's policies can never collide with a
    /// user's own `custom/<category>/<name>.rego` policies (a real,
    /// observed layout on a populated global store) — harness-scoped by
    /// `claude/` already, further scoped to `cerberus/` within it.
    pub fn cupcake_global_custom_dir(&self) -> PathBuf {
        self.cupcake_global_root()
            .join("policies/claude/custom/cerberus")
    }

    /// A cerberus-owned tirith policy root, analogous in spirit to
    /// [`Self::cupcake_stub`]: not a real repo, just a fixed location
    /// `tirith check` can be pointed at via `TIRITH_POLICY_ROOT` when the
    /// real repo being guarded has no `.tirith/policy.yaml` of its own.
    pub fn tirith_overlay_root(&self) -> PathBuf {
        self.data_home.join("cerberus-tirith-overlay")
    }

    pub fn tirith_overlay_policy_file(&self) -> PathBuf {
        self.tirith_overlay_root().join(".tirith/policy.yaml")
    }

    /// A decoy `HOME` for the `cupcake init --global` subprocess only.
    /// `cupcake init --global` doesn't just scaffold the policy tree — it
    /// also tries to auto-wire its own independent `PreToolUse` hook
    /// (matcher `"*"`, running `cupcake eval` directly) into
    /// `$HOME/.claude/settings.json` on its own initiative, unrelated to
    /// and uncoordinated with `settings::install_hooks`. That would corrupt
    /// the single hook slot cerberus owns and double-evaluate cupcake, so
    /// `init::ensure_cupcake_global` runs the subprocess with `HOME`
    /// pointed here instead of the user's real home: the global config
    /// destination is controlled separately via `XDG_CONFIG_HOME`
    /// (`cupcake_global_root`'s parent), so the store still lands in the
    /// right place, but cupcake's settings.json probe finds nothing at this
    /// decoy path and leaves the real `~/.claude/settings.json` alone.
    pub fn cupcake_global_init_decoy_home(&self) -> PathBuf {
        self.data_home.join("cupcake-global-init-home")
    }

    /// Where Rhai rule scripts (`*.rhai`) are loaded from at runtime,
    /// deliberately outside the compiled binary, so adding or editing a
    /// rule doesn't need a rebuild. See `rules::engine`.
    pub fn rule_scripts_dir(&self) -> PathBuf {
        self.config_home.join("cerberus/rules")
    }

    /// Claude Code's global settings file: where `cerberus init` wires up
    /// the `PreToolUse`/`SessionStart` hook entries. See also
    /// [`Self::codex_hooks_json`], wired the same way.
    pub fn claude_settings_json(&self) -> PathBuf {
        self.home.join(".claude/settings.json")
    }

    /// OpenAI Codex CLI's global hooks file. Confirmed to use the identical
    /// `hooks.PreToolUse[]`/`hooks.SessionStart[]` shape as Claude Code's
    /// `settings.json` (down to the nested `{"matcher", "hooks": [{"type",
    /// "command"}]}` entries), so `settings::install_hooks` wires either
    /// file with the same code, unmodified.
    pub fn codex_hooks_json(&self) -> PathBuf {
        self.home.join(".codex/hooks.json")
    }

    /// Codex CLI's own config file. Codex's hooks are `Stage::UnderDevelopment`
    /// — writing `codex_hooks_json()` alone does nothing until
    /// `[features] codex_hooks = true` is also set here; without it, hooks
    /// are documented to be silent no-ops. See
    /// `init::ensure_codex_hooks_enabled`.
    pub fn codex_config_toml(&self) -> PathBuf {
        self.home.join(".codex/config.toml")
    }

    /// Cursor's global hooks file. Unlike Claude/Codex's shared shape,
    /// Cursor's `hooks.json` splits `beforeShellExecution`/
    /// `beforeMCPExecution` into flat per-event arrays with no nested
    /// `hooks` array of their own — see `harness::cursor::install_hooks`.
    pub fn cursor_hooks_json(&self) -> PathBuf {
        self.home.join(".cursor/hooks.json")
    }

    /// Which heads `cerberus guard` runs. See `config::enabled_heads`.
    pub fn config_file(&self) -> PathBuf {
        self.config_home.join("cerberus/config.toml")
    }
}
