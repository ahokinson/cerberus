use std::env;
use std::path::PathBuf;

/// Resolved once at startup and threaded explicitly into every head, rather
/// than read from the environment deep inside each function. Keeps the
/// logic testable without env-var races between parallel tests.
pub struct Paths {
    pub state_home: PathBuf,
    pub data_home: PathBuf,
    pub config_home: PathBuf,
    pub cache_home: PathBuf,
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
        let cache_home = env::var("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".cache"));
        Self {
            state_home,
            data_home,
            config_home,
            cache_home,
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

    /// The structured audit log (opt-in, see `config::audit_enabled` and
    /// `src/audit.rs`): one JSONL record per non-allow decision, in the same
    /// `guard/` directory as the violation counters and degraded sentinel.
    pub fn audit_log_file(&self) -> PathBuf {
        self.state_home.join("guard").join("audit.jsonl")
    }

    /// The single rotated generation of [`Self::audit_log_file`]. Simple
    /// size-based rotation, one generation: when the live file crosses the
    /// size threshold it's renamed here (clobbering any prior one) before a
    /// fresh file is started.
    pub fn audit_log_rotated_file(&self) -> PathBuf {
        self.state_home.join("guard").join("audit.jsonl.1")
    }

    /// The cupcake *project* root cerberus owns. cupcake needs a project
    /// alongside its global store, so `cerberus init` scaffolds one here
    /// with `cupcake init --harness claude`; cerberus's own policies all
    /// live in the global store ([`Self::cupcake_policies_dir`]), not here.
    ///
    /// Formerly `$XDG_DATA_HOME/cupcake-stub`, and formerly reached by
    /// running `cupcake eval` with its `current_dir` set here, because
    /// cupcake used to discover its project from the cwd. It takes an
    /// explicit `--policy-dir` now (see [`Self::cupcake_policy_dir`]), so
    /// this is just a directory cerberus owns rather than a cwd it borrows.
    pub fn cupcake_project_root(&self) -> PathBuf {
        self.data_home.join("cerberus/cupcake")
    }

    /// What `cupcake eval --policy-dir` actually wants: the project root's
    /// `.cupcake` directory, **not** the `policies` directory inside it.
    /// Confirmed against cupcake 0.5.2, which derives the project root as
    /// this path's *parent* and then re-joins `.cupcake/policies/<harness>`
    /// itself — passing the `policies` directory instead makes it look for
    /// `.cupcake/.cupcake/policies/claude` and fail to initialize. This
    /// matches what cupcake's own generated Claude hook passes
    /// (`--policy-dir $CLAUDE_PROJECT_DIR/.cupcake`).
    pub fn cupcake_policy_dir(&self) -> PathBuf {
        self.cupcake_project_root().join(".cupcake")
    }

    /// cerberus's **own** cupcake global store, passed to `cupcake eval`
    /// via `--global-config`. Formerly the user's own machine-wide
    /// `$XDG_CONFIG_HOME/cupcake`, into which cerberus wrote a reserved
    /// subdirectory; cerberus now owns this store outright and never
    /// touches the user's cupcake install at all.
    ///
    /// Note `--global-config` is honored by `cupcake eval` but silently
    /// ignored by `cupcake verify`/`inspect` (confirmed against 0.5.2), so
    /// those two are not usable to check what cerberus's store contains.
    pub fn cupcake_global_root(&self) -> PathBuf {
        self.config_home.join("cerberus/cupcake")
    }

    /// Where cerberus's shipped `.rego` policies are installed inside its
    /// own global store.
    ///
    /// The `claude/` segment is cupcake's addressing, not a Claude Code
    /// assumption: the global phase scans `policies/<harness>/` and only
    /// that, so a policy outside it is never scanned and the head would
    /// enforce nothing. It matches the `--harness claude` cerberus passes
    /// deliberately, every harness's payload having been normalized into
    /// Claude's wire format at the edge.
    ///
    /// There is no `custom/` segment. That existed only to reserve a
    /// namespace inside the *user's* store, beside their own onboarded
    /// `custom/<category>/*.rego` — a collision that cannot happen in a
    /// store cerberus owns. Verified live: policies here are scanned,
    /// parsed, routed, and enforcing.
    pub fn cupcake_policies_dir(&self) -> PathBuf {
        self.cupcake_global_root().join("policies/claude/cerberus")
    }

    /// The `XDG_CONFIG_HOME` value handed to the `cupcake init --global`
    /// subprocess. cupcake derives its global root as
    /// `$XDG_CONFIG_HOME/cupcake`, so pointing it one level into cerberus's
    /// own config directory is what makes the store land at
    /// [`Self::cupcake_global_root`] instead of the user's
    /// `~/.config/cupcake`. This is the whole mechanism by which cerberus
    /// gets a cupcake-scaffolded (and therefore version-correct) store
    /// without hand-rolling cupcake's `system/evaluate.rego`.
    pub fn cupcake_init_xdg_config_home(&self) -> PathBuf {
        self.config_home.join("cerberus")
    }

    /// A cerberus-owned tirith policy root: not a real repo, just a fixed
    /// location `tirith check` can be pointed at via `TIRITH_POLICY_ROOT`
    /// when the real repo being guarded has no `.tirith/policy.yaml` of its
    /// own. Formerly `$XDG_DATA_HOME/cerberus-tirith-overlay`.
    pub fn tirith_overlay_root(&self) -> PathBuf {
        self.data_home.join("cerberus/tirith")
    }

    /// The single composed policy file tirith reads. Generated, never
    /// hand-edited: `integrations::tirith::compose` merges cerberus's
    /// embedded base with [`Self::tirith_fragments_dir`] and every source's
    /// fragments into this one file, because tirith has no policy layering
    /// of its own (no `extends`/`import` in its schema — `TIRITH_POLICY_ROOT`
    /// points at exactly one file).
    pub fn tirith_overlay_policy_file(&self) -> PathBuf {
        self.tirith_overlay_root().join(".tirith/policy.yaml")
    }

    /// Where a user drops their **own** tirith policy fragments (`*.yaml`),
    /// the risk head's counterpart to dropping a personal `.rhai` file into
    /// [`Self::rule_scripts_dir`]. `cerberus init` creates this directory
    /// and never writes into it or removes anything from it.
    pub fn tirith_fragments_dir(&self) -> PathBuf {
        self.config_home.join("cerberus/tirith")
    }

    /// Where a named source's tirith fragments are installed — a sibling of
    /// the personal fragments above, never colliding with them, mirroring
    /// how [`Self::source_rules_dir`] sits beside the top-level rules.
    pub fn source_tirith_dir(&self, name: &str) -> PathBuf {
        self.tirith_fragments_dir().join("sources").join(name)
    }

    /// The directories earlier versions of cerberus created at the top level
    /// of `$XDG_DATA_HOME`, before everything moved under a single
    /// `cerberus/` namespace. `cerberus init` removes these once the new
    /// locations are in place; they are cerberus's own artifacts, so nothing
    /// of the user's is at risk, but the removal is always reported by name
    /// rather than done silently.
    pub fn legacy_dirs(&self) -> Vec<PathBuf> {
        vec![
            self.data_home.join("cupcake-stub"),
            self.data_home.join("cerberus-tirith-overlay"),
            self.data_home.join("cupcake-global-init-home"),
        ]
    }

    /// A decoy `HOME` for the `cupcake init` subprocesses only.
    /// `cupcake init --global` doesn't just scaffold the policy tree — it
    /// also tries to auto-wire its own independent `PreToolUse` hook
    /// (matcher `"*"`, running `cupcake eval` directly) into
    /// `$HOME/.claude/settings.json` on its own initiative, unrelated to
    /// and uncoordinated with `settings::install_hooks`. That would corrupt
    /// the single hook slot cerberus owns and double-evaluate cupcake, so
    /// `init::ensure_cupcake_global` runs the subprocess with `HOME`
    /// pointed here instead of the user's real home: the global config
    /// destination is controlled separately via `XDG_CONFIG_HOME`
    /// ([`Self::cupcake_init_xdg_config_home`]), so the store still lands
    /// in the right place, but cupcake's settings.json probe finds nothing
    /// at this decoy path and leaves the real `~/.claude/settings.json`
    /// alone. Re-confirmed against cupcake 0.5.2: running `init --global`
    /// with a decoy `HOME` leaves a `.claude/settings.json` behind *in the
    /// decoy*, which is exactly the file that would otherwise have been the
    /// user's.
    pub fn cupcake_init_decoy_home(&self) -> PathBuf {
        self.data_home.join("cerberus/cupcake-init-home")
    }

    /// Where Rhai rule scripts (`*.rhai`) are loaded from at runtime,
    /// deliberately outside the compiled binary, so adding or editing a
    /// rule doesn't need a rebuild. See `rules::engine`.
    pub fn rule_scripts_dir(&self) -> PathBuf {
        self.config_home.join("cerberus/rules")
    }

    /// Where a named policy `source`'s cloned git repo is cached
    /// (`XDG_CACHE_HOME/cerberus/sources/<name>`). This is regenerable
    /// derived data, not user config and not runtime state, so it lives
    /// under the cache root: a corrupted or stale clone can be deleted and
    /// re-fetched without touching anything else `source sync` manages. See
    /// `src/sources`.
    pub fn source_cache_dir(&self, name: &str) -> PathBuf {
        self.cache_home.join("cerberus/sources").join(name)
    }

    /// Where a named source's `.rhai` rule scripts are installed
    /// (a sibling of the flat top-level [`Self::rule_scripts_dir`], never
    /// colliding with personal or shipped rules there). `rules::evaluate`
    /// walks every configured source's directory here as an additive OR-of-
    /// denials layer on top of the top-level rules.
    pub fn source_rules_dir(&self, name: &str) -> PathBuf {
        self.rule_scripts_dir().join("sources").join(name)
    }

    /// Where a named source's `.rego` policies are installed: nested under
    /// cerberus's own policy subtree ([`Self::cupcake_policies_dir`]), so
    /// `guard-self-protection.rego`'s match on `cerberus/cupcake/` covers
    /// anything nested further under it — no policy change is needed to
    /// protect source content from tampering.
    pub fn cupcake_source_policies_dir(&self, name: &str) -> PathBuf {
        self.cupcake_policies_dir().join("sources").join(name)
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

    /// Codex CLI's own config file. Codex's hooks are `Stage::UnderDevelopment`,
    /// so writing `codex_hooks_json()` alone does nothing until
    /// `[features] codex_hooks = true` is also set here; without it, hooks
    /// are documented to be silent no-ops. See
    /// `init::ensure_codex_hooks_enabled`.
    pub fn codex_config_toml(&self) -> PathBuf {
        self.home.join(".codex/config.toml")
    }

    /// Cursor's global hooks file. Unlike Claude/Codex's shared shape,
    /// Cursor's `hooks.json` splits `beforeShellExecution`/
    /// `beforeMCPExecution` into flat per-event arrays with no nested
    /// `hooks` array of their own. See `harness::cursor::install_hooks`.
    pub fn cursor_hooks_json(&self) -> PathBuf {
        self.home.join(".cursor/hooks.json")
    }

    /// Hermes Agent's plugin directory reserved for cerberus's own plugin
    /// (`embedded::HERMES_PLUGIN`), a Python `pre_tool_call` hook that
    /// shells out to `cerberus guard` rather than a config file cerberus
    /// merges into. See `init::write_hermes_plugin`.
    pub fn hermes_plugin_dir(&self) -> PathBuf {
        self.home.join(".hermes/plugins/cerberus")
    }

    /// opencode's global plugin directory. cerberus writes a single file
    /// here (`embedded::OPENCODE_PLUGIN`) rather than a config file to
    /// merge into: opencode plugins are auto-loaded in-process
    /// TypeScript/JavaScript, not a subprocess/stdin contract. See
    /// `init::write_opencode_plugin`.
    ///
    /// `plugin`, singular, and under `config_home` rather than a hardcoded
    /// dot-config path: that is the directory a real opencode install reads
    /// (verified against 1.18.9). A plural name is silently never loaded,
    /// which would leave the guard looking installed while nothing it wrote
    /// there ever ran.
    pub fn opencode_plugin_dir(&self) -> PathBuf {
        self.config_home.join("opencode/plugin")
    }

    /// Which heads `cerberus guard` runs. See `config::enabled_heads`.
    pub fn config_file(&self) -> PathBuf {
        self.config_home.join("cerberus/config.toml")
    }
}
