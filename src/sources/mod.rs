//! Layered policy sources: named, independently syncable external bundles
//! (e.g. a team repo, or eventually a public cerberus-examples repo) that
//! stack on top of a machine's personal rules (see `rules::evaluate`'s
//! additive OR-of-denials).
//!
//! A source repo carries content for **all three heads** — `rules/*.rhai`
//! for judgement, `policies/*.rego` for policy, `tirith/*.yaml` for risk —
//! which is what makes `cerberus source add` worth using over wiring each
//! tool up by hand. The risk half is the part with no native equivalent at
//! all: tirith reads exactly one policy file and has no way to layer, so
//! cerberus composes every source's fragments into it
//! (`integrations::tirith::compose`).
//!
//! Trust model: `add` clones and pins a resolved commit SHA, and a plain
//! `cerberus init`/`cerberus guard` never touches the network — only
//! `sync` does. Applying an update always requires `apply: true`
//! (`cerberus source sync --yes` at the CLI), so remote content that
//! executes against every guarded tool call never changes on a machine
//! without a human asking for it, and a pending update's diff can be shown
//! before it's ever applied.

mod repo;
pub mod spec;

use crate::config::{self, SourceConfig};
use crate::init;
use crate::integrations::tirith::{self, compose};
use crate::paths::Paths;
use crate::process::command_exists;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

/// The outcome of validating a source's fetched content — `.rego` through
/// `opa check`, `tirith/*.yaml` through `tirith rule validate` on the
/// composed policy — before any of it is installed. This is a supply-chain
/// safety gate on *untrusted content coming from a source*, distinct from
/// the heads' own fail-open philosophy about a *missing binary at guard
/// time*: a source that ships broken content should never be installed at
/// all, rather than surfacing as a `cupcake`/`tirith` error (or a silently
/// degraded head) later.
///
/// Both kinds collapse into one type deliberately, so a caller can't report
/// on one and forget the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentCheck {
    /// The source ships nothing of this kind — nothing to validate.
    NotApplicable,
    /// Everything parses and compiles cleanly.
    Passed,
    /// The validating binary isn't on PATH, so the check couldn't run. The
    /// content is still installed — cerberus doesn't require `opa` or
    /// `tirith` merely to *accept* a source, only to enforce the
    /// corresponding head — but this is surfaced so the caller can warn
    /// that it went in unchecked.
    Skipped,
}

impl ContentCheck {
    /// Merges two checks into the one a caller should report. `Skipped`
    /// dominates `Passed`, so a source whose Rego was validated but whose
    /// tirith fragments weren't still warns; `NotApplicable` never hides a
    /// real result.
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Skipped, _) | (_, Self::Skipped) => Self::Skipped,
            (Self::Passed, _) | (_, Self::Passed) => Self::Passed,
            _ => Self::NotApplicable,
        }
    }
}

/// Runs `opa check` over `dir`'s `.rego` files, if there are any and `opa`
/// is available. Returns `Err` only when `opa` actually rejected the
/// content: that's the one outcome that must abort an `add`/`sync` before
/// anything is installed.
fn check_rego(dir: &Path) -> Result<ContentCheck, String> {
    if !contains_ext_recursive(dir, "rego") {
        return Ok(ContentCheck::NotApplicable);
    }
    if !command_exists("opa") {
        return Ok(ContentCheck::Skipped);
    }
    let output = Command::new("opa")
        .arg("check")
        .arg(dir)
        .output()
        .map_err(|e| format!("failed to run opa check: {e}"))?;
    if output.status.success() {
        Ok(ContentCheck::Passed)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

/// Validates a source's tirith fragments by composing a *candidate* overlay
/// — cerberus's base plus everything already installed plus this source's
/// fetched fragments — and running the real `tirith rule validate` over it.
///
/// Composing first, rather than validating a fragment alone, is the only
/// check worth anything: a fragment is a partial policy with no
/// `schema_version`, so tirith can't judge it in isolation, and what
/// actually has to be valid is the merged file `tirith check` will read.
/// This also catches a fragment that's individually fine but breaks the
/// composition (a duplicate rule id that survived namespacing, say).
///
/// Mirrors [`check_rego`]'s contract exactly: a rejection aborts the whole
/// operation before anything is installed, and a missing `tirith` binary
/// skips with a warning rather than blocking the source.
fn check_tirith(
    paths: &Paths,
    name: &str,
    cache: &Path,
) -> Result<(ContentCheck, Vec<String>), String> {
    let fragments = cache.join("tirith");
    if !contains_ext_recursive(&fragments, "yaml") {
        return Ok((ContentCheck::NotApplicable, Vec::new()));
    }
    if !command_exists("tirith") {
        return Ok((ContentCheck::Skipped, Vec::new()));
    }

    // Everything already configured, minus this source (a `sync` is
    // replacing its installed fragments, not stacking on them), plus what
    // was just fetched.
    let mut layers: Vec<compose::Layer> = compose::collect_layers(paths)
        .into_iter()
        .filter(|l| l.namespace.as_deref() != Some(name))
        .collect();
    layers.extend(compose::read_fragments_from(
        &fragments,
        Some(name.to_string()),
        &format!("source '{name}'"),
    ));

    let composed = compose::compose(crate::embedded::TIRITH_POLICY, &layers);
    if let Some(problem) = composed.problems.first() {
        return Err(problem.clone());
    }

    let scratch = paths.source_cache_dir(name).with_extension("validate");
    let _ = fs::remove_dir_all(&scratch);
    fs::create_dir_all(&scratch).map_err(|e| format!("couldn't create a scratch dir: {e}"))?;
    let candidate = scratch.join("policy.yaml");
    fs::write(&candidate, &composed.yaml)
        .map_err(|e| format!("couldn't write a candidate policy: {e}"))?;

    let output = Command::new("tirith")
        .args(["rule", "validate", "--path"])
        .arg(&candidate)
        .output();

    let verdict = match output {
        Ok(out) if out.status.success() => Ok(ContentCheck::Passed),
        Ok(out) => Err(String::from_utf8_lossy(&out.stderr).trim().to_string()),
        Err(e) => Err(format!("failed to run tirith rule validate: {e}")),
    };
    if verdict.is_err() {
        let _ = fs::remove_dir_all(&scratch);
        return verdict.map(|c| (c, Vec::new()));
    }

    // Validation only proves the rules are well-formed. Whether they can
    // ever actually fire is a separate — and much easier to get wrong —
    // question; see `tirith::rules_that_never_fire`.
    let never_fire = tirith::rules_that_never_fire(&composed.yaml, &scratch);
    let _ = fs::remove_dir_all(&scratch);

    let warnings = never_fire
        .into_iter()
        .map(|id| {
            format!(
                "rule '{id}' did not fire for any of its own examples_bad. `tirith check` only \
                 consults custom rules once tirith's built-in detections have escalated a \
                 command past tier 1, so a rule matching nothing tirith already finds \
                 interesting never runs in production — even though it validates cleanly. It is \
                 installed, but it is not enforcing anything."
            )
        })
        .collect();
    verdict.map(|c| (c, warnings))
}

/// Whether any file with `ext` exists anywhere under `dir`, at any depth.
/// `check_rego` can't just look one level down: a source may organize its
/// policies into subdirectories (`policies/cloud/destructive.rego`), and a
/// flat check would classify such a source as shipping no policies at all —
/// skipping the `opa check` gate entirely. Uses `DirEntry::file_type` rather
/// than following `path.is_dir()`, so a symlinked directory in a hostile
/// source can't loop the walk.
fn contains_ext_recursive(dir: &Path, ext: &str) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
        let path = entry.path();
        if is_dir {
            if contains_ext_recursive(&path, ext) {
                return true;
            }
        } else if path.extension().and_then(|x| x.to_str()) == Some(ext) {
            return true;
        }
    }
    false
}

pub struct SyncResult {
    pub name: String,
    pub status: SyncStatus,
}

/// The outcome of syncing one configured source.
pub enum SyncStatus {
    UpToDate,
    Applied {
        from: Option<String>,
        to: String,
        content_check: ContentCheck,
        installed: Installed,
        warnings: Vec<String>,
    },
    /// An update is available but wasn't applied (`apply: false`). `log`
    /// and `diffstat` are empty when there was no previous `pinned` commit
    /// to diff against (a source installed by hand-editing config.toml,
    /// never through `add`).
    PendingConfirmation {
        from: Option<String>,
        to: String,
        log: String,
        diffstat: String,
    },
    Failed(String),
}

/// What `add` produces on success: the recorded source, whether its content
/// was actually validated (see [`ContentCheck`]), and how much of each
/// head's content it turned out to carry.
#[derive(Debug)]
pub struct AddOutcome {
    pub source: SourceConfig,
    pub content_check: ContentCheck,
    pub installed: Installed,
    /// Non-fatal findings worth showing the user — currently a tirith rule
    /// that validates but can never fire. Installed, but not enforcing.
    pub warnings: Vec<String>,
}

/// Clones `git_url`, resolves `git_ref` (or the remote's default branch if
/// `None`) to a commit, validates whatever it ships (`.rego` via
/// `opa check`, `tirith/*.yaml` via `tirith rule validate` on the composed
/// policy), installs its content for all three heads, and records the
/// source in `config.toml`. Content a validator rejects aborts the whole
/// operation: nothing is installed and `config.toml` isn't touched.
pub fn add(
    paths: &Paths,
    name: &str,
    git_url: &str,
    git_ref: Option<&str>,
) -> Result<AddOutcome, String> {
    if !config::valid_source_name(name) {
        return Err(format!(
            "'{name}' isn't a valid source name (use lowercase letters, digits, '-', '_')"
        ));
    }
    if !command_exists("git") {
        return Err("git not on PATH".to_string());
    }

    let cache = paths.source_cache_dir(name);
    repo::clone(git_url, &cache)?;
    let sha = repo::resolve_ref(&cache, git_ref)?;
    repo::checkout(&cache, &sha)?;
    let (content_check, warnings) = validate_cache(paths, name, &cache)?;
    let installed = install_from_cache(paths, name)
        .map_err(|e| format!("couldn't install source '{name}': {e}"))?;

    let source = SourceConfig {
        name: name.to_string(),
        git: git_url.to_string(),
        git_ref: git_ref.map(str::to_string),
        pinned: Some(sha),
    };
    config::upsert_source(&paths.config_file(), source.clone())
        .map_err(|e| format!("couldn't write config.toml: {e}"))?;
    // Only once config.toml names the source does `collect_layers` see its
    // fragments, so the overlay is rewritten after the upsert, not before.
    refresh_tirith_overlay(paths);
    Ok(AddOutcome {
        source,
        content_check,
        installed,
        warnings,
    })
}

/// Runs every content validator over a fetched clone and combines their
/// verdicts, along with any non-fatal warnings. Errors name which validator
/// objected, since "opa rejected this" and "tirith rejected this" want
/// completely different fixes.
fn validate_cache(
    paths: &Paths,
    name: &str,
    cache: &Path,
) -> Result<(ContentCheck, Vec<String>), String> {
    let rego = check_rego(&cache.join("policies"))
        .map_err(|e| format!("source '{name}' failed opa validation: {e}"))?;
    let (tirith, warnings) = check_tirith(paths, name, cache)
        .map_err(|e| format!("source '{name}' failed tirith validation: {e}"))?;
    Ok((rego.merge(tirith), warnings))
}

/// Recomposes and rewrites the tirith overlay after a source's fragments
/// change — the risk head's equivalent of the `.rhai`/`.rego` files simply
/// appearing on disk, since tirith reads one composed file rather than a
/// directory.
///
/// Best-effort: by this point the source is already installed and recorded,
/// and `guard`'s own self-heal recomposes anyway if the file turns out not
/// to have loaded, so a failure here must not fail the operation.
fn refresh_tirith_overlay(paths: &Paths) {
    let _ = init::write_tirith_overlay(paths);
}

/// Removes a source's config entry, its installed content for all three
/// heads, and its cached clone, then recomposes the tirith overlay so the
/// source's rules stop enforcing immediately. Returns whether a configured
/// entry actually existed (the on-disk cleanup happens either way,
/// best-effort).
pub fn remove(paths: &Paths, name: &str) -> Result<bool, String> {
    let removed = config::remove_source(&paths.config_file(), name)
        .map_err(|e| format!("couldn't update config.toml: {e}"))?;
    let _ = fs::remove_dir_all(paths.source_rules_dir(name));
    let _ = fs::remove_dir_all(paths.cupcake_source_policies_dir(name));
    let _ = fs::remove_dir_all(paths.source_tirith_dir(name));
    let _ = fs::remove_dir_all(paths.source_cache_dir(name));
    // Deleting the fragments isn't enough on its own: they're already baked
    // into the composed policy tirith reads, so it has to be rebuilt.
    refresh_tirith_overlay(paths);
    Ok(removed)
}

pub fn list(paths: &Paths) -> Vec<SourceConfig> {
    config::sources(paths)
}

/// Fetches and, only with `apply: true`, applies an update for `name` (or
/// every configured source when `name` is `None`). Without `apply`, this
/// only fetches and reports whether an update is pending — nothing on disk
/// changes and `config.toml`'s `pinned` value is untouched.
pub fn sync(paths: &Paths, name: Option<&str>, apply: bool) -> Vec<SyncResult> {
    config::sources(paths)
        .into_iter()
        .filter(|s| name.is_none_or(|n| n == s.name))
        .map(|source| SyncResult {
            name: source.name.clone(),
            status: sync_one(paths, &source, apply),
        })
        .collect()
}

fn sync_one(paths: &Paths, source: &SourceConfig, apply: bool) -> SyncStatus {
    if !command_exists("git") {
        return SyncStatus::Failed("git not on PATH".to_string());
    }
    let cache = paths.source_cache_dir(&source.name);
    if !cache.is_dir()
        && let Err(e) = repo::clone(&source.git, &cache)
    {
        return SyncStatus::Failed(e);
    }
    if let Err(e) = repo::fetch(&cache) {
        return SyncStatus::Failed(e);
    }
    let resolved = match repo::resolve_ref(&cache, source.git_ref.as_deref()) {
        Ok(sha) => sha,
        Err(e) => return SyncStatus::Failed(e),
    };

    if source.pinned.as_deref() == Some(resolved.as_str()) {
        return SyncStatus::UpToDate;
    }

    if !apply {
        let (log, diffstat) = match source.pinned.as_deref() {
            Some(from) => (
                repo::log_range(&cache, from, &resolved),
                repo::diffstat_range(&cache, from, &resolved),
            ),
            None => (String::new(), String::new()),
        };
        return SyncStatus::PendingConfirmation {
            from: source.pinned.clone(),
            to: resolved,
            log,
            diffstat,
        };
    }

    if let Err(e) = repo::checkout(&cache, &resolved) {
        return SyncStatus::Failed(e);
    }
    let (content_check, warnings) = match validate_cache(paths, &source.name, &cache) {
        Ok(v) => v,
        Err(e) => return SyncStatus::Failed(e),
    };
    let installed = match install_from_cache(paths, &source.name) {
        Ok(i) => i,
        Err(e) => {
            return SyncStatus::Failed(format!("couldn't install source '{}': {e}", source.name));
        }
    };
    let mut updated = source.clone();
    updated.pinned = Some(resolved.clone());
    if let Err(e) = config::upsert_source(&paths.config_file(), updated) {
        return SyncStatus::Failed(format!("couldn't write config.toml: {e}"));
    }
    refresh_tirith_overlay(paths);
    SyncStatus::Applied {
        from: source.pinned.clone(),
        to: resolved,
        content_check,
        installed,
        warnings,
    }
}

/// How much of each head's content a source turned out to carry. Reported
/// back to the user by `add`/`sync`/`list` so "did my team's rules actually
/// land" is answerable without going digging on the filesystem.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    pub rules: usize,
    pub policies: usize,
    pub tirith: usize,
}

impl std::fmt::Display for Installed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} rule(s), {} polic(ies), {} tirith fragment(s)",
            self.rules, self.policies, self.tirith
        )
    }
}

fn install_from_cache(paths: &Paths, name: &str) -> io::Result<Installed> {
    let cache = paths.source_cache_dir(name);
    reject_nested(&cache.join("rules"), "rhai", "rules")?;
    reject_nested(&cache.join("tirith"), "yaml", "tirith")?;
    Ok(Installed {
        rules: install_matching_ext(&cache.join("rules"), &paths.source_rules_dir(name), "rhai")?,
        policies: install_matching_ext(
            &cache.join("policies"),
            &paths.cupcake_source_policies_dir(name),
            "rego",
        )?,
        tirith: install_matching_ext(
            &cache.join("tirith"),
            &paths.source_tirith_dir(name),
            "yaml",
        )?,
    })
}

/// `rules/*.rhai` and `tirith/*.yaml` must stay flat: `engine::load_rules`
/// and `compose::read_fragments` each read a single directory level, so a
/// nested file would install but silently never run — the "quietly stopped
/// working" failure mode this codebase exists to prevent. Reject the layout
/// at `add`/`sync` time instead, loudly. (`policies/` has no such
/// constraint: cupcake's own scanner is recursive, so nested policies
/// install *and* enforce.)
fn reject_nested(src: &Path, ext: &str, label: &str) -> io::Result<()> {
    let Ok(entries) = fs::read_dir(src) else {
        return Ok(());
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if entry.file_type().is_ok_and(|t| t.is_dir()) && contains_ext_recursive(&path, ext) {
            return Err(io::Error::other(format!(
                "{} contains .{ext} files in subdirectories; a source's {label}/ must be flat \
                 (policies/ may nest, {label}/ may not)",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Returns how many files were installed. Fully replaces `dest`'s contents
/// with every `*.ext` file from `src`,
/// preserving `src`'s subdirectory layout: `policies/cloud/destructive.rego`
/// installs to `dest/cloud/destructive.rego`. Nesting matters for real
/// sources — one organized by category can carry two different
/// `destructive.rego` files, which a flat copy would silently overwrite.
/// Safe as a full replace specifically because `dest` (a `sources/<name>`
/// subdirectory) is exclusively sync-managed — unlike the top-level rules
/// dir, where personal files also live. A source that ships only rules or
/// only policies is fine: a missing `src` is a no-op, not an error.
fn install_matching_ext(src: &Path, dest: &Path, ext: &str) -> io::Result<usize> {
    if dest.exists() {
        fs::remove_dir_all(dest)?;
    }
    if !src.is_dir() {
        return Ok(0);
    }
    install_dir(src, dest, ext)
}

/// The recursive half of [`install_matching_ext`]. Like
/// [`contains_ext_recursive`], directories are identified via
/// `DirEntry::file_type` rather than following symlinks, so a symlinked
/// directory in a hostile source is skipped rather than followed — the
/// copy can never escape `dest` or loop.
fn install_dir(src: &Path, dest: &Path, ext: &str) -> io::Result<usize> {
    fs::create_dir_all(dest)?;
    let mut installed = 0;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let Some(file_name) = path.file_name().map(|n| n.to_os_string()) else {
            continue;
        };
        if entry.file_type()?.is_dir() {
            installed += install_dir(&path, &dest.join(&file_name), ext)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some(ext) {
            fs::copy(&path, dest.join(&file_name))?;
            installed += 1;
        }
    }
    Ok(installed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as StdCommand;

    fn scratch_paths(name: &str) -> Paths {
        let root = std::env::temp_dir().join(format!(
            "cerberus-sources-mod-test-{}-{name}",
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

    fn run_git(dir: &Path, args: &[&str]) {
        let status = StdCommand::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {:?} failed in {:?}", args, dir);
    }

    fn make_upstream(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cerberus-sources-mod-upstream-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        run_git(&dir, &["init", "-q", "-b", "main"]);
        run_git(&dir, &["config", "user.email", "test@example.com"]);
        run_git(&dir, &["config", "user.name", "Test"]);
        fs::create_dir_all(dir.join("rules")).unwrap();
        fs::create_dir_all(dir.join("policies")).unwrap();
        fs::create_dir_all(dir.join("tirith")).unwrap();
        fs::write(
            dir.join("rules/deny-all.rhai"),
            "fn check(cmd, cwd, input) { return \"denied by upstream rule\"; }",
        )
        .unwrap();
        fs::write(
            dir.join("policies/example.rego"),
            "package cupcake.global.policies.cerberus.sources.example\n",
        )
        .unwrap();
        fs::write(
            dir.join("tirith/risky.yaml"),
            "custom_rules:\n  - id: upstream-risk\n    context: [exec]\n    \
             pattern: 'zzz-upstream'\n    severity: HIGH\n    action: block\n    \
             title: An upstream risk rule\n",
        )
        .unwrap();
        run_git(&dir, &["add", "."]);
        run_git(&dir, &["commit", "-q", "-m", "initial"]);
        dir
    }

    /// One repo, all three heads. This is the property that makes a source
    /// worth using over wiring tirith and cupcake up by hand.
    #[test]
    fn add_installs_content_for_all_three_heads_and_records_config() {
        let paths = scratch_paths("add");
        let upstream = make_upstream("add");

        let outcome = add(&paths, "team", &upstream.to_string_lossy(), None).unwrap();
        let source = outcome.source;
        assert_eq!(source.name, "team");
        assert!(source.pinned.is_some());
        assert!(matches!(
            outcome.content_check,
            ContentCheck::Passed | ContentCheck::Skipped
        ));
        assert_eq!(
            outcome.installed,
            Installed {
                rules: 1,
                policies: 1,
                tirith: 1
            }
        );

        assert!(
            paths
                .source_rules_dir("team")
                .join("deny-all.rhai")
                .is_file()
        );
        assert!(
            paths
                .cupcake_source_policies_dir("team")
                .join("example.rego")
                .is_file()
        );
        assert!(
            paths.source_tirith_dir("team").join("risky.yaml").is_file(),
            "the risk head's half of a source has to install too"
        );
        assert_eq!(list(&paths), vec![source]);
    }

    /// A tirith fragment that merely lands on disk enforces nothing —
    /// tirith reads one composed file. `add` has to rebuild it, with the
    /// source's rule id namespaced, or the risk head silently ignores
    /// everything the source shipped.
    #[test]
    fn add_composes_the_source_into_the_live_tirith_overlay() {
        let paths = scratch_paths("add-composes");
        let upstream = make_upstream("add-composes");
        add(&paths, "team", &upstream.to_string_lossy(), None).unwrap();

        let overlay = fs::read_to_string(paths.tirith_overlay_policy_file())
            .expect("add must write the composed overlay");
        assert!(
            overlay.contains("team-upstream-risk"),
            "the source's rule must be namespaced into the overlay: {overlay}"
        );
        assert!(
            overlay.contains("cerberus-guard-self-tamper"),
            "and must not displace cerberus's own rule: {overlay}"
        );
    }

    /// The mirror of the above: removing a source has to rebuild the
    /// overlay too, or its rules keep enforcing after it's gone.
    #[test]
    fn remove_recomposes_the_overlay_without_the_source() {
        let paths = scratch_paths("remove-recomposes");
        let upstream = make_upstream("remove-recomposes");
        add(&paths, "team", &upstream.to_string_lossy(), None).unwrap();
        assert!(
            fs::read_to_string(paths.tirith_overlay_policy_file())
                .unwrap()
                .contains("team-upstream-risk")
        );

        remove(&paths, "team").unwrap();

        let overlay = fs::read_to_string(paths.tirith_overlay_policy_file()).unwrap();
        assert!(
            !overlay.contains("team-upstream-risk"),
            "a removed source's rules must stop enforcing: {overlay}"
        );
        assert!(overlay.contains("cerberus-guard-self-tamper"));
        assert!(!paths.source_tirith_dir("team").exists());
    }

    /// A source organized by category (`policies/cloud/destructive.rego`,
    /// `policies/database/destructive.rego`) must install with its
    /// subdirectories preserved — a flat copy would overwrite one
    /// `destructive.rego` with the other.
    #[test]
    fn add_installs_a_nested_policy_layout_preserving_directories() {
        let paths = scratch_paths("add-nested");
        let upstream = make_upstream("add-nested");
        for category in ["cloud", "database"] {
            fs::create_dir_all(upstream.join("policies").join(category)).unwrap();
            fs::write(
                upstream
                    .join("policies")
                    .join(category)
                    .join("destructive.rego"),
                format!("package cupcake.global.policies.cerberus.sources.team.{category}\n"),
            )
            .unwrap();
        }
        run_git(&upstream, &["add", "."]);
        run_git(&upstream, &["commit", "-q", "-m", "nested policies"]);

        let outcome = add(&paths, "team", &upstream.to_string_lossy(), None).unwrap();

        let installed = paths.cupcake_source_policies_dir("team");
        assert!(installed.join("cloud/destructive.rego").is_file());
        assert!(installed.join("database/destructive.rego").is_file());
        assert!(
            !installed.join("destructive.rego").exists(),
            "a nested layout must not also be flattened into the top level"
        );
        // A flat rego check would classify this source as NotApplicable and
        // skip the opa gate entirely; nested policies must still be gated.
        assert_ne!(outcome.content_check, ContentCheck::NotApplicable);
    }

    /// `rules/` must stay flat: the rhai loader reads one directory level,
    /// so nested scripts would install but never run. That has to fail the
    /// `add`, not install silently-dead rules.
    #[test]
    fn add_rejects_a_source_with_nested_rhai_files() {
        let paths = scratch_paths("add-nested-rhai");
        let upstream = make_upstream("add-nested-rhai");
        fs::create_dir_all(upstream.join("rules/nested")).unwrap();
        fs::write(
            upstream.join("rules/nested/deep.rhai"),
            "fn check(cmd, cwd, input) { return \"never runs\"; }",
        )
        .unwrap();
        run_git(&upstream, &["add", "."]);
        run_git(&upstream, &["commit", "-q", "-m", "nested rules"]);

        let err = add(&paths, "team", &upstream.to_string_lossy(), None).unwrap_err();
        assert!(
            err.contains("rules/ must be flat"),
            "unexpected error: {err}"
        );
        assert!(!paths.source_rules_dir("team").exists());
        assert!(!paths.cupcake_source_policies_dir("team").exists());
        assert_eq!(list(&paths), vec![]);
    }

    /// `compose::read_fragments_from` reads one directory level, so a
    /// nested fragment would install and never merge — the same
    /// silently-dead-content trap as a nested `.rhai`, and rejected the
    /// same way.
    #[test]
    fn add_rejects_a_source_with_nested_tirith_fragments() {
        let paths = scratch_paths("add-nested-tirith");
        let upstream = make_upstream("add-nested-tirith");
        fs::create_dir_all(upstream.join("tirith/nested")).unwrap();
        fs::write(
            upstream.join("tirith/nested/deep.yaml"),
            "custom_rules: []\n",
        )
        .unwrap();
        run_git(&upstream, &["add", "."]);
        run_git(&upstream, &["commit", "-q", "-m", "nested tirith"]);

        let err = add(&paths, "team", &upstream.to_string_lossy(), None).unwrap_err();
        assert!(
            err.contains("tirith/ must be flat"),
            "unexpected error: {err}"
        );
        assert!(!paths.source_tirith_dir("team").exists());
        assert_eq!(list(&paths), vec![]);
    }

    /// The tirith counterpart to the `opa check` gate: content tirith
    /// rejects must abort the whole `add`, with nothing installed for any
    /// head and no entry in config.toml.
    #[test]
    fn add_rejects_a_source_whose_tirith_fragment_tirith_wont_accept() {
        if !command_exists("tirith") {
            eprintln!("skipping: tirith not on PATH");
            return;
        }
        let paths = scratch_paths("add-tirith-rejects");
        let upstream = make_upstream("add-tirith-rejects");
        // A custom rule must carry exactly one of `pattern:`/`when:`;
        // declaring neither is a shape tirith rejects outright.
        fs::write(
            upstream.join("tirith/broken.yaml"),
            "custom_rules:\n  - id: no-matcher\n    context: [exec]\n    severity: HIGH\n",
        )
        .unwrap();
        run_git(&upstream, &["add", "."]);
        run_git(&upstream, &["commit", "-q", "-m", "broken tirith rule"]);

        let err = add(&paths, "team", &upstream.to_string_lossy(), None).unwrap_err();
        assert!(err.contains("tirith validation"), "unexpected error: {err}");
        assert!(!paths.source_rules_dir("team").exists());
        assert!(!paths.source_tirith_dir("team").exists());
        assert_eq!(
            list(&paths),
            vec![],
            "config.toml must not record a rejected source"
        );
    }

    #[test]
    fn add_reports_passed_when_opa_validates_good_rego() {
        if !command_exists("opa") {
            eprintln!("skipping: opa not on PATH");
            return;
        }
        let paths = scratch_paths("add-opa-passed");
        let upstream = make_upstream("add-opa-passed");
        let outcome = add(&paths, "team", &upstream.to_string_lossy(), None).unwrap();
        assert_eq!(outcome.content_check, ContentCheck::Passed);
    }

    #[test]
    fn add_rejects_a_source_with_invalid_rego_and_installs_nothing() {
        if !command_exists("opa") {
            eprintln!("skipping: opa not on PATH");
            return;
        }
        let paths = scratch_paths("add-opa-rejects");
        let upstream = make_upstream("add-opa-rejects");
        fs::write(
            upstream.join("policies/broken.rego"),
            "this is not valid rego {{{",
        )
        .unwrap();
        run_git(&upstream, &["add", "."]);
        run_git(&upstream, &["commit", "-q", "-m", "add broken policy"]);

        let err = add(&paths, "team", &upstream.to_string_lossy(), None).unwrap_err();
        assert!(err.contains("opa validation"), "unexpected error: {err}");

        assert!(
            !paths.source_rules_dir("team").exists(),
            "a source that fails validation must install nothing"
        );
        assert!(!paths.cupcake_source_policies_dir("team").exists());
        assert_eq!(
            list(&paths),
            vec![],
            "config.toml must not record a rejected source"
        );
    }

    #[test]
    fn check_rego_is_not_applicable_when_a_source_ships_no_policies() {
        let dir = std::env::temp_dir().join(format!(
            "cerberus-sources-mod-test-{}-no-policies-dir",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        // Deliberately not created: mirrors a source that ships only rules.
        assert_eq!(check_rego(&dir), Ok(ContentCheck::NotApplicable));
    }

    #[test]
    fn add_rejects_an_invalid_name() {
        let paths = scratch_paths("invalid-name");
        let upstream = make_upstream("invalid-name");
        let err = add(&paths, "../escape", &upstream.to_string_lossy(), None).unwrap_err();
        assert!(err.contains("valid source name"));
    }

    #[test]
    fn sync_reports_up_to_date_when_nothing_changed() {
        let paths = scratch_paths("sync-up-to-date");
        let upstream = make_upstream("sync-up-to-date");
        add(&paths, "team", &upstream.to_string_lossy(), None).unwrap();

        let results = sync(&paths, None, false);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].status, SyncStatus::UpToDate));
    }

    #[test]
    fn sync_without_apply_reports_pending_and_changes_nothing() {
        let paths = scratch_paths("sync-pending");
        let upstream = make_upstream("sync-pending");
        let original = add(&paths, "team", &upstream.to_string_lossy(), None)
            .unwrap()
            .source;

        fs::write(
            upstream.join("rules/second.rhai"),
            "fn check(cmd, cwd, input) {}",
        )
        .unwrap();
        run_git(&upstream, &["add", "."]);
        run_git(&upstream, &["commit", "-q", "-m", "second"]);

        let results = sync(&paths, None, false);
        assert_eq!(results.len(), 1);
        match &results[0].status {
            SyncStatus::PendingConfirmation { from, to, log, .. } => {
                assert_eq!(from.as_deref(), original.pinned.as_deref());
                assert_ne!(to, original.pinned.as_ref().unwrap());
                assert!(log.contains("second"));
            }
            _ => panic!("expected a pending update"),
        }
        // Not applied: config.toml and the installed files are untouched.
        assert_eq!(list(&paths), vec![original]);
        assert!(
            !paths.source_rules_dir("team").join("second.rhai").is_file(),
            "unapplied sync must not touch installed files"
        );
    }

    #[test]
    fn sync_with_apply_updates_pinned_and_reinstalls() {
        let paths = scratch_paths("sync-apply");
        let upstream = make_upstream("sync-apply");
        add(&paths, "team", &upstream.to_string_lossy(), None).unwrap();

        fs::write(
            upstream.join("rules/second.rhai"),
            "fn check(cmd, cwd, input) {}",
        )
        .unwrap();
        run_git(&upstream, &["add", "."]);
        run_git(&upstream, &["commit", "-q", "-m", "second"]);

        let results = sync(&paths, None, true);
        assert!(matches!(results[0].status, SyncStatus::Applied { .. }));
        assert!(paths.source_rules_dir("team").join("second.rhai").is_file());

        let after = list(&paths);
        assert_eq!(after.len(), 1);
        assert!(after[0].pinned.is_some());
    }

    #[test]
    fn sync_with_apply_rejects_an_update_with_invalid_rego_and_keeps_the_old_pin() {
        if !command_exists("opa") {
            eprintln!("skipping: opa not on PATH");
            return;
        }
        let paths = scratch_paths("sync-apply-opa-rejects");
        let upstream = make_upstream("sync-apply-opa-rejects");
        let original = add(&paths, "team", &upstream.to_string_lossy(), None)
            .unwrap()
            .source;

        fs::write(
            upstream.join("policies/broken.rego"),
            "this is not valid rego {{{",
        )
        .unwrap();
        run_git(&upstream, &["add", "."]);
        run_git(&upstream, &["commit", "-q", "-m", "add broken policy"]);

        let results = sync(&paths, None, true);
        assert!(
            matches!(results[0].status, SyncStatus::Failed(_)),
            "expected the update to be rejected"
        );

        // The old pin and installed content survive an update opa rejects.
        assert_eq!(list(&paths), vec![original]);
        assert!(
            !paths
                .cupcake_source_policies_dir("team")
                .join("broken.rego")
                .exists()
        );
    }

    #[test]
    fn remove_deletes_config_and_installed_files() {
        let paths = scratch_paths("remove");
        let upstream = make_upstream("remove");
        add(&paths, "team", &upstream.to_string_lossy(), None).unwrap();

        assert!(remove(&paths, "team").unwrap());
        assert_eq!(list(&paths), vec![]);
        assert!(!paths.source_rules_dir("team").exists());
        assert!(!paths.cupcake_source_policies_dir("team").exists());
        assert!(!remove(&paths, "team").unwrap(), "already removed");
    }
}
