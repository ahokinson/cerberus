//! Layered policy sources: named, independently syncable external
//! `.rhai`/`.rego` bundles (e.g. a team repo, or eventually a public
//! cerberus-examples repo) that stack on top of a machine's personal rules
//! (see `rules::evaluate`'s additive OR-of-denials).
//!
//! Trust model: `add` clones and pins a resolved commit SHA, and a plain
//! `cerberus init`/`cerberus guard` never touches the network — only
//! `sync` does. Applying an update always requires `apply: true`
//! (`cerberus source sync --yes` at the CLI), so remote content that
//! executes against every guarded tool call never changes on a machine
//! without a human asking for it, and a pending update's diff can be shown
//! before it's ever applied.

mod repo;

use crate::config::{self, SourceConfig};
use crate::paths::Paths;
use crate::process::command_exists;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

/// The outcome of validating a source's fetched `.rego` files with
/// `opa check` before they're ever installed. This is a supply-chain safety
/// gate on *untrusted content coming from a source*, distinct from the
/// `policy` head's own fail-open philosophy about a *missing binary at
/// guard time* — a source that ships broken or malicious-shaped Rego
/// should never be installed at all, not surface as a `cupcake` error (or a
/// silently degraded `policy` head) later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegoCheck {
    /// The source ships no `.rego` files at all — nothing to validate.
    NotApplicable,
    /// Every `.rego` file parses and compiles cleanly.
    Passed,
    /// `opa` isn't on PATH, so validation couldn't run. The content is
    /// still installed — cerberus doesn't require `opa` merely to accept a
    /// source, only to enforce the `policy` head — but this is surfaced so
    /// the caller can warn that it went in unchecked.
    Skipped,
}

/// Runs `opa check` over `dir`'s `.rego` files, if there are any and `opa`
/// is available. Returns `Err` only when `opa` actually rejected the
/// content: that's the one outcome that must abort an `add`/`sync` before
/// anything is installed.
fn check_rego(dir: &Path) -> Result<RegoCheck, String> {
    if !contains_ext_recursive(dir, "rego") {
        return Ok(RegoCheck::NotApplicable);
    }
    if !command_exists("opa") {
        return Ok(RegoCheck::Skipped);
    }
    let output = Command::new("opa")
        .arg("check")
        .arg(dir)
        .output()
        .map_err(|e| format!("failed to run opa check: {e}"))?;
    if output.status.success() {
        Ok(RegoCheck::Passed)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
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
        rego_check: RegoCheck,
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

/// What `add` produces on success: the recorded source plus whether its
/// `.rego` content (if any) was actually validated. See [`RegoCheck`].
#[derive(Debug)]
pub struct AddOutcome {
    pub source: SourceConfig,
    pub rego_check: RegoCheck,
}

/// Clones `git_url`, resolves `git_ref` (or the remote's default branch if
/// `None`) to a commit, validates any `.rego` it ships with `opa check`,
/// installs its `rules/*.rhai` and `policies/*.rego`, and records the
/// source in `config.toml`. A `.rego` file `opa` rejects aborts the whole
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
    let rego_check = check_rego(&cache.join("policies"))
        .map_err(|e| format!("source '{name}' failed opa validation: {e}"))?;
    install_from_cache(paths, name)
        .map_err(|e| format!("couldn't install source '{name}': {e}"))?;

    let source = SourceConfig {
        name: name.to_string(),
        git: git_url.to_string(),
        git_ref: git_ref.map(str::to_string),
        pinned: Some(sha),
    };
    config::upsert_source(&paths.config_file(), source.clone())
        .map_err(|e| format!("couldn't write config.toml: {e}"))?;
    Ok(AddOutcome { source, rego_check })
}

/// Removes a source's config entry, installed rules/policies, and cached
/// clone. Returns whether a configured entry actually existed (the on-disk
/// cleanup happens either way, best-effort).
pub fn remove(paths: &Paths, name: &str) -> Result<bool, String> {
    let removed = config::remove_source(&paths.config_file(), name)
        .map_err(|e| format!("couldn't update config.toml: {e}"))?;
    let _ = fs::remove_dir_all(paths.source_rules_dir(name));
    let _ = fs::remove_dir_all(paths.cupcake_source_custom_dir(name));
    let _ = fs::remove_dir_all(paths.source_cache_dir(name));
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
    let rego_check = match check_rego(&cache.join("policies")) {
        Ok(c) => c,
        Err(e) => return SyncStatus::Failed(format!("opa validation failed: {e}")),
    };
    if let Err(e) = install_from_cache(paths, &source.name) {
        return SyncStatus::Failed(format!("couldn't install source '{}': {e}", source.name));
    }
    let mut updated = source.clone();
    updated.pinned = Some(resolved.clone());
    if let Err(e) = config::upsert_source(&paths.config_file(), updated) {
        return SyncStatus::Failed(format!("couldn't write config.toml: {e}"));
    }
    SyncStatus::Applied {
        from: source.pinned.clone(),
        to: resolved,
        rego_check,
    }
}

fn install_from_cache(paths: &Paths, name: &str) -> io::Result<()> {
    let cache = paths.source_cache_dir(name);
    reject_nested_rules(&cache.join("rules"))?;
    install_matching_ext(&cache.join("rules"), &paths.source_rules_dir(name), "rhai")?;
    install_matching_ext(
        &cache.join("policies"),
        &paths.cupcake_source_custom_dir(name),
        "rego",
    )?;
    Ok(())
}

/// `rules/*.rhai` must stay flat: `engine::load_rules` reads a single
/// directory level, so a nested script would install but silently never
/// run — the "quietly stopped working" failure mode this codebase exists
/// to prevent. Reject the layout at `add`/`sync` time instead, loudly.
/// (`policies/` has no such constraint: cupcake's own scanner is
/// recursive, so nested policies install *and* enforce.)
fn reject_nested_rules(rules_src: &Path) -> io::Result<()> {
    let Ok(entries) = fs::read_dir(rules_src) else {
        return Ok(());
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if entry.file_type().is_ok_and(|t| t.is_dir()) && contains_ext_recursive(&path, "rhai") {
            return Err(io::Error::other(format!(
                "{} contains .rhai files in subdirectories; a source's rules/ must be flat \
                 (policies/ may nest, rules/ may not)",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Fully replaces `dest`'s contents with every `*.ext` file from `src`,
/// preserving `src`'s subdirectory layout: `policies/cloud/destructive.rego`
/// installs to `dest/cloud/destructive.rego`. Nesting matters for real
/// sources — one organized by category can carry two different
/// `destructive.rego` files, which a flat copy would silently overwrite.
/// Safe as a full replace specifically because `dest` (a `sources/<name>`
/// subdirectory) is exclusively sync-managed — unlike the top-level rules
/// dir, where personal files also live. A source that ships only rules or
/// only policies is fine: a missing `src` is a no-op, not an error.
fn install_matching_ext(src: &Path, dest: &Path, ext: &str) -> io::Result<()> {
    if dest.exists() {
        fs::remove_dir_all(dest)?;
    }
    if !src.is_dir() {
        return Ok(());
    }
    install_dir(src, dest, ext)
}

/// The recursive half of [`install_matching_ext`]. Like
/// [`contains_ext_recursive`], directories are identified via
/// `DirEntry::file_type` rather than following symlinks, so a symlinked
/// directory in a hostile source is skipped rather than followed — the
/// copy can never escape `dest` or loop.
fn install_dir(src: &Path, dest: &Path, ext: &str) -> io::Result<()> {
    fs::create_dir_all(dest)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let Some(file_name) = path.file_name().map(|n| n.to_os_string()) else {
            continue;
        };
        if entry.file_type()?.is_dir() {
            install_dir(&path, &dest.join(&file_name), ext)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some(ext) {
            fs::copy(&path, dest.join(&file_name))?;
        }
    }
    Ok(())
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
        run_git(&dir, &["add", "."]);
        run_git(&dir, &["commit", "-q", "-m", "initial"]);
        dir
    }

    #[test]
    fn add_installs_rules_and_policies_and_records_config() {
        let paths = scratch_paths("add");
        let upstream = make_upstream("add");

        let outcome = add(&paths, "team", &upstream.to_string_lossy(), None).unwrap();
        let source = outcome.source;
        assert_eq!(source.name, "team");
        assert!(source.pinned.is_some());
        assert!(matches!(
            outcome.rego_check,
            RegoCheck::Passed | RegoCheck::Skipped
        ));

        assert!(
            paths
                .source_rules_dir("team")
                .join("deny-all.rhai")
                .is_file()
        );
        assert!(
            paths
                .cupcake_source_custom_dir("team")
                .join("example.rego")
                .is_file()
        );
        assert_eq!(list(&paths), vec![source]);
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

        let installed = paths.cupcake_source_custom_dir("team");
        assert!(installed.join("cloud/destructive.rego").is_file());
        assert!(installed.join("database/destructive.rego").is_file());
        assert!(
            !installed.join("destructive.rego").exists(),
            "a nested layout must not also be flattened into the top level"
        );
        // A flat rego check would classify this source as NotApplicable and
        // skip the opa gate entirely; nested policies must still be gated.
        assert_ne!(outcome.rego_check, RegoCheck::NotApplicable);
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
        assert!(!paths.cupcake_source_custom_dir("team").exists());
        assert_eq!(list(&paths), vec![]);
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
        assert_eq!(outcome.rego_check, RegoCheck::Passed);
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
        assert!(!paths.cupcake_source_custom_dir("team").exists());
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
        assert_eq!(check_rego(&dir), Ok(RegoCheck::NotApplicable));
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
                .cupcake_source_custom_dir("team")
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
        assert!(!paths.cupcake_source_custom_dir("team").exists());
        assert!(!remove(&paths, "team").unwrap(), "already removed");
    }
}
