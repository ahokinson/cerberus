//! `git` operations for a source's cached clone (`Paths::source_cache_dir`).
//! Deliberately separate from `rules::git`: that module is
//! `pub(super)`-scoped to `rules` and is read-only introspection of the
//! *repo being edited* (is the tree dirty, would this discard commits) — a
//! different concern from cloning and mutating a cerberus-owned cache of a
//! *different*, remote repo. The two share only the generic "run git in a
//! directory" primitive, hoisted to `crate::process::{git_cmd, git_stdout}`.

use crate::process::{git_cmd, git_stdout};
use std::fs;
use std::path::Path;
use std::process::Command;

fn run_stdout(dest: &Path, args: &[&str]) -> String {
    git_stdout(dest, args)
}

/// Clones `url` into `dest`, clearing any stale directory already there
/// first. A full clone, not shallow: `sync` needs real history to compute
/// `git log <pinned>..<new>` and a diffstat between two arbitrary commits,
/// which a shallow clone can't provide. Team/example policy repos are
/// expected to be small, so this is a deliberate simplicity-over-speed
/// trade, not an oversight.
pub(super) fn clone(url: &str, dest: &Path) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("couldn't create {}: {e}", parent.display()))?;
    }
    if dest.exists() {
        fs::remove_dir_all(dest)
            .map_err(|e| format!("couldn't clear stale cache {}: {e}", dest.display()))?;
    }
    let status = Command::new("git")
        .args(["clone", "--quiet", url])
        .arg(dest)
        .status()
        .map_err(|e| format!("failed to run git clone: {e}"))?;
    if !status.success() {
        return Err(format!("git clone {url} into {} failed", dest.display()));
    }
    Ok(())
}

/// Fetches every branch and tag from `origin`, updating the refs `sync`
/// resolves against.
pub(super) fn fetch(dest: &Path) -> Result<(), String> {
    let status = git_cmd(dest, &["fetch", "--quiet", "--tags", "origin"])
        .status()
        .map_err(|e| format!("failed to run git fetch: {e}"))?;
    if !status.success() {
        return Err(format!("git fetch failed in {}", dest.display()));
    }
    Ok(())
}

fn rev_parse(dest: &Path, refname: &str) -> Result<String, String> {
    let output = git_cmd(
        dest,
        &["rev-parse", "--verify", &format!("{refname}^{{commit}}")],
    )
    .output()
    .map_err(|e| format!("failed to run git rev-parse: {e}"))?;
    if !output.status.success() {
        return Err(format!("{refname} doesn't resolve to a commit"));
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("non-UTF-8 output from git rev-parse: {e}"))
}

/// Resolves `git_ref` (a branch or tag name) to a commit SHA, or the
/// remote's default branch when `git_ref` is `None` (via `origin/HEAD`,
/// which a plain `git clone` sets up automatically). Tries the ref as a
/// remote-tracking branch first, then bare — tags aren't namespaced under
/// `refs/remotes/origin/`, so a tag only resolves on the second attempt.
pub(super) fn resolve_ref(dest: &Path, git_ref: Option<&str>) -> Result<String, String> {
    let remote_branch = format!("refs/remotes/origin/{}", git_ref.unwrap_or("HEAD"));
    if let Ok(sha) = rev_parse(dest, &remote_branch) {
        return Ok(sha);
    }
    if let Some(r) = git_ref
        && let Ok(sha) = rev_parse(dest, r)
    {
        return Ok(sha);
    }
    Err(format!(
        "couldn't resolve {} in {}",
        git_ref.unwrap_or("the default branch"),
        dest.display()
    ))
}

/// Detaches HEAD at `sha`. A source's cache is never worked in directly, so
/// there's no branch to keep in sync — just a fixed commit to install from.
pub(super) fn checkout(dest: &Path, sha: &str) -> Result<(), String> {
    let status = git_cmd(dest, &["checkout", "--quiet", "--detach", sha])
        .status()
        .map_err(|e| format!("failed to run git checkout: {e}"))?;
    if !status.success() {
        return Err(format!("git checkout {sha} failed in {}", dest.display()));
    }
    Ok(())
}

/// `git log --oneline from..to`, for showing what a pending `sync` would
/// bring in before it's applied.
pub(super) fn log_range(dest: &Path, from: &str, to: &str) -> String {
    run_stdout(dest, &["log", "--oneline", &format!("{from}..{to}")])
}

/// A diffstat between `from` and `to`, scoped to the two directories
/// cerberus actually reads from a source (`rules/`, `policies/`) rather than
/// the whole repo.
pub(super) fn diffstat_range(dest: &Path, from: &str, to: &str) -> String {
    run_stdout(
        dest,
        &["diff", "--stat", from, to, "--", "rules", "policies"],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as StdCommand;

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cerberus-sources-repo-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
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

    /// A real local repo to clone from, with two commits on `main` so
    /// there's a range to compute a log/diffstat over, plus a tag.
    fn make_upstream(name: &str) -> std::path::PathBuf {
        let dir = tempdir(&format!("{name}-upstream"));
        run_git(&dir, &["init", "-q", "-b", "main"]);
        run_git(&dir, &["config", "user.email", "test@example.com"]);
        run_git(&dir, &["config", "user.name", "Test"]);
        fs::create_dir_all(dir.join("rules")).unwrap();
        fs::write(dir.join("rules/first.rhai"), "fn check(cmd, cwd, input) {}").unwrap();
        run_git(&dir, &["add", "."]);
        run_git(&dir, &["commit", "-q", "-m", "first"]);
        run_git(&dir, &["tag", "v1"]);
        fs::write(
            dir.join("rules/second.rhai"),
            "fn check(cmd, cwd, input) {}",
        )
        .unwrap();
        run_git(&dir, &["add", "."]);
        run_git(&dir, &["commit", "-q", "-m", "second"]);
        dir
    }

    #[test]
    fn clone_then_resolve_default_branch_and_checkout_round_trip() {
        let upstream = make_upstream("clone-basic");
        let dest = tempdir("clone-basic-dest");
        fs::remove_dir_all(&dest).unwrap(); // clone must create it itself

        clone(&upstream.to_string_lossy(), &dest).unwrap();
        let sha = resolve_ref(&dest, None).unwrap();
        assert_eq!(sha.len(), 40, "expected a full commit SHA");
        checkout(&dest, &sha).unwrap();
        assert!(dest.join("rules/second.rhai").is_file());
    }

    #[test]
    fn resolve_ref_understands_a_tag_name() {
        let upstream = make_upstream("tag");
        let dest = tempdir("tag-dest");
        fs::remove_dir_all(&dest).unwrap();
        clone(&upstream.to_string_lossy(), &dest).unwrap();

        let tagged_sha = resolve_ref(&dest, Some("v1")).unwrap();
        checkout(&dest, &tagged_sha).unwrap();
        assert!(dest.join("rules/first.rhai").is_file());
        assert!(
            !dest.join("rules/second.rhai").is_file(),
            "v1 predates the second commit"
        );
    }

    #[test]
    fn fetch_after_upstream_advances_lets_sync_resolve_the_new_commit() {
        let upstream = make_upstream("advance");
        let dest = tempdir("advance-dest");
        fs::remove_dir_all(&dest).unwrap();
        clone(&upstream.to_string_lossy(), &dest).unwrap();
        let original = resolve_ref(&dest, None).unwrap();

        fs::write(
            upstream.join("rules/third.rhai"),
            "fn check(cmd, cwd, input) {}",
        )
        .unwrap();
        run_git(&upstream, &["add", "."]);
        run_git(&upstream, &["commit", "-q", "-m", "third"]);

        fetch(&dest).unwrap();
        let advanced = resolve_ref(&dest, None).unwrap();
        assert_ne!(original, advanced);

        let log = log_range(&dest, &original, &advanced);
        assert!(log.contains("third"));
        let diffstat = diffstat_range(&dest, &original, &advanced);
        assert!(diffstat.contains("third.rhai"));
    }

    #[test]
    fn resolve_ref_fails_clearly_for_an_unknown_ref() {
        let upstream = make_upstream("unknown-ref");
        let dest = tempdir("unknown-ref-dest");
        fs::remove_dir_all(&dest).unwrap();
        clone(&upstream.to_string_lossy(), &dest).unwrap();

        assert!(resolve_ref(&dest, Some("does-not-exist")).is_err());
    }
}
