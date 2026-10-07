//! Repo-local cerberus content: a `.cerberus/` directory at a repo's root
//! that adds to what the three heads enforce there.
//!
//! ```text
//! .cerberus/
//!   judgements/*.rhai     flat      judgement head
//!   policies/**/*.rego    may nest  policy head
//!   risks/*.yaml          flat      risk head
//! ```
//!
//! cerberus owns what it enforces, so a repo's own `.tirith/policy.yaml` and
//! `.cupcake/` are never read. This directory is the one door a repo gets,
//! and it is a locked one: a cloned repo is untrusted input that would run on
//! every guarded tool call (a Rhai script executes code), so `.cerberus/` does
//! nothing until a human runs `cerberus trust` in that repo.
//!
//! Trust is a **snapshot**, not a pin. `trust` validates the directory, then
//! copies it into cerberus's own data home (`Paths::repo_snapshot_dir`) and
//! records the repo's root in `config.toml`; the heads enforce that copy and
//! never read the live directory. So what runs is exactly what was approved,
//! with no window between a check and a use, and an agent that edits or
//! deletes `.cerberus/` changes nothing about what is enforced. `doctor`
//! reports the drift, and running `trust` again approves it.
//!
//! A repo's layer only ever adds. Its tirith fragments go through the same
//! composition as a source's, which refuses to let a layer loosen the base
//! policy, and the judgement and policy heads are deny-only stacks.

use crate::config::{self, Paths, RepoConfig};
use crate::heads::{policy, risk};
use crate::sources::{self, ContentCheck, Installed};
use std::collections::BTreeMap;
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};

/// The directory at a repo's root that carries its cerberus content.
pub const DIR: &str = ".cerberus";

/// A repo approved with `cerberus trust`, as the heads need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    pub id: String,
}

/// The nearest ancestor of `cwd` (itself included) that holds a `.git`,
/// canonicalized so the same repo reached through a symlink or a `..` is
/// one repo. Stops there: a `.cerberus/` in a parent of the repo is not the
/// repo's. `None` outside a git repository.
pub fn find_root(cwd: &Path) -> Option<PathBuf> {
    let start = cwd.canonicalize().ok()?;
    start
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .map(Path::to_path_buf)
}

fn key(root: &Path) -> String {
    root.to_string_lossy().into_owned()
}

fn entry(paths: &Paths, root: &Path) -> Option<RepoConfig> {
    let key = key(root);
    config::repos(paths).into_iter().find(|r| r.path == key)
}

/// The approval covering `cwd`, if the repo it sits in has one.
pub fn approved(paths: &Paths, cwd: &Path) -> Option<Approved> {
    let root = find_root(cwd)?;
    entry(paths, &root).map(|r| Approved { id: r.id })
}

/// A directory name for a repo's snapshot, from its root. It only has to be
/// unique and filesystem-safe, not secret: it is recorded in `config.toml`
/// when approved, so it never needs to be recomputed.
fn new_id(root: &Path) -> String {
    let mut hasher = DefaultHasher::new();
    root.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// What `trust` did.
#[derive(Debug)]
pub enum Outcome {
    /// The repo's `.cerberus/` is approved and now enforcing.
    Approved {
        root: PathBuf,
        installed: Installed,
        /// Files added, changed or removed against the last approval; every
        /// file is "added" the first time.
        changes: Vec<String>,
        content_check: ContentCheck,
        warnings: Vec<String>,
    },
    /// There was no `.cerberus/` left, so the standing approval was withdrawn.
    Withdrawn { root: PathBuf },
}

/// Makes the repo that `cwd` is in match its `.cerberus/`: approves what is
/// there, or, if the directory is gone, withdraws an earlier approval. One
/// command for both, so there is nothing to remember beyond `trust`.
///
/// Validation is the sources' own: `opa check` over the Rego, and the
/// composed tirith policy through `tirith rule validate`, with a failure
/// aborting before anything is recorded. Layout is held to the same rules too
/// (`judgements/` and `risks/` flat), so nothing installs that would silently
/// never run.
pub fn trust(paths: &Paths, cwd: &Path) -> Result<Outcome, String> {
    let root = find_root(cwd).ok_or("not inside a git repository")?;
    let existing = entry(paths, &root);
    let live = root.join(DIR);

    let live_is_dir = live.symlink_metadata().is_ok_and(|m| m.is_dir());
    if !live_is_dir {
        return match existing {
            Some(repo) => {
                withdraw(paths, &repo)?;
                Ok(Outcome::Withdrawn { root })
            }
            None => Err(format!("no {DIR}/ directory in {}", root.display())),
        };
    }

    let judgements = live.join("judgements");
    let risks = live.join("risks");
    sources::reject_nested(&judgements, "rhai", "judgements").map_err(|e| e.to_string())?;
    sources::reject_nested(&risks, "yaml", "risks").map_err(|e| e.to_string())?;

    let id = existing
        .as_ref()
        .map_or_else(|| new_id(&root), |r| r.id.clone());
    let rego = sources::check_rego(&live.join("policies"))
        .map_err(|e| format!("{DIR}/policies failed opa validation: {e}"))?;
    let (tirith, warnings) = sources::check_tirith_fragments(
        paths,
        risk::compose::REPO_NAMESPACE,
        &risks,
        &format!("{DIR}/risks"),
        &paths.repo_snapshot_dir(&id).with_extension("validate"),
    )
    .map_err(|e| format!("{DIR}/risks failed tirith validation: {e}"))?;

    let changes = diff(&paths.repo_snapshot_dir(&id), &live);
    let snapshot = |from: &str, to: PathBuf, ext: &str| {
        sources::install_matching_ext(&live.join(from), &to, ext)
            .map_err(|e| format!("couldn't snapshot {DIR}/{from}: {e}"))
    };
    let installed = Installed {
        rules: snapshot("judgements", paths.repo_judgements_dir(&id), "rhai")?,
        policies: snapshot("policies", paths.repo_policies_dir(&id), "rego")?,
        tirith: snapshot("risks", paths.repo_risks_dir(&id), "yaml")?,
    };

    config::upsert_repo(
        &paths.config_file(),
        RepoConfig {
            path: key(&root),
            id: id.clone(),
        },
    )
    .map_err(|e| format!("couldn't write config.toml: {e}"))?;
    rebuild(paths, &id);

    Ok(Outcome::Approved {
        root,
        installed,
        changes,
        content_check: rego.merge(tirith),
        warnings,
    })
}

/// Drops an approval and everything derived from it.
fn withdraw(paths: &Paths, repo: &RepoConfig) -> Result<(), String> {
    config::remove_repo(&paths.config_file(), &repo.path)
        .map_err(|e| format!("couldn't update config.toml: {e}"))?;
    for dir in [
        paths.repo_snapshot_dir(&repo.id),
        paths.tirith_repo_overlay_root(&repo.id),
        paths.cupcake_repo_project_root(&repo.id),
    ] {
        let _ = fs::remove_dir_all(dir);
    }
    Ok(())
}

/// Rebuilds what is derived from a repo's snapshot: its tirith overlay and
/// its cupcake store, or removes them when the snapshot ships no `risks/` or
/// `policies/`. Best-effort, like the overlay refresh a source does: by now
/// the approval is recorded, and both are rebuilt again by `init` and by
/// `source sync`.
fn rebuild(paths: &Paths, id: &str) {
    let overlay = paths.tirith_repo_overlay_root(id);
    if risk::has_risks(paths, id) {
        let _ = risk::write_repo_overlay(paths, id);
    } else {
        let _ = fs::remove_dir_all(overlay);
    }
    if sources::contains_ext_recursive(&paths.repo_policies_dir(id), "rego") {
        let _ = policy::write_repo_project(paths, id);
    } else {
        let _ = fs::remove_dir_all(paths.cupcake_repo_project_root(id));
    }
}

/// Rebuilds every approved repo's derived stores, for the moments a layer
/// beneath them changed: `init` refreshing cerberus's own policies, or a
/// source being added, synced or removed.
pub fn rebuild_all(paths: &Paths) {
    for repo in config::repos(paths) {
        rebuild(paths, &repo.id);
    }
}

/// Where a repo's `.cerberus/` stands, for `doctor`.
#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    /// Not in a git repository, or the repo has no `.cerberus/` and no
    /// approval: nothing to say.
    Nothing,
    /// A `.cerberus/` exists that nobody has approved, so it enforces nothing.
    Unapproved { root: PathBuf },
    /// Approved, and the live directory matches what was approved.
    Current { root: PathBuf },
    /// Approved, but the live directory has drifted. The approved snapshot is
    /// still what enforces.
    Drifted { root: PathBuf, changes: Vec<String> },
}

pub fn status(paths: &Paths, cwd: &Path) -> Status {
    let Some(root) = find_root(cwd) else {
        return Status::Nothing;
    };
    let live = root.join(DIR);
    match (entry(paths, &root), live.is_dir()) {
        (None, false) => Status::Nothing,
        (None, true) => Status::Unapproved { root },
        (Some(repo), _) => {
            let changes = diff(&paths.repo_snapshot_dir(&repo.id), &live);
            if changes.is_empty() {
                Status::Current { root }
            } else {
                Status::Drifted { root, changes }
            }
        }
    }
}

/// A repo's own tirith or cupcake configuration that cerberus deliberately
/// does not read, so no one assumes it is enforcing.
pub fn ignored_native(cwd: &Path) -> Vec<&'static str> {
    let Some(root) = find_root(cwd) else {
        return Vec::new();
    };
    [
        (".tirith/policy.yaml", ".tirith/policy.yaml"),
        (".cupcake", ".cupcake/"),
    ]
    .into_iter()
    .filter(|(probe, _)| root.join(probe).exists())
    .map(|(_, shown)| shown)
    .collect()
}

/// The files cerberus reads from a `.cerberus/`-shaped directory, keyed by
/// path relative to it: only the three subdirectories, only each one's own
/// extension, and never through a symlink.
fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    for (sub, ext) in [
        ("judgements", "rhai"),
        ("policies", "rego"),
        ("risks", "yaml"),
    ] {
        collect(&dir.join(sub), sub, ext, &mut files);
    }
    files
}

fn collect(dir: &Path, rel: &str, ext: &str, files: &mut BTreeMap<String, Vec<u8>>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = format!("{rel}/{name}");
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            collect(&entry.path(), &rel, ext, files);
        } else if entry.path().extension().and_then(|e| e.to_str()) == Some(ext)
            && let Ok(bytes) = fs::read(entry.path())
        {
            files.insert(rel, bytes);
        }
    }
}

/// What differs between an approved snapshot and a live `.cerberus/`, as
/// `added`/`changed`/`removed` lines, sorted by path.
fn diff(snapshot: &Path, live: &Path) -> Vec<String> {
    let before = tree(snapshot);
    let after = tree(live);
    let mut lines = Vec::new();
    for (path, bytes) in &after {
        match before.get(path) {
            None => lines.push(format!("added {path}")),
            Some(old) if old != bytes => lines.push(format!("changed {path}")),
            Some(_) => {}
        }
    }
    for path in before.keys().filter(|p| !after.contains_key(*p)) {
        lines.push(format!("removed {path}"));
    }
    lines.sort_by(|a, b| {
        a.split_once(' ')
            .map(|x| x.1)
            .cmp(&b.split_once(' ').map(|x| x.1))
    });
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> (Paths, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("cerberus-repos-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let repo = root.join("work/app");
        fs::create_dir_all(repo.join(".git")).unwrap();
        let paths = Paths {
            state_home: root.join("state"),
            data_home: root.join("data"),
            config_home: root.join("config"),
            cache_home: root.join("cache"),
            home: root.join("home"),
        };
        (paths, repo.canonicalize().unwrap())
    }

    fn write(repo: &Path, rel: &str, body: &str) {
        let file = repo.join(DIR).join(rel);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, body).unwrap();
    }

    const DENY: &str = "fn check(cmd, cwd, input) { return \"denied by repo\"; }";
    const RISK: &str = "custom_rules:\n  - id: no-zzz\n    context: [exec]\n    pattern: 'zzz'\n    severity: HIGH\n    action: block\n    title: no zzz\n";

    #[test]
    fn find_root_stops_at_the_nearest_git_directory() {
        let (_, repo) = scratch("root");
        let nested = repo.join("src/deep");
        fs::create_dir_all(&nested).unwrap();
        assert_eq!(find_root(&nested), Some(repo.clone()));
        assert_eq!(find_root(&repo), Some(repo.clone()));
        // A repo inside a repo is its own root, not its parent's.
        fs::create_dir_all(nested.join(".git")).unwrap();
        assert_eq!(find_root(&nested), Some(nested.canonicalize().unwrap()));
        assert_eq!(find_root(&repo.join("missing")), None);
    }

    #[test]
    fn find_root_is_none_outside_a_git_repository() {
        let dir = std::env::temp_dir().join(format!("cerberus-repos-nogit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // The scratch dir sits under the system temp dir, which is not inside
        // a repository on any machine this runs on.
        if dir.ancestors().all(|a| !a.join(".git").exists()) {
            assert_eq!(find_root(&dir), None);
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_cerberus_directory_enforces_nothing_until_trusted() {
        let (paths, repo) = scratch("untrusted");
        write(&repo, "judgements/deny.rhai", DENY);
        assert_eq!(approved(&paths, &repo), None);
        assert_eq!(status(&paths, &repo), Status::Unapproved { root: repo });
    }

    #[test]
    fn trust_snapshots_the_directory_and_records_the_repo() {
        let (paths, repo) = scratch("trust");
        write(&repo, "judgements/deny.rhai", DENY);
        write(&repo, "policies/cloud/p.rego", "package x\n");
        write(&repo, "risks/r.yaml", RISK);
        write(&repo, "notes.txt", "ignored: not one of the three");
        // What `init` leaves behind, which a repo's project is copied from.
        let stub = paths.cupcake_policy_dir();
        fs::create_dir_all(stub.join("policies/claude")).unwrap();
        fs::write(stub.join("rulebook.yml"), "").unwrap();
        fs::write(
            stub.join("policies/claude/example.rego"),
            "package example\n",
        )
        .unwrap();

        let Outcome::Approved {
            installed, changes, ..
        } = trust(&paths, &repo.join("src"))
            .or_else(|_| trust(&paths, &repo))
            .unwrap()
        else {
            panic!("expected an approval");
        };
        assert_eq!(
            installed,
            Installed {
                rules: 1,
                policies: 1,
                tirith: 1
            }
        );
        assert_eq!(
            changes,
            vec![
                "added judgements/deny.rhai",
                "added policies/cloud/p.rego",
                "added risks/r.yaml"
            ]
        );

        let id = approved(&paths, &repo).expect("approved").id;
        assert!(paths.repo_judgements_dir(&id).join("deny.rhai").is_file());
        assert!(paths.repo_policies_dir(&id).join("cloud/p.rego").is_file());
        assert!(paths.repo_risks_dir(&id).join("r.yaml").is_file());
        assert!(
            paths
                .tirith_repo_overlay_root(&id)
                .join(".tirith/policy.yaml")
                .is_file(),
            "a repo that ships risks gets an overlay of its own"
        );
        let project = paths.cupcake_repo_policy_dir(&id);
        assert!(
            project.join("policies/claude/repo/cloud/p.rego").is_file(),
            "and one that ships policies gets a cupcake project of its own"
        );
        assert!(
            project.join("rulebook.yml").is_file(),
            "built on the stub's scaffold"
        );
        assert_eq!(status(&paths, &repo), Status::Current { root: repo });
    }

    #[test]
    fn what_enforces_is_the_approved_copy_not_the_live_directory() {
        let (paths, repo) = scratch("drift");
        write(&repo, "judgements/deny.rhai", DENY);
        trust(&paths, &repo).unwrap();
        let id = approved(&paths, &repo).unwrap().id;

        write(&repo, "judgements/deny.rhai", "fn check(c, d, i) {}");
        write(&repo, "judgements/extra.rhai", DENY);
        fs::remove_dir_all(repo.join(DIR).join("risks")).ok();

        assert_eq!(
            fs::read_to_string(paths.repo_judgements_dir(&id).join("deny.rhai")).unwrap(),
            DENY,
            "an edit after approval must not reach the snapshot"
        );
        assert_eq!(
            status(&paths, &repo),
            Status::Drifted {
                root: repo.clone(),
                changes: vec![
                    "changed judgements/deny.rhai".into(),
                    "added judgements/extra.rhai".into()
                ]
            }
        );

        // Approving again takes the new content, and the id stays put.
        trust(&paths, &repo).unwrap();
        assert_eq!(approved(&paths, &repo).unwrap().id, id);
        assert!(paths.repo_judgements_dir(&id).join("extra.rhai").is_file());
        assert_eq!(status(&paths, &repo), Status::Current { root: repo });
    }

    #[test]
    fn deleting_the_directory_then_trusting_withdraws_the_approval() {
        let (paths, repo) = scratch("withdraw");
        write(&repo, "risks/r.yaml", RISK);
        trust(&paths, &repo).unwrap();
        let id = approved(&paths, &repo).unwrap().id;

        fs::remove_dir_all(repo.join(DIR)).unwrap();
        assert_eq!(
            status(&paths, &repo),
            Status::Drifted {
                root: repo.clone(),
                changes: vec!["removed risks/r.yaml".into()]
            },
            "the snapshot keeps enforcing until a human says otherwise"
        );
        assert!(approved(&paths, &repo).is_some());

        assert!(matches!(
            trust(&paths, &repo).unwrap(),
            Outcome::Withdrawn { .. }
        ));
        assert_eq!(approved(&paths, &repo), None);
        assert!(!paths.repo_snapshot_dir(&id).exists());
        assert!(!paths.tirith_repo_overlay_root(&id).exists());
        assert_eq!(status(&paths, &repo), Status::Nothing);
    }

    #[test]
    fn trust_refuses_what_cannot_work() {
        let (paths, repo) = scratch("refuse");
        assert!(trust(&paths, &repo).unwrap_err().contains("no .cerberus/"));

        write(&repo, "judgements/nested/deep.rhai", DENY);
        let err = trust(&paths, &repo).unwrap_err();
        assert!(err.contains("must be flat"), "{err}");
        assert_eq!(config::repos(&paths), vec![], "nothing may be recorded");

        let outside =
            std::env::temp_dir().join(format!("cerberus-repos-out-{}", std::process::id()));
        fs::create_dir_all(&outside).unwrap();
        if outside.ancestors().all(|a| !a.join(".git").exists()) {
            assert_eq!(
                trust(&paths, &outside).unwrap_err(),
                "not inside a git repository"
            );
        }
        fs::remove_dir_all(&outside).ok();
    }

    #[test]
    fn a_repo_without_risks_or_policies_gets_no_derived_stores() {
        let (paths, repo) = scratch("judgements-only");
        write(&repo, "judgements/deny.rhai", DENY);
        trust(&paths, &repo).unwrap();
        let id = approved(&paths, &repo).unwrap().id;
        assert!(!paths.tirith_repo_overlay_root(&id).exists());
        assert!(!paths.cupcake_repo_project_root(&id).exists());
    }

    #[test]
    fn rebuild_all_refreshes_every_approved_repo() {
        let (paths, repo) = scratch("rebuild");
        write(&repo, "risks/r.yaml", RISK);
        trust(&paths, &repo).unwrap();
        let id = approved(&paths, &repo).unwrap().id;
        let overlay = paths
            .tirith_repo_overlay_root(&id)
            .join(".tirith/policy.yaml");
        fs::remove_file(&overlay).unwrap();
        rebuild_all(&paths);
        assert!(overlay.is_file());
    }

    #[test]
    fn a_repos_own_tirith_and_cupcake_files_are_named_as_ignored() {
        let (_, repo) = scratch("ignored");
        assert!(ignored_native(&repo).is_empty());
        fs::create_dir_all(repo.join(".tirith")).unwrap();
        fs::write(repo.join(".tirith/policy.yaml"), "paranoia: 1\n").unwrap();
        fs::create_dir_all(repo.join(".cupcake")).unwrap();
        assert_eq!(
            ignored_native(&repo),
            vec![".tirith/policy.yaml", ".cupcake/"]
        );
    }
}
