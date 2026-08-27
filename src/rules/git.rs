use super::shell::OPERATORS;
use crate::process::{git_cmd, git_stdout};
use std::path::Path;
use std::process::Stdio;

const GLOBAL_FLAGS_WITH_VALUE: [&str; 6] = [
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--exec-path",
];
const TARGET_SUBCOMMANDS: [&str; 8] = [
    "checkout", "switch", "restore", "push", "branch", "rebase", "commit", "clean",
];

/// One `git` invocation found in a tokenized command line: its subcommand
/// and the args up to the next shell operator.
pub(super) struct GitInvocation {
    pub(super) subcommand: String,
    pub(super) args: Vec<String>,
}

/// Walks every `git` token, skips its global flags to find the subcommand,
/// and collects that invocation's args up to the next shell operator, for
/// the subcommands `git-safety.rhai` and other callers care about.
///
/// The scanning is deliberately loose: it checks every token position
/// rather than only command starts, so `echo git checkout` is treated the
/// same as a real invocation. Erring toward more scrutiny matches the
/// guard's intent.
pub(super) fn find_git_invocations(tokens: &[String]) -> Vec<GitInvocation> {
    let mut result = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if tokens[index] != "git" {
            index += 1;
            continue;
        }
        let mut sub_index = index + 1;
        while sub_index < tokens.len() {
            let t = tokens[sub_index].as_str();
            if GLOBAL_FLAGS_WITH_VALUE.contains(&t) {
                sub_index += 2;
            } else if t.starts_with('-') {
                sub_index += 1;
            } else {
                break;
            }
        }
        index += 1;
        if sub_index >= tokens.len() {
            continue;
        }
        let subcommand = tokens[sub_index].clone();
        if !TARGET_SUBCOMMANDS.contains(&subcommand.as_str()) {
            continue;
        }
        let mut args = Vec::new();
        let mut arg_index = sub_index + 1;
        while arg_index < tokens.len() && !OPERATORS.contains(&tokens[arg_index].as_str()) {
            args.push(tokens[arg_index].clone());
            arg_index += 1;
        }
        result.push(GitInvocation { subcommand, args });
    }
    result
}

/// Already-classified flags for `checkout`/`switch`/`restore` args. See
/// [`parse_args`].
#[derive(Default, Debug, PartialEq, Eq)]
pub(super) struct ParsedArgs {
    pub(super) creating: bool,
    pub(super) staged: bool,
    pub(super) worktree: bool,
    pub(super) dashdash: bool,
    pub(super) target: Option<String>,
    pub(super) pathspecs: Vec<String>,
}

pub(super) fn parse_args(args: &[String]) -> ParsedArgs {
    let mut parsed = ParsedArgs::default();
    let mut after_dashdash = false;
    let mut i = 0;
    while i < args.len() {
        let word = &args[i];
        if after_dashdash {
            parsed.pathspecs.push(word.clone());
            i += 1;
            continue;
        }
        match word.as_str() {
            "--" => {
                parsed.dashdash = true;
                after_dashdash = true;
            }
            "-b" | "-B" | "-c" | "-C" | "--create" | "--orphan" => parsed.creating = true,
            "--staged" | "-S" => parsed.staged = true,
            "--worktree" | "-W" => parsed.worktree = true,
            "--source" | "-s" => i += 1, // takes a value; skip it
            w if w.starts_with('-') => {}
            _ => {
                if parsed.target.is_none() {
                    parsed.target = Some(word.clone());
                }
                parsed.pathspecs.push(word.clone());
            }
        }
        i += 1;
    }
    parsed
}

/// True if `name` is an existing local branch.
pub(super) fn ref_exists_as_branch(cwd: &Path, name: &str) -> bool {
    ref_exists(cwd, &format!("refs/heads/{name}"))
}

fn git_status_ok(cwd: &Path, args: &[&str]) -> bool {
    git_cmd(cwd, args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub(super) fn is_inside_work_tree(cwd: &Path) -> bool {
    git_status_ok(cwd, &["rev-parse", "--is-inside-work-tree"])
}

pub(super) fn ref_exists(cwd: &Path, refname: &str) -> bool {
    git_status_ok(cwd, &["show-ref", "--verify", "--quiet", refname])
}

/// True if there are staged or unstaged changes to tracked files. Untracked
/// files are ignored: they carry over across a checkout or switch anyway.
pub(super) fn tree_is_dirty(cwd: &Path) -> bool {
    !git_stdout(cwd, &["status", "--porcelain", "--untracked-files=no"])
        .trim()
        .is_empty()
}

/// True if the given pathspecs have unstaged changes that a restore or
/// checkout would discard.
pub(super) fn would_discard(cwd: &Path, pathspecs: &[String]) -> bool {
    let mut args = vec![
        "diff".to_string(),
        "--name-only".to_string(),
        "--".to_string(),
    ];
    if pathspecs.is_empty() {
        args.push(".".to_string());
    } else {
        args.extend(pathspecs.iter().cloned());
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    !git_stdout(cwd, &arg_refs).trim().is_empty()
}

/// True if `ancestor` is an ancestor of, or equal to, `descendant`.
pub(super) fn is_ancestor(cwd: &Path, ancestor: &str, descendant: &str) -> bool {
    git_status_ok(cwd, &["merge-base", "--is-ancestor", ancestor, descendant])
}

/// The current branch's configured upstream (e.g. "origin/main"), or `None`
/// if there isn't one.
pub(super) fn upstream_ref(cwd: &Path) -> Option<String> {
    let out = git_stdout(
        cwd,
        &[
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        ],
    );
    let trimmed = out.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// The current branch name, or `None` for a detached HEAD.
pub(super) fn current_branch(cwd: &Path) -> Option<String> {
    let out = git_stdout(cwd, &["rev-parse", "--abbrev-ref", "HEAD"]);
    let trimmed = out.trim();
    if trimmed.is_empty() || trimmed == "HEAD" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Output of a dry-run `git clean` with the given (non-force) args, used to
/// check whether a forced clean would actually remove anything.
pub(super) fn clean_dry_run(cwd: &Path, extra_args: &[String]) -> String {
    let mut args = vec!["clean".to_string(), "-n".to_string()];
    args.extend(extra_args.iter().cloned());
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    git_stdout(cwd, &arg_refs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::shell::tokenize;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command as StdCommand;

    fn init_repo() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cerberus-git-test-{}-{}",
            std::process::id(),
            fastrand()
        ));
        fs::create_dir_all(&dir).unwrap();
        run(&dir, &["init", "-q"]);
        run(&dir, &["config", "user.email", "test@example.com"]);
        run(&dir, &["config", "user.name", "Test"]);
        fs::write(dir.join("file.txt"), "one\n").unwrap();
        run(&dir, &["add", "."]);
        run(&dir, &["commit", "-q", "-m", "initial"]);
        dir
    }

    fn run(dir: &Path, args: &[&str]) {
        let status = StdCommand::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {:?} failed in {:?}", args, dir);
    }

    // subsec_nanos() alone can collide between parallel test threads
    // scheduled within the same nanosecond window; an atomic counter
    // guarantees uniqueness regardless of timing.
    fn fastrand() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos() as u64;
        nanos.wrapping_mul(1_000_003).wrapping_add(n)
    }

    #[test]
    fn tree_is_dirty_false_on_clean_repo() {
        let dir = init_repo();
        assert!(!tree_is_dirty(&dir));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tree_is_dirty_true_with_unstaged_edit() {
        let dir = init_repo();
        fs::write(dir.join("file.txt"), "two\n").unwrap();
        assert!(tree_is_dirty(&dir));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn find_git_invocations_skips_global_flags_to_reach_subcommand() {
        let tokens = tokenize("git -C /some/path --git-dir foo checkout main");
        let found = find_git_invocations(&tokens);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].subcommand, "checkout");
        assert_eq!(found[0].args, vec!["main"]);
    }

    #[test]
    fn find_git_invocations_ignores_non_target_subcommands() {
        let tokens = tokenize("git status");
        assert!(find_git_invocations(&tokens).is_empty());
    }

    #[test]
    fn find_git_invocations_stops_args_at_the_next_operator() {
        let tokens = tokenize("git checkout main && echo done");
        let found = find_git_invocations(&tokens);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].args, vec!["main"]);
    }

    #[test]
    fn find_git_invocations_finds_multiple_in_one_command() {
        let tokens = tokenize("git checkout main && git restore file.txt");
        let found = find_git_invocations(&tokens);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].subcommand, "checkout");
        assert_eq!(found[1].subcommand, "restore");
    }

    #[test]
    fn parse_args_detects_branch_creation_flags() {
        assert!(parse_args(&["-b".to_string(), "new-branch".to_string()]).creating);
        assert!(parse_args(&["--orphan".to_string()]).creating);
        assert!(!parse_args(&["main".to_string()]).creating);
    }

    #[test]
    fn parse_args_source_flag_skips_its_value() {
        let parsed = parse_args(&[
            "--source".to_string(),
            "main".to_string(),
            "file.txt".to_string(),
        ]);
        assert_eq!(parsed.target, Some("file.txt".to_string()));
        assert_eq!(parsed.pathspecs, vec!["file.txt".to_string()]);
    }

    #[test]
    fn parse_args_dashdash_treats_everything_after_as_pathspec() {
        let parsed = parse_args(&["--".to_string(), "-weird-file".to_string()]);
        assert!(parsed.dashdash);
        assert_eq!(parsed.pathspecs, vec!["-weird-file".to_string()]);
        assert_eq!(parsed.target, None);
    }

    #[test]
    fn parse_args_staged_and_worktree_flags() {
        let parsed = parse_args(&["--staged".to_string(), "-W".to_string()]);
        assert!(parsed.staged);
        assert!(parsed.worktree);
    }
}
