use std::env;
use std::path::Path;
use std::process::Command;

pub fn command_exists(bin: &str) -> bool {
    let Some(path_var) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path_var).any(|dir| is_executable(&dir.join(bin)))
}

/// Builds `git -C <dir> <args>` — the one shared primitive `rules::git`
/// (read-only introspection of the repo being edited) and `sources::repo`
/// (cloning/mutating a cerberus-owned cache of a different, remote repo)
/// both invoke git through, rather than each constructing the same
/// `Command` independently.
pub fn git_cmd(dir: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir).args(args);
    cmd
}

/// Runs `git_cmd(dir, args)` and returns stdout as a string, empty on any
/// failure (missing repo, bad ref, git not installed) — an empty result is
/// the caller's signal to interpret, not this function's to report.
pub fn git_stdout(dir: &Path, args: &[&str]) -> String {
    git_cmd(dir, args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default()
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}
