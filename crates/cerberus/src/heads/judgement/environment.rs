use crate::process::command_exists;
use std::path::Path;
use std::process::Command;

const PROD_HINTS: [&str; 3] = ["prod", "production", "live"];

/// True if `name` looks like a production cluster/workspace name. Shared
/// state-query helper for any rule script that cares (currently
/// `environment-awareness.rhai`).
pub(super) fn looks_like_production(name: &str) -> bool {
    let lower = name.to_lowercase();
    PROD_HINTS.iter().any(|hint| lower.contains(hint))
}

pub(super) fn kube_context() -> Option<String> {
    if !command_exists("kubectl") {
        return None;
    }
    let output = Command::new("kubectl")
        .args(["config", "current-context"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let name = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

pub(super) fn terraform_workspace(cwd: &Path) -> Option<String> {
    if !command_exists("terraform") {
        return None;
    }
    let output = Command::new("terraform")
        .current_dir(cwd)
        .args(["workspace", "show"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let name = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_production_matches_common_names() {
        assert!(looks_like_production("prod"));
        assert!(looks_like_production("production"));
        assert!(looks_like_production("my-prod-cluster"));
        assert!(looks_like_production("Production-East"));
        assert!(looks_like_production("live"));
        assert!(!looks_like_production("staging"));
        assert!(!looks_like_production("dev"));
    }
}
