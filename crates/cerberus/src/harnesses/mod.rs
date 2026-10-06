//! One module per agent harness cerberus can guard, each a
//! [`HarnessInstaller`]. Codex CLI's wire format already matches Claude's
//! byte for byte, so the two share [`settings::install_hooks`]; Cursor's
//! payload differs and has its own translation in [`cursor`].

pub mod claude;
pub mod codex;
pub mod cursor;
pub mod hermes;
pub mod opencode;
pub mod settings;

use crate::domain::Check;
use crate::ports::HarnessInstaller;
use std::fs;
use std::path::Path;

/// Every supported harness, in the order `init` wires them.
pub fn all() -> Vec<Box<dyn HarnessInstaller>> {
    vec![
        Box::new(claude::Claude),
        Box::new(codex::Codex),
        Box::new(cursor::Cursor),
        Box::new(hermes::Hermes),
        Box::new(opencode::Opencode),
    ]
}

/// `doctor`'s check for a harness wired through a hooks file: warns when
/// the guard or health hook is missing from it. Never degrades the guard.
pub(crate) fn hooks_check(id: &'static str, name: &str, file: &Path, expected: bool) -> Check {
    if !expected {
        return Check::ok(None, id, format!("{name}: harness not in use"));
    }
    let wired = |cmd: &str| {
        fs::read_to_string(file)
            .map(|text| text.contains(cmd))
            .unwrap_or(false)
    };
    let missing: Vec<&str> = ["cerberus guard", "cerberus health"]
        .into_iter()
        .filter(|cmd| !wired(cmd))
        .collect();
    if missing.is_empty() {
        Check::ok(None, id, format!("{name}: guard and health hooks wired"))
    } else {
        Check::warn(
            None,
            id,
            format!("{name}: no hook for `{}`", missing.join("`, `")),
        )
        .detail(format!("checked {}", file.display()))
        .fix("cerberus init")
    }
}

/// `doctor`'s check for a harness wired through a plugin file or directory.
pub(crate) fn plugin_check(id: &'static str, name: &str, expected: bool, file: &Path) -> Check {
    if !expected {
        Check::ok(None, id, format!("{name}: harness not in use"))
    } else if file.exists() {
        Check::ok(None, id, format!("{name} installed"))
    } else {
        Check::warn(None, id, format!("{name} missing"))
            .detail(format!("expected {}", file.display()))
            .fix("cerberus init")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Status;

    #[test]
    fn hooks_check_warns_when_unwired_and_passes_when_wired() {
        let dir =
            std::env::temp_dir().join(format!("cerberus-harness-hooks-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("settings.json");

        assert_eq!(hooks_check("h", "x", &file, true).status, Status::Warn);
        assert_eq!(hooks_check("h", "x", &file, false).status, Status::Ok);

        fs::write(
            &file,
            r#"{"command":"cerberus guard"} {"command":"cerberus health"}"#,
        )
        .unwrap();
        assert_eq!(hooks_check("h", "x", &file, true).status, Status::Ok);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn plugin_check_warns_only_when_expected_and_missing() {
        let dir =
            std::env::temp_dir().join(format!("cerberus-harness-plugin-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("plugin.ts");

        assert_eq!(plugin_check("p", "x", false, &file).status, Status::Ok);
        assert_eq!(plugin_check("p", "x", true, &file).status, Status::Warn);
        fs::write(&file, "").unwrap();
        assert_eq!(plugin_check("p", "x", true, &file).status, Status::Ok);
        let _ = fs::remove_dir_all(&dir);
    }
}
