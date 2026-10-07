use crate::config::Paths;
use crate::repos::{self, Outcome};
use crate::sources::ContentCheck;

/// `cerberus trust`: approve the `.cerberus/` of the repo the shell is in,
/// or withdraw the approval if the directory is gone. Prints what changed
/// since the last approval first, since reading that is the review.
pub fn run(paths: &Paths) -> i32 {
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(e) => {
            eprintln!("couldn't read the current directory: {e}");
            return 1;
        }
    };
    match repos::trust(paths, &cwd) {
        Ok(Outcome::Approved {
            root,
            installed,
            changes,
            content_check,
            warnings,
        }) => {
            if changes.is_empty() {
                println!("{}: already approved, nothing changed", root.display());
            } else {
                println!("{}: approved", root.display());
                for change in &changes {
                    println!("  {change}");
                }
            }
            println!("  enforcing {installed}");
            if content_check == ContentCheck::Skipped {
                eprintln!(
                    "  warning: opa and/or tirith not on PATH, so some of this content was \
                     approved unvalidated"
                );
            }
            for warning in &warnings {
                eprintln!("  warning: {warning}");
            }
            0
        }
        Ok(Outcome::Withdrawn { root }) => {
            println!(
                "{}: no {}/ left, approval withdrawn",
                root.display(),
                repos::DIR
            );
            0
        }
        Err(e) => {
            eprintln!("couldn't trust this repo: {e}");
            1
        }
    }
}
