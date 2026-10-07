use crate::config::Paths;
use crate::repos::{self, Outcome, Pending};
use crate::sources::ContentCheck;
use std::io::{self, BufRead, IsTerminal, Write};

/// `cerberus trust`: approve the `.cerberus/` of the repo the shell is in,
/// or withdraw the approval if the directory is gone.
///
/// Approving is the review step, so a human has to be there for it: it needs
/// a terminal on both ends, shows the content of everything that changed
/// since the last approval, and asks before recording anything. The agent's
/// shell has no terminal, which is what actually keeps it from approving its
/// own rules.
pub fn run(paths: &Paths) -> i32 {
    if !at_a_terminal() {
        eprintln!(
            "cerberus trust needs a terminal: it shows what it is about to approve and asks. \
             Run it yourself in the repo."
        );
        return 1;
    }
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(e) => {
            eprintln!("couldn't read the current directory: {e}");
            return 1;
        }
    };
    let pending = match repos::stage(paths, &cwd) {
        Ok(pending) => pending,
        Err(e) => {
            eprintln!("couldn't trust this repo: {e}");
            return 1;
        }
    };

    let question = match &pending {
        Pending::Approve(staged) => {
            if staged.changes().is_empty() {
                println!("already approved, nothing changed");
                return 0;
            }
            println!("{}", staged.review());
            for change in staged.changes() {
                println!("  {change}");
            }
            "Approve and enforce this?"
        }
        Pending::Withdraw { root, .. } => {
            println!(
                "{}: no {}/ left. This withdraws its approval.",
                root.display(),
                repos::DIR
            );
            "Withdraw?"
        }
    };
    if !confirm(question) {
        eprintln!("not approved, nothing changed");
        return 1;
    }

    match repos::commit(paths, pending) {
        Ok(Outcome::Approved {
            root,
            installed,
            content_check,
            warnings,
            ..
        }) => {
            println!("{}: approved", root.display());
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

/// No build, debug or release, has a way to claim a terminal it does not have;
/// the tests drive `trust` through a real pseudo-terminal instead.
fn at_a_terminal() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn confirm(question: &str) -> bool {
    print!("{question} [y/N] ");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer).is_ok() && matches!(answer.trim(), "y" | "Y" | "yes")
}
