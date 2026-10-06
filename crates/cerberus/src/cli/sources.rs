use super::args::SourceCommand;
use crate::config::Paths;
use crate::sources;

/// Surfaces the one `ContentCheck` outcome that isn't self-evident from the
/// success message alone: content installed without the validating binary
/// on hand to check it. `NotApplicable`/`Passed` need no comment.
fn warn_if_content_unvalidated(check: sources::ContentCheck) {
    if check == sources::ContentCheck::Skipped {
        eprintln!(
            "  warning: opa and/or tirith not on PATH, so some of this source's content was \
             installed unvalidated"
        );
    }
}

/// Prints a source's non-fatal findings. These go to stderr and aren't
/// abbreviated: the case they exist for is a tirith rule that installs and
/// validates but can never fire, which looks like success everywhere else.
fn print_warnings(warnings: &[String]) {
    for warning in warnings {
        eprintln!("  warning: {warning}");
    }
}

pub fn run(paths: &Paths, action: SourceCommand) -> i32 {
    match action {
        SourceCommand::Add {
            spec,
            git,
            r#ref,
            name,
        } => {
            let parsed = match sources::spec::parse(&spec, git.as_deref(), name.as_deref()) {
                Ok(parsed) => parsed,
                Err(e) => {
                    eprintln!("couldn't add source: {e}");
                    return 1;
                }
            };
            match sources::add(paths, &parsed.name, &parsed.git, r#ref.as_deref()) {
                Ok(sources::AddOutcome {
                    source,
                    content_check,
                    installed,
                    warnings,
                }) => {
                    println!(
                        "source '{}' added: {}{}",
                        source.name,
                        source.git,
                        source
                            .pinned
                            .as_deref()
                            .map(|p| format!(" @ {p}"))
                            .unwrap_or_default()
                    );
                    println!("  installed {installed}");
                    warn_if_content_unvalidated(content_check);
                    print_warnings(&warnings);
                    0
                }
                Err(e) => {
                    eprintln!("couldn't add source '{}': {e}", parsed.name);
                    1
                }
            }
        }
        SourceCommand::Remove { name } => match sources::remove(paths, &name) {
            Ok(true) => {
                println!("source '{name}' removed");
                0
            }
            Ok(false) => {
                println!("no source named '{name}'");
                1
            }
            Err(e) => {
                eprintln!("couldn't remove source '{name}': {e}");
                1
            }
        },
        SourceCommand::List => {
            let configured = sources::list(paths);
            if configured.is_empty() {
                println!("no policy sources configured");
            }
            for s in configured {
                println!(
                    "{}  {}{}{}",
                    s.name,
                    s.git,
                    s.git_ref
                        .as_deref()
                        .map(|r| format!(" @ {r}"))
                        .unwrap_or_default(),
                    s.pinned
                        .as_deref()
                        .map(|p| format!(" (pinned {p})"))
                        .unwrap_or_default(),
                );
            }
            0
        }
        SourceCommand::Sync { name, yes } => {
            let results = sources::sync(paths, name.as_deref(), yes);
            if results.is_empty() {
                eprintln!("no matching policy source configured");
                return 1;
            }
            let mut exit_code = 0;
            for r in results {
                match r.status {
                    sources::SyncStatus::UpToDate => println!("{}: up to date", r.name),
                    sources::SyncStatus::Applied {
                        from,
                        to,
                        content_check,
                        installed,
                        warnings,
                    } => {
                        println!(
                            "{}: updated {} -> {to}",
                            r.name,
                            from.as_deref().unwrap_or("(none)")
                        );
                        println!("  installed {installed}");
                        warn_if_content_unvalidated(content_check);
                        print_warnings(&warnings);
                    }
                    sources::SyncStatus::PendingConfirmation {
                        from,
                        to,
                        log,
                        diffstat,
                    } => {
                        exit_code = 1;
                        println!(
                            "{}: update available {} -> {to}",
                            r.name,
                            from.as_deref().unwrap_or("(none)")
                        );
                        if !log.is_empty() {
                            println!("{log}");
                        }
                        if !diffstat.is_empty() {
                            println!("{diffstat}");
                        }
                        println!("  (run `cerberus source sync {} --yes` to apply)", r.name);
                    }
                    sources::SyncStatus::Failed(e) => {
                        exit_code = 1;
                        eprintln!("{}: {e}", r.name);
                    }
                }
            }
            exit_code
        }
    }
}
