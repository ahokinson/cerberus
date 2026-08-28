//! Turning what someone types into a git URL and a source name.
//!
//! The point of a source is that pointing cerberus at a repo of rules should
//! be easier than wiring the same content into tirith and cupcake by hand.
//! `cerberus source add <name> <full-git-url>` was not obviously easier, so
//! this accepts the form people actually have in front of them — the
//! `owner/repo` slug off a GitHub page — and derives everything else.
//!
//! The two-argument form still works unchanged; nothing already written down
//! in a README or a team runbook breaks.

/// A parsed `source add` target.
#[derive(Debug, PartialEq, Eq)]
pub struct Spec {
    pub name: String,
    pub git: String,
}

/// Prefixes that mean "this is already a URL, use it verbatim". Anything
/// else containing exactly one `/` and no whitespace is treated as a GitHub
/// `owner/repo` slug.
const URL_PREFIXES: &[&str] = &[
    "https://",
    "http://",
    "ssh://",
    "git://",
    "file://",
    "git+ssh://",
];

/// Explicit shorthand prefixes for GitHub, for when `owner/repo` would be
/// ambiguous with a relative path.
const GITHUB_PREFIXES: &[&str] = &["gh:", "github:"];

/// Expands `spec` into a git URL, or returns it unchanged when it already is
/// one. Recognizes, in order: an explicit `gh:`/`github:` prefix, a real URL
/// scheme, an scp-style `git@host:path`, an absolute path, and finally a
/// bare `owner/repo` GitHub slug.
pub fn expand_url(spec: &str) -> Result<String, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("expected a git URL or an owner/repo slug".to_string());
    }

    for prefix in GITHUB_PREFIXES {
        if let Some(slug) = spec.strip_prefix(prefix) {
            return github_url(slug);
        }
    }
    if URL_PREFIXES.iter().any(|p| spec.starts_with(p)) {
        return Ok(spec.to_string());
    }
    // scp-style (`git@github.com:owner/repo.git`), which has no scheme but
    // is unambiguous: a user@host before the first colon.
    if spec.contains('@') && spec.contains(':') {
        return Ok(spec.to_string());
    }
    if spec.starts_with('/') || spec.starts_with('.') || spec.starts_with('~') {
        return Ok(spec.to_string());
    }
    github_url(spec)
}

fn github_url(slug: &str) -> Result<String, String> {
    let slug = slug.trim_end_matches('/').trim_end_matches(".git");
    let parts: Vec<&str> = slug.split('/').collect();
    if parts.len() != 2 || parts.iter().any(|p| p.is_empty()) {
        return Err(format!(
            "'{slug}' isn't an owner/repo slug or a git URL (try \
             https://github.com/owner/repo.git)"
        ));
    }
    Ok(format!("https://github.com/{}/{}.git", parts[0], parts[1]))
}

/// The source name derived from a git URL: the repository's basename,
/// lowercased, with `.git` and any character `config::valid_source_name`
/// rejects folded to `-`. This is untrusted input on its way to a path join
/// (`Paths::source_rules_dir` and friends), so the caller still validates
/// the result — this only makes a *reasonable* name, it doesn't get to
/// decide what's *safe*.
pub fn infer_name(git: &str) -> Result<String, String> {
    let trimmed = git.trim_end_matches('/');
    let basename = trimmed
        .rsplit(['/', ':'])
        .find(|s| !s.is_empty())
        .unwrap_or(trimmed)
        .trim_end_matches(".git");

    let name: String = basename
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let name = name.trim_matches('-').to_string();

    if name.is_empty() {
        return Err(format!(
            "couldn't work out a source name from '{git}' — pass one with --name"
        ));
    }
    Ok(name)
}

/// Resolves the CLI's `add` arguments into a [`Spec`].
///
/// `first`/`second` are positional: with both present it's the original
/// `add <name> <git-url>` form. With only `first` it's the shorthand form,
/// and the name comes from `--name` or is inferred from the URL.
pub fn parse(
    first: &str,
    second: Option<&str>,
    name_override: Option<&str>,
) -> Result<Spec, String> {
    match second {
        // `add <name> <spec>` — the name is given, and the URL still gets
        // expanded, so `cerberus source add team owner/repo` works too.
        Some(git) => Ok(Spec {
            name: name_override.unwrap_or(first).to_string(),
            git: expand_url(git)?,
        }),
        None => {
            let git = expand_url(first)?;
            let name = match name_override {
                Some(n) => n.to_string(),
                None => infer_name(&git)?,
            };
            Ok(Spec { name, git })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::valid_source_name;

    #[test]
    fn expands_a_bare_github_slug() {
        assert_eq!(
            expand_url("ahokinson/cerberus-rules").unwrap(),
            "https://github.com/ahokinson/cerberus-rules.git"
        );
    }

    #[test]
    fn expands_the_explicit_github_prefixes() {
        for spec in ["gh:owner/repo", "github:owner/repo"] {
            assert_eq!(
                expand_url(spec).unwrap(),
                "https://github.com/owner/repo.git",
                "{spec}"
            );
        }
    }

    #[test]
    fn tolerates_a_slug_that_already_carries_dot_git_or_a_trailing_slash() {
        for spec in ["owner/repo.git", "owner/repo/"] {
            assert_eq!(
                expand_url(spec).unwrap(),
                "https://github.com/owner/repo.git",
                "{spec}"
            );
        }
    }

    /// A real URL must survive untouched — expanding one would silently
    /// retarget a source at a different host.
    #[test]
    fn leaves_real_urls_alone() {
        for url in [
            "https://github.com/owner/repo.git",
            "https://gitlab.example.com/team/policies.git",
            "ssh://git@example.com/team/policies.git",
            "file:///tmp/rulepack",
            "git@github.com:owner/repo.git",
            "/srv/git/policies",
        ] {
            assert_eq!(expand_url(url).unwrap(), url, "{url}");
        }
    }

    #[test]
    fn rejects_something_that_is_neither_a_slug_nor_a_url() {
        for spec in ["", "not a repo", "owner/repo/extra", "owner/"] {
            assert!(
                expand_url(spec).is_err(),
                "expected {spec:?} to be rejected"
            );
        }
    }

    #[test]
    fn infers_a_name_from_every_url_shape() {
        for (url, expected) in [
            (
                "https://github.com/ahokinson/cerberus-rules.git",
                "cerberus-rules",
            ),
            ("git@github.com:owner/Repo.git", "repo"),
            ("ssh://git@example.com/team/policies.git", "policies"),
            ("file:///tmp/rulepack", "rulepack"),
            ("https://example.com/team/My.Policies.git", "my-policies"),
        ] {
            assert_eq!(infer_name(url).unwrap(), expected, "{url}");
        }
    }

    /// Whatever the inference produces has to be usable as a directory name
    /// inside a security tool, or `add` would fail after the clone.
    #[test]
    fn an_inferred_name_always_passes_source_name_validation() {
        for url in [
            "https://github.com/Owner/Some.Weird--Name.git",
            "git@github.com:owner/UPPER.git",
            "file:///tmp/rulepack",
        ] {
            let name = infer_name(url).unwrap();
            assert!(valid_source_name(&name), "{url} inferred {name:?}");
        }
    }

    #[test]
    fn parse_handles_the_original_two_argument_form() {
        assert_eq!(
            parse("team", Some("git@example.com:org/repo.git"), None).unwrap(),
            Spec {
                name: "team".into(),
                git: "git@example.com:org/repo.git".into(),
            }
        );
    }

    #[test]
    fn parse_handles_the_one_argument_shorthand() {
        assert_eq!(
            parse("ahokinson/cerberus-rules", None, None).unwrap(),
            Spec {
                name: "cerberus-rules".into(),
                git: "https://github.com/ahokinson/cerberus-rules.git".into(),
            }
        );
    }

    #[test]
    fn name_override_wins_in_both_forms() {
        assert_eq!(
            parse("owner/repo", None, Some("team")).unwrap().name,
            "team"
        );
        assert_eq!(
            parse("ignored", Some("owner/repo"), Some("team"))
                .unwrap()
                .name,
            "team"
        );
    }
}
