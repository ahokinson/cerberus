/// Tokenizes a shell command line respecting single/double quotes (with
/// backslash escapes inside double quotes) and treating the shell control
/// operators as their own tokens even when not surrounded by whitespace
/// (e.g. "status;git" -> ["status", ";", "git"]), matching zsh's `${(z)}`
/// closely enough for finding invocations and where they end. Shared by any
/// rule that needs to scan a raw command string, not git-specific.
pub(super) fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();

    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                chars.next();
            }
            '\'' => {
                chars.next();
                for c2 in chars.by_ref() {
                    if c2 == '\'' {
                        break;
                    }
                    current.push(c2);
                }
            }
            '"' => {
                chars.next();
                while let Some(c2) = chars.next() {
                    if c2 == '"' {
                        break;
                    }
                    if c2 == '\\'
                        && let Some(c3) = chars.next()
                    {
                        current.push(c3);
                        continue;
                    }
                    current.push(c2);
                }
            }
            ';' | '|' | '&' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                chars.next();
                let mut op = c.to_string();
                if let Some(&next) = chars.peek() {
                    let doubled = (c == '|' && next == '|')
                        || (c == '&' && next == '&')
                        || (c == '|' && next == '&');
                    if doubled {
                        op.push(next);
                        chars.next();
                    }
                }
                tokens.push(op);
            }
            _ => {
                current.push(c);
                chars.next();
            }
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

pub(super) const OPERATORS: [&str; 6] = [";", "|", "||", "&", "&&", "|&"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_splits_on_whitespace() {
        assert_eq!(
            tokenize("git checkout main"),
            vec!["git", "checkout", "main"]
        );
    }

    #[test]
    fn tokenize_respects_single_and_double_quotes() {
        assert_eq!(
            tokenize("git commit -m 'a b c'"),
            vec!["git", "commit", "-m", "a b c"]
        );
        assert_eq!(tokenize(r#"echo "a b" c"#), vec!["echo", "a b", "c"]);
    }

    #[test]
    fn tokenize_handles_double_quote_backslash_escapes() {
        assert_eq!(tokenize(r#""a\"b""#), vec![r#"a"b"#]);
    }

    #[test]
    fn tokenize_splits_operators_even_without_surrounding_whitespace() {
        assert_eq!(tokenize("status;git"), vec!["status", ";", "git"]);
        assert_eq!(tokenize("a&&b"), vec!["a", "&&", "b"]);
        assert_eq!(tokenize("a||b"), vec!["a", "||", "b"]);
        assert_eq!(tokenize("a|&b"), vec!["a", "|&", "b"]);
    }
}
