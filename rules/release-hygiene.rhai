// Head: judgement — Purpose: governance policy
//
// Blocks `npm publish` / `cargo publish` when the working tree has
// uncommitted changes, so the published artifact always matches a real
// commit you can point back to later.

fn has_token(tokens, word) {
    tokens.contains(word)
}

fn check(cmd, cwd, input) {
    if !cmd.contains("publish") {
        return;
    }
    let tokens = tokenize(cmd);
    let is_publish = (has_token(tokens, "npm") && has_token(tokens, "publish")) ||
        (has_token(tokens, "cargo") && has_token(tokens, "publish"));
    if !is_publish {
        return;
    }
    if !command_exists("git") || !git_is_inside_work_tree(cwd) {
        return;
    }
    if git_tree_dirty(cwd) {
        return "Blocked (RELEASE-001): publishing with uncommitted changes in the working tree. Commit or stash first so the published artifact matches a real commit.";
    }
}
