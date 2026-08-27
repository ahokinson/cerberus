// Head: judgement — Purpose: general risk avoidance
//
// Guards against irreversible loss of work: branch switches or discards
// with uncommitted changes (CONTEXT-001/002), force-pushes that would
// discard remote commits, force-deleting unmerged branches, rewriting
// already-pushed history (rebase/amend), and `git clean -f` actually
// removing files.
//
// All the fiddly parsing (tokenizing, walking git's global flags to find
// the subcommand, classifying checkout/switch/restore flags) happens in
// Rust and is exposed here already-structured via git_invocations() and
// git_parse_checkout_args(). See CONTRIBUTING.md for the full native
// function API. This script only does the situational judgement.

fn has_trigger_word(cmd) {
    for word in ["checkout", "switch", "restore", "push", "branch", "rebase", "commit", "clean"] {
        if cmd.contains(word) {
            return true;
        }
    }
    false
}

fn is_deny(result) {
    type_of(result) == "string"
}

// ─── checkout / switch / restore (original CONTEXT-001/002 checks) ─────────

fn analyze_switch(cwd, args) {
    let parsed = git_parse_checkout_args(args);
    if parsed.creating {
        return;
    }
    if parsed.target == "" {
        return;
    }
    if git_tree_dirty(cwd) {
        return "Blocked (CONTEXT-001): switching branches with uncommitted changes to tracked files. Commit or `git stash` first, then switch.";
    }
}

fn analyze_checkout(cwd, args) {
    let parsed = git_parse_checkout_args(args);
    if parsed.creating {
        return;
    }
    let is_branch_switch = !parsed.dashdash && parsed.target != "" &&
        (parsed.target == "-" || git_ref_exists_as_branch(cwd, parsed.target));
    if is_branch_switch {
        if git_tree_dirty(cwd) {
            return "Blocked (CONTEXT-001): switching branches with uncommitted changes to tracked files. Commit or `git stash` first, then switch.";
        }
        return;
    }
    if git_would_discard(cwd, parsed.pathspecs) {
        return "Blocked (CONTEXT-002): `git checkout` would discard unstaged changes to those files. Commit or `git stash` first if you want to keep them.";
    }
}

fn analyze_restore(cwd, args) {
    let parsed = git_parse_checkout_args(args);
    if parsed.staged && !parsed.worktree {
        return;
    }
    if git_would_discard(cwd, parsed.pathspecs) {
        return "Blocked (CONTEXT-002): `git restore` would discard unstaged changes to those files. Commit or `git stash` first if you want to keep them.";
    }
}

// ─── push --force: would it discard remote commits? ────────────────────────

fn analyze_push(cwd, args) {
    let forced = args.contains("-f") || args.contains("--force");
    if !forced {
        // --force-with-lease is deliberately not flagged: it already checks
        // the remote hasn't moved.
        return;
    }

    // Simplified positional parsing: good enough for the common `git push
    // [-f] [remote] [refspec]` shapes; doesn't try to handle every flag
    // that takes a value (e.g. `-o <option>`). Those are rare enough here
    // that misreading one just means this check doesn't fire, the safe
    // direction to be wrong in.
    let positional = args.filter(|a| !a.starts_with("-"));
    let remote = if positional.len() > 0 { positional[0] } else { "origin" };
    let refspec = if positional.len() > 1 { positional[1] } else { "" };

    let local_ref = "";
    let remote_branch = "";
    if refspec.contains(":") {
        let parts = refspec.split(":", 2);
        local_ref = parts[0];
        remote_branch = parts[1];
    } else if refspec != "" {
        local_ref = refspec;
        remote_branch = refspec;
    } else {
        let branch = git_current_branch(cwd);
        if branch == "" {
            return;
        }
        local_ref = branch;
        remote_branch = branch;
    }
    if local_ref == "" {
        local_ref = "HEAD";
    }

    let remote_tracking = `refs/remotes/${remote}/${remote_branch}`;
    if !git_ref_exists(cwd, remote_tracking) {
        // nothing known locally about the remote's state; don't guess
        return;
    }
    if git_is_ancestor(cwd, remote_tracking, local_ref) {
        // remote is behind (or equal to) what's being pushed: a normal
        // fast-forward
        return;
    }
    `Blocked (CONTEXT-003): force-pushing ${local_ref} to ${remote}/${remote_branch} would discard commits present on the remote that aren't in your local history (per the last fetch). Fetch and reconcile first, or use --force-with-lease.`
}

// ─── branch -D: force-deleting a branch with unmerged commits ──────────────

fn analyze_branch_delete(cwd, args) {
    let forced = args.contains("-D") ||
        (args.contains("--delete") && (args.contains("--force") || args.contains("-f")));
    if !forced {
        return;
    }
    let target = args.find(|a| !a.starts_with("-"));
    if type_of(target) != "string" {
        return;
    }
    let branch_ref = `refs/heads/${target}`;
    if !git_ref_exists(cwd, branch_ref) {
        return;
    }
    if git_is_ancestor(cwd, branch_ref, "HEAD") {
        // fully merged into HEAD: the same case plain `-d` would already allow
        return;
    }
    `Blocked (CONTEXT-004): force-deleting branch '${target}', which has commits not merged into HEAD. They'll become unreachable. Merge first, or confirm you really want to lose them.`
}

// ─── rebase / commit --amend: rewriting already-pushed history ─────────────

fn analyze_rebase(cwd, args) {
    if args.contains("--continue") || args.contains("--abort") || args.contains("--skip") {
        // these don't create new rewrites beyond what's already in progress
        return;
    }
    let upstream = git_upstream_ref(cwd);
    if upstream == "" {
        return;
    }
    if git_is_ancestor(cwd, "HEAD", upstream) {
        return `Blocked (CONTEXT-005): rebasing would rewrite commits already pushed to ${upstream}. Coordinate with anyone who might have that history, or use a merge instead.`;
    }
}

fn analyze_amend(cwd, args) {
    if !args.contains("--amend") {
        return;
    }
    let upstream = git_upstream_ref(cwd);
    if upstream == "" {
        return;
    }
    if git_is_ancestor(cwd, "HEAD", upstream) {
        return `Blocked (CONTEXT-006): amending HEAD, which is already pushed to ${upstream}. This rewrites a commit others may already have.`;
    }
}

// ─── clean -f: only deny if it would actually remove something ────────────

fn analyze_clean(cwd, args) {
    let forced = args.contains("-f") || args.contains("--force");
    if !forced || args.contains("-n") || args.contains("--dry-run") {
        return;
    }
    let dry_run_args = args.filter(|a| a != "-f" && a != "--force");
    let output = git_clean_dry_run(cwd, dry_run_args);
    if output.trim() == "" {
        // nothing would actually be removed
        return;
    }
    "Blocked (CONTEXT-007): `git clean -f` would permanently delete untracked files. Review with `git clean -n` first if you want to proceed."
}

// ─── dispatch ────────────────────────────────────────────────────────────

fn analyze(cwd, subcommand, args) {
    if subcommand == "switch" {
        return analyze_switch(cwd, args);
    }
    if subcommand == "checkout" {
        return analyze_checkout(cwd, args);
    }
    if subcommand == "restore" {
        return analyze_restore(cwd, args);
    }
    if subcommand == "push" {
        return analyze_push(cwd, args);
    }
    if subcommand == "branch" {
        return analyze_branch_delete(cwd, args);
    }
    if subcommand == "rebase" {
        return analyze_rebase(cwd, args);
    }
    if subcommand == "commit" {
        return analyze_amend(cwd, args);
    }
    if subcommand == "clean" {
        return analyze_clean(cwd, args);
    }
}

fn check(cmd, cwd, input) {
    // Cheap gate: nothing to do unless the command touches one of the
    // subcommands this rule cares about.
    if !has_trigger_word(cmd) {
        return;
    }
    if !command_exists("git") {
        return;
    }

    // Each invocation is judged against the directory it actually runs in:
    // `git -C <dir>` or a `cd` earlier on the line, not the hook's cwd. Two
    // different repos on one command line get judged separately, and the
    // work-tree check has to be per-invocation for the same reason.
    for invocation in git_invocations(cmd) {
        let dir = resolve_dir(cwd, invocation.dir);
        if !git_is_inside_work_tree(dir) {
            continue;
        }
        let result = analyze(dir, invocation.subcommand, invocation.args);
        if is_deny(result) {
            return result;
        }
    }
}
