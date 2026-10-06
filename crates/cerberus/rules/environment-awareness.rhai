// Head: judgement — Purpose: contextual bad decisions
//
// Catches the classic "meant to run this in staging, forgot my shell was
// still pointed at prod" mistake: `kubectl delete` or `terraform destroy`/
// `apply` while the *currently active* context/workspace looks like
// production. This is situational by nature. The same command is fine or
// dangerous purely depending on state nothing in the command line itself
// reveals.

fn has_token(tokens, word) {
    tokens.contains(word)
}

fn check(cmd, cwd, input) {
    if !(cmd.contains("kubectl") || cmd.contains("terraform")) {
        return;
    }
    let tokens = tokenize(cmd);

    if has_token(tokens, "kubectl") && has_token(tokens, "delete") {
        let context = kube_context();
        if context != "" && looks_like_production(context) {
            return `Blocked (ENV-001): kubectl delete while the active context ('${context}') looks like production. Switch context explicitly first if this is intentional.`;
        }
    }

    if has_token(tokens, "terraform") && (has_token(tokens, "destroy") || has_token(tokens, "apply")) {
        let workspace = terraform_workspace(cwd);
        if workspace != "" && looks_like_production(workspace) {
            let verb = if has_token(tokens, "destroy") { "destroy" } else { "apply" };
            return `Blocked (ENV-002): terraform ${verb} while the active workspace ('${workspace}') looks like production.`;
        }
    }
}
