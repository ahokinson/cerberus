**What this changes**

**Why**

**Checks**

- [ ] `cargo test`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo fmt`

**If this touches a rule script**

- [ ] The `// Head: judgement — Purpose: <purpose>` header is present and
      accurate
- [ ] Behavioral tests added in `src/rules/engine.rs` (not just
      `shipped_rule_scripts_compile`)
- [ ] Listed in `src/embedded.rs`'s `RULES` array, if it's a new shipped
      script
- [ ] Noted which commands stay allowed, so the false-positive cost is
      visible

**If this changes the `sandbox-integrity` rule**

`health` uses SANDBOX-001 as its canary for the judgement head. Weakening it
turns the whole rule-script layer's health check into a no-op. Say why.
