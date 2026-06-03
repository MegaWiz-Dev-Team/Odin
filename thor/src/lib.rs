//! Thor — Asgard policy enforcer.
//!
//! Embeds the [Regorus](https://github.com/microsoft/regorus) Rego engine and a
//! bundled `.rego` policy to gate T3 write actions. Policy lives as data
//! (`policies/*.rego`), not hand-rolled Rust `if`s, so it can be reviewed, tested
//! and (later) hot-swapped without recompiling call sites.
//!
//! Surface: PR-merge + issue-creation policies. The same engine pattern gates more
//! T2/T3 paths (Active Response, Loki guards, Bifrost/Iris writes) by adding a
//! `.rego` file + an entry point.

use regorus::{Engine, Value};

/// Policies compiled into the binary.
const MERGE_POLICY: &str = include_str!("../policies/merge.rego");
const CREATE_POLICY: &str = include_str!("../policies/create.rego");
const ACTIVE_RESPONSE_POLICY: &str = include_str!("../policies/active_response.rego");

/// Result of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub allow: bool,
    pub violations: Vec<String>,
    pub warnings: Vec<String>,
}

impl Verdict {
    fn denied(reason: String) -> Self {
        Verdict { allow: false, violations: vec![reason], warnings: vec![] }
    }
}

fn load_engine(policy_name: &str, policy_src: &str) -> Result<Engine, String> {
    let mut engine = Engine::new();
    engine
        .add_policy(policy_name.to_string(), policy_src.to_string())
        .map_err(|e| format!("add_policy failed: {e}"))?;
    Ok(engine)
}

/// Eval a set/array-valued rule into a sorted Vec<String>. Missing/undefined → [].
fn eval_strings(engine: &mut Engine, rule: &str) -> Vec<String> {
    let v = match engine.eval_rule(rule.to_string()) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let mut out: Vec<String> = if let Ok(set) = v.as_set() {
        set.iter().filter_map(|x| x.as_string().ok().map(|s| s.to_string())).collect()
    } else if let Ok(arr) = v.as_array() {
        arr.iter().filter_map(|x| x.as_string().ok().map(|s| s.to_string())).collect()
    } else {
        vec![]
    };
    out.sort();
    out
}

/// Generic evaluator: load `policy_src`, set `input_json`, query the rules under
/// the `pkg` package (`data.<pkg>.{allow,violations,warnings}`).
///
/// **Fails closed**: any policy-load or input-parse error yields `allow = false`
/// with an explanatory violation, so a broken policy can never wave an action through.
fn evaluate(policy_name: &str, policy_src: &str, pkg: &str, input_json: &str) -> Verdict {
    let mut engine = match load_engine(policy_name, policy_src) {
        Ok(e) => e,
        Err(e) => return Verdict::denied(format!("thor policy load error: {e}")),
    };
    let input = match Value::from_json_str(input_json) {
        Ok(v) => v,
        Err(e) => return Verdict::denied(format!("thor input parse error: {e}")),
    };
    engine.set_input(input);

    let violations = eval_strings(&mut engine, &format!("data.{pkg}.violations"));
    let warnings = eval_strings(&mut engine, &format!("data.{pkg}.warnings"));
    let allow_rule = engine
        .eval_rule(format!("data.{pkg}.allow"))
        .ok()
        .and_then(|v| v.as_bool().ok().copied())
        .unwrap_or(false);

    // Belt-and-suspenders: allow only if the policy says so AND there are no
    // violations (guards against an out-of-sync policy).
    let allow = allow_rule && violations.is_empty();
    Verdict { allow, violations, warnings }
}

/// Evaluate the PR-merge policy. Input shape — see `policies/merge.rego`.
pub fn evaluate_merge(input_json: &str) -> Verdict {
    evaluate("merge.rego", MERGE_POLICY, "thor.merge", input_json)
}

/// Evaluate the issue-creation policy. Input shape — see `policies/create.rego`.
pub fn evaluate_create(input_json: &str) -> Verdict {
    evaluate("create.rego", CREATE_POLICY, "thor.create", input_json)
}

/// Evaluate the Active-Response policy. Input — see `policies/active_response.rego`.
pub fn evaluate_active_response(input_json: &str) -> Verdict {
    evaluate("active_response.rego", ACTIVE_RESPONSE_POLICY, "thor.active_response", input_json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input(pr: serde_json::Value, lines: u64, files: u64, pol: serde_json::Value) -> String {
        json!({ "pr": pr, "diff_lines": lines, "num_files": files, "policy": pol }).to_string()
    }
    fn pol() -> serde_json::Value {
        json!({ "max_lines": 800, "max_files": 15, "block_protected_base": false, "head_pattern": null })
    }
    fn clean_pr() -> serde_json::Value {
        json!({ "draft": false, "mergeable": true, "mergeable_state": "clean", "base": "main", "head": "fix/muninn-1" })
    }

    #[test]
    fn allows_clean_small_pr() {
        let v = evaluate_merge(&input(clean_pr(), 12, 1, pol()));
        assert!(v.allow, "violations: {:?}", v.violations);
        assert!(!v.warnings.is_empty(), "expected protected-base warning for main");
    }

    #[test]
    fn denies_draft() {
        let mut pr = clean_pr();
        pr["draft"] = json!(true);
        let v = evaluate_merge(&input(pr, 10, 1, pol()));
        assert!(!v.allow);
        assert!(v.violations.iter().any(|m| m.contains("draft")));
    }

    #[test]
    fn denies_unmergeable() {
        let mut pr = clean_pr();
        pr["mergeable"] = json!(false);
        assert!(!evaluate_merge(&input(pr, 10, 1, pol())).allow);
        let mut pr2 = clean_pr();
        pr2["mergeable_state"] = json!("dirty");
        assert!(!evaluate_merge(&input(pr2, 10, 1, pol())).allow);
    }

    #[test]
    fn denies_oversize_diff_and_files() {
        assert!(!evaluate_merge(&input(clean_pr(), 1000, 1, pol())).allow);
        let p = json!({ "max_lines": 800, "max_files": 1, "block_protected_base": false, "head_pattern": null });
        assert!(!evaluate_merge(&input(clean_pr(), 10, 2, p)).allow);
    }

    #[test]
    fn blocks_protected_when_configured() {
        let p = json!({ "max_lines": 800, "max_files": 15, "block_protected_base": true, "head_pattern": null });
        let v = evaluate_merge(&input(clean_pr(), 10, 1, p));
        assert!(!v.allow, "should block merge to main when configured");
    }

    #[test]
    fn warns_unknown_mergeability() {
        let mut pr = clean_pr();
        pr["mergeable"] = json!(null);
        let v = evaluate_merge(&input(pr, 10, 1, pol()));
        assert!(v.allow); // null mergeability is a warning, not a block
        assert!(v.warnings.iter().any(|m| m.contains("mergeability")));
    }

    #[test]
    fn warns_head_pattern_mismatch() {
        let mut pr = clean_pr();
        pr["head"] = json!("random-branch");
        let p = json!({ "max_lines": 800, "max_files": 15, "block_protected_base": false, "head_pattern": "fix/" });
        let v = evaluate_merge(&input(pr, 10, 1, p));
        assert!(v.warnings.iter().any(|m| m.contains("pattern")));
    }

    #[test]
    fn fails_closed_on_bad_input() {
        let v = evaluate_merge("not json");
        assert!(!v.allow);
    }

    // ── create policy ──
    fn cpol() -> serde_json::Value {
        json!({ "org_prefix": "MegaWiz-Dev-Team/", "max_title": 200, "max_body": 20000 })
    }
    fn cinput(repo: &str, title_len: u64, title_empty: bool, body_len: u64) -> String {
        json!({ "repo": repo, "title_len": title_len, "title_empty": title_empty,
                "body_len": body_len, "policy": cpol() }).to_string()
    }

    #[test]
    fn create_allows_normal_issue() {
        let v = evaluate_create(&cinput("MegaWiz-Dev-Team/Odin", 42, false, 300));
        assert!(v.allow, "violations: {:?}", v.violations);
    }

    #[test]
    fn create_denies_empty_title() {
        let v = evaluate_create(&cinput("MegaWiz-Dev-Team/Odin", 0, true, 300));
        assert!(!v.allow);
        assert!(v.violations.iter().any(|m| m.contains("title is empty")));
    }

    #[test]
    fn create_denies_foreign_repo() {
        let v = evaluate_create(&cinput("evil-org/x", 42, false, 300));
        assert!(!v.allow);
        assert!(v.violations.iter().any(|m| m.contains("outside the allowed org")));
    }

    #[test]
    fn create_denies_oversize_title_and_body() {
        assert!(!evaluate_create(&cinput("MegaWiz-Dev-Team/Odin", 500, false, 300)).allow);
        assert!(!evaluate_create(&cinput("MegaWiz-Dev-Team/Odin", 42, false, 50000)).allow);
    }

    #[test]
    fn create_warns_empty_body() {
        let v = evaluate_create(&cinput("MegaWiz-Dev-Team/Odin", 42, false, 0));
        assert!(v.allow);
        assert!(v.warnings.iter().any(|m| m.contains("body is empty")));
    }

    // ── active response policy ──
    fn arinput(cmd: &str, agents: serde_json::Value, allow_all: bool) -> String {
        json!({ "command": cmd, "agents": agents, "policy": {
            "allowed_commands": ["firewall-drop", "restart-wazuh", "disable-account"],
            "allow_all_agents": allow_all
        }}).to_string()
    }

    #[test]
    fn ar_allows_allowlisted_command() {
        let v = evaluate_active_response(&arinput("firewall-drop", json!(["001"]), false));
        assert!(v.allow, "violations: {:?}", v.violations);
    }

    #[test]
    fn ar_denies_unknown_command() {
        let v = evaluate_active_response(&arinput("rm-rf-everything", json!(["001"]), false));
        assert!(!v.allow);
        assert!(v.violations.iter().any(|m| m.contains("allowlist")));
    }

    #[test]
    fn ar_denies_no_agents() {
        assert!(!evaluate_active_response(&arinput("firewall-drop", json!([]), false)).allow);
    }

    #[test]
    fn ar_blocks_mass_or_manager_target() {
        assert!(!evaluate_active_response(&arinput("firewall-drop", json!(["all"]), false)).allow);
        assert!(!evaluate_active_response(&arinput("firewall-drop", json!(["000"]), false)).allow);
        // allowed when explicitly permitted
        assert!(evaluate_active_response(&arinput("firewall-drop", json!(["all"]), true)).allow);
    }
}
