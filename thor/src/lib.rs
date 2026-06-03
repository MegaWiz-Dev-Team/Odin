//! Thor — Asgard policy enforcer.
//!
//! Embeds the [Regorus](https://github.com/microsoft/regorus) Rego engine and a
//! bundled `.rego` policy to gate T3 write actions. Policy lives as data
//! (`policies/*.rego`), not hand-rolled Rust `if`s, so it can be reviewed, tested
//! and (later) hot-swapped without recompiling call sites.
//!
//! v1 surface: PR-merge policy. The same engine pattern will gate other T3 paths
//! (Loki guards, Bifrost/Iris writes) by adding more policies + entry points.

use regorus::{Engine, Value};

/// The merge policy, compiled into the binary.
const MERGE_POLICY: &str = include_str!("../policies/merge.rego");

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

/// Evaluate the PR-merge policy against the given input JSON.
///
/// Input shape — see `policies/merge.rego`. **Fails closed**: any policy-load or
/// input-parse error yields `allow = false` with an explanatory violation, so a
/// broken policy can never silently wave a merge through.
pub fn evaluate_merge(input_json: &str) -> Verdict {
    let mut engine = match load_engine("merge.rego", MERGE_POLICY) {
        Ok(e) => e,
        Err(e) => return Verdict::denied(format!("thor policy load error: {e}")),
    };
    let input = match Value::from_json_str(input_json) {
        Ok(v) => v,
        Err(e) => return Verdict::denied(format!("thor input parse error: {e}")),
    };
    engine.set_input(input);

    let violations = eval_strings(&mut engine, "data.thor.merge.violations");
    let warnings = eval_strings(&mut engine, "data.thor.merge.warnings");
    let allow_rule = engine
        .eval_rule("data.thor.merge.allow".to_string())
        .ok()
        .and_then(|v| v.as_bool().ok().copied())
        .unwrap_or(false);

    // Belt-and-suspenders: allow only if the policy says so AND there are no
    // violations (guards against an out-of-sync policy).
    let allow = allow_rule && violations.is_empty();
    Verdict { allow, violations, warnings }
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
}
