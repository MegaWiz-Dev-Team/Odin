//! Thor v0 — lightweight policy gate for T3 write actions (PR merge).
//!
//! Hand-rolled checks now; designed to be swapped for a Regorus (Rego-in-Rust)
//! engine later without changing the call site. Runs AFTER the human confirms a
//! merge but BEFORE Odin actually calls the GitHub merge API — defense-in-depth.
//!
//! Tunable via env (all optional):
//!   THOR_MAX_MERGE_LINES (default 800)  — reject merges whose diff exceeds this
//!   THOR_MAX_MERGE_FILES (default 15)   — reject merges touching more files
//!   THOR_BLOCK_PROTECTED_MERGE (false)  — if true, block merges into main/master/etc
//!   THOR_HEAD_PATTERN ("")              — warn if head branch lacks this substring
//!   THOR_DRY_RUN (false)               — evaluate + report, but never merge

use serde_json::Value;

const PROTECTED: &[&str] = &["main", "master", "production", "prod", "release"];

pub struct ThorMergePolicy {
    pub max_lines: u64,
    pub max_files: u64,
    pub block_protected_base: bool,
    pub head_pattern: Option<String>,
    pub dry_run: bool,
}

impl ThorMergePolicy {
    pub fn from_env() -> Self {
        let num = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
        let flag = |k: &str| std::env::var(k).map(|v| v == "true" || v == "1").unwrap_or(false);
        Self {
            max_lines: num("THOR_MAX_MERGE_LINES", 800),
            max_files: num("THOR_MAX_MERGE_FILES", 15),
            block_protected_base: flag("THOR_BLOCK_PROTECTED_MERGE"),
            head_pattern: std::env::var("THOR_HEAD_PATTERN").ok().filter(|s| !s.is_empty()),
            dry_run: flag("THOR_DRY_RUN"),
        }
    }
}

#[derive(Debug)]
pub struct ThorVerdict {
    pub allow: bool,
    pub violations: Vec<String>,
    pub warnings: Vec<String>,
}

/// Evaluate the merge policy against a PR object (shape from `agents::gh_pr_get`).
/// Fails closed: any load error or hard violation → allow=false.
pub fn check_merge(policy: &ThorMergePolicy, pr: &Value) -> ThorVerdict {
    let mut violations = Vec::new();
    let mut warnings = Vec::new();

    // Upstream fetch error → fail closed.
    if let Some(err) = pr.get("error").and_then(|e| e.as_str()) {
        violations.push(format!("could not load PR: {}", err));
        return ThorVerdict { allow: false, violations, warnings };
    }

    if pr.get("draft").and_then(|v| v.as_bool()).unwrap_or(false) {
        violations.push("PR is a draft — mark ready-for-review before merging".into());
    }

    let base = pr.get("base").and_then(|v| v.as_str()).unwrap_or("");
    if PROTECTED.contains(&base) {
        if policy.block_protected_base {
            violations.push(format!(
                "merge into protected branch '{}' blocked by policy (THOR_BLOCK_PROTECTED_MERGE)",
                base
            ));
        } else {
            warnings.push(format!("merging into protected branch '{}'", base));
        }
    }

    match pr.get("mergeable").and_then(|v| v.as_bool()) {
        Some(false) => violations.push("PR is not mergeable (conflicts or failing required checks)".into()),
        None => warnings.push("mergeability not yet computed by GitHub — retry shortly".into()),
        Some(true) => {}
    }
    if let Some(st) = pr.get("mergeable_state").and_then(|v| v.as_str()) {
        if matches!(st, "dirty" | "blocked" | "behind") {
            violations.push(format!("mergeable_state='{}' — not safe to merge", st));
        }
    }

    let files = pr.get("files").and_then(|v| v.as_array());
    let nfiles = files.map(|a| a.len() as u64).unwrap_or(0);
    let lines: u64 = files
        .map(|a| {
            a.iter()
                .map(|f| {
                    f.get("additions").and_then(|v| v.as_u64()).unwrap_or(0)
                        + f.get("deletions").and_then(|v| v.as_u64()).unwrap_or(0)
                })
                .sum()
        })
        .unwrap_or(0);
    if nfiles > policy.max_files {
        violations.push(format!("too many files: {} > cap {}", nfiles, policy.max_files));
    }
    if lines > policy.max_lines {
        violations.push(format!("diff too large: {} lines > cap {}", lines, policy.max_lines));
    }

    if let Some(pat) = &policy.head_pattern {
        let head = pr.get("head").and_then(|v| v.as_str()).unwrap_or("");
        if !head.contains(pat.as_str()) {
            warnings.push(format!(
                "head branch '{}' doesn't match required pattern '{}'",
                head, pat
            ));
        }
    }

    ThorVerdict { allow: violations.is_empty(), violations, warnings }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy() -> ThorMergePolicy {
        ThorMergePolicy {
            max_lines: 800,
            max_files: 15,
            block_protected_base: false,
            head_pattern: None,
            dry_run: false,
        }
    }

    fn clean_pr() -> Value {
        json!({
            "draft": false, "base": "main", "mergeable": true, "mergeable_state": "clean",
            "head": "fix/muninn-1-x",
            "files": [{"filename": "a.rs", "additions": 10, "deletions": 2}]
        })
    }

    #[test]
    fn allows_clean_small_pr() {
        let v = check_merge(&policy(), &clean_pr());
        assert!(v.allow, "violations: {:?}", v.violations);
        // merging to main is a warning by default, not a block
        assert!(!v.warnings.is_empty());
    }

    #[test]
    fn denies_draft() {
        let mut pr = clean_pr();
        pr["draft"] = json!(true);
        assert!(!check_merge(&policy(), &pr).allow);
    }

    #[test]
    fn denies_unmergeable() {
        let mut pr = clean_pr();
        pr["mergeable"] = json!(false);
        assert!(!check_merge(&policy(), &pr).allow);
        let mut pr2 = clean_pr();
        pr2["mergeable_state"] = json!("dirty");
        assert!(!check_merge(&policy(), &pr2).allow);
    }

    #[test]
    fn denies_oversize_diff_and_files() {
        let mut pr = clean_pr();
        pr["files"] = json!([{"filename": "big.rs", "additions": 900, "deletions": 100}]);
        assert!(!check_merge(&policy(), &pr).allow);

        let mut p = policy();
        p.max_files = 1;
        let mut pr2 = clean_pr();
        pr2["files"] = json!([
            {"filename": "a.rs", "additions": 1, "deletions": 0},
            {"filename": "b.rs", "additions": 1, "deletions": 0}
        ]);
        assert!(!check_merge(&p, &pr2).allow);
    }

    #[test]
    fn blocks_protected_when_configured() {
        let mut p = policy();
        p.block_protected_base = true;
        assert!(!check_merge(&p, &clean_pr()).allow); // base=main
    }

    #[test]
    fn fails_closed_on_load_error() {
        let v = check_merge(&policy(), &json!({"error": "github 404"}));
        assert!(!v.allow);
    }
}
