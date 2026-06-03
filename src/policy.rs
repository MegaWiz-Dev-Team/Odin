//! Merge-policy adapter.
//!
//! Reads env thresholds, builds the Rego `input` from a PR's facts, and delegates
//! the decision to the `thor` crate (embedded Regorus engine + bundled `.rego`).
//! Keeps Odin-specific glue (env + the GitHub PR JSON shape) out of the reusable
//! policy crate. The verdict type is re-exported from `thor`.

use serde_json::{json, Value};

pub use thor::Verdict;

pub struct MergePolicy {
    pub max_lines: u64,
    pub max_files: u64,
    pub block_protected_base: bool,
    pub head_pattern: Option<String>,
    pub dry_run: bool,
}

impl MergePolicy {
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

/// Build the Rego input from a PR object (shape from `agents::gh_pr_get`) + the
/// env policy, then evaluate via the `thor` crate. Fails closed if the PR
/// couldn't be loaded (the crate also fails closed on any engine error).
pub fn check_merge(policy: &MergePolicy, pr: &Value) -> Verdict {
    if let Some(err) = pr.get("error").and_then(|e| e.as_str()) {
        return Verdict {
            allow: false,
            violations: vec![format!("could not load PR: {err}")],
            warnings: vec![],
        };
    }

    let files = pr.get("files").and_then(|v| v.as_array());
    let num_files = files.map(|a| a.len() as u64).unwrap_or(0);
    let diff_lines: u64 = files
        .map(|a| {
            a.iter()
                .map(|f| {
                    f.get("additions").and_then(|v| v.as_u64()).unwrap_or(0)
                        + f.get("deletions").and_then(|v| v.as_u64()).unwrap_or(0)
                })
                .sum()
        })
        .unwrap_or(0);

    let input = json!({
        "pr": {
            "draft": pr.get("draft").and_then(|v| v.as_bool()).unwrap_or(false),
            "mergeable": pr.get("mergeable").cloned().unwrap_or(Value::Null),
            "mergeable_state": pr.get("mergeable_state").and_then(|v| v.as_str()).unwrap_or(""),
            "base": pr.get("base").and_then(|v| v.as_str()).unwrap_or(""),
            "head": pr.get("head").and_then(|v| v.as_str()).unwrap_or(""),
        },
        "diff_lines": diff_lines,
        "num_files": num_files,
        "policy": {
            "max_lines": policy.max_lines,
            "max_files": policy.max_files,
            "block_protected_base": policy.block_protected_base,
            "head_pattern": policy.head_pattern,
        }
    });

    thor::evaluate_merge(&input.to_string())
}
