# Thor — PR merge policy (Rego v1, evaluated by Regorus, embedded in the `thor` crate).
#
# Input shape (built by the caller from the PR facts + env policy):
#   {
#     "pr": { "draft": bool, "mergeable": bool|null, "mergeable_state": str,
#             "base": str, "head": str },
#     "diff_lines": int,
#     "num_files": int,
#     "policy": { "max_lines": int, "max_files": int,
#                 "block_protected_base": bool, "head_pattern": str|null }
#   }
#
# Outputs (queried as data.thor.merge.<rule>):
#   allow       : bool   — true only when there are zero violations
#   violations  : set    — hard reasons the merge is blocked
#   warnings    : set    — advisory notes (merge still allowed)
package thor.merge

protected := {"main", "master", "production", "prod", "release"}

default allow := false

allow if count(violations) == 0

# ---- hard violations (block the merge) ----

violations contains "PR is a draft — mark ready-for-review before merging" if {
	input.pr.draft == true
}

violations contains "PR is not mergeable (conflicts or failing required checks)" if {
	input.pr.mergeable == false
}

violations contains msg if {
	input.pr.mergeable_state in {"dirty", "blocked", "behind"}
	msg := sprintf("mergeable_state='%s' — not safe to merge", [input.pr.mergeable_state])
}

violations contains msg if {
	input.diff_lines > input.policy.max_lines
	msg := sprintf("diff too large: %d lines > cap %d", [input.diff_lines, input.policy.max_lines])
}

violations contains msg if {
	input.num_files > input.policy.max_files
	msg := sprintf("too many files: %d > cap %d", [input.num_files, input.policy.max_files])
}

violations contains msg if {
	input.policy.block_protected_base == true
	input.pr.base in protected
	msg := sprintf("merge into protected branch '%s' blocked by policy", [input.pr.base])
}

# ---- soft warnings (allowed, but surfaced + audited) ----

warnings contains msg if {
	input.policy.block_protected_base == false
	input.pr.base in protected
	msg := sprintf("merging into protected branch '%s'", [input.pr.base])
}

warnings contains "mergeability not yet computed by GitHub — retry shortly" if {
	input.pr.mergeable == null
}

warnings contains msg if {
	input.policy.head_pattern != null
	indexof(input.pr.head, input.policy.head_pattern) == -1
	msg := sprintf("head branch '%s' doesn't match required pattern '%s'", [input.pr.head, input.policy.head_pattern])
}
