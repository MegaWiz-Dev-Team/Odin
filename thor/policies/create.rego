# Thor — GitHub issue-creation policy (Rego v1, Regorus). Gates BOTH the
# human-confirmed /api/issues/create endpoint and the autonomous Týr bridge,
# centrally via agents::create_issue_core.
#
# Input shape (lengths precomputed by the caller to avoid builtin ambiguity):
#   {
#     "repo": "owner/repo",
#     "title_len": int, "title_empty": bool,
#     "body_len": int,
#     "policy": { "org_prefix": "MegaWiz-Dev-Team/", "max_title": 200, "max_body": 20000 }
#   }
#
# Outputs (data.thor.create.*): allow : bool, violations : set, warnings : set
package thor.create

default allow := false

allow if count(violations) == 0

violations contains "issue title is empty" if {
	input.title_empty == true
}

violations contains msg if {
	input.title_len > input.policy.max_title
	msg := sprintf("issue title too long: %d chars > cap %d", [input.title_len, input.policy.max_title])
}

violations contains msg if {
	input.body_len > input.policy.max_body
	msg := sprintf("issue body too long: %d chars > cap %d", [input.body_len, input.policy.max_body])
}

# Only file issues into the sanctioned org — prevents a bad service→repo mapping
# from opening issues on an arbitrary/foreign repository.
violations contains msg if {
	not startswith(input.repo, input.policy.org_prefix)
	msg := sprintf("repo '%s' is outside the allowed org prefix '%s'", [input.repo, input.policy.org_prefix])
}

warnings contains "issue body is empty" if {
	input.body_len == 0
}
