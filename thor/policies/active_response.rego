# Thor — Active Response policy (Rego v1, Regorus). Gates Odin's T3 "enforcement
# arm": sending a Wazuh Active Response command (block IP / isolate / restart …)
# to agents. Runs after human confirm, before Odin calls the Wazuh manager API.
#
# Input shape:
#   {
#     "command": "firewall-drop",
#     "agents": ["001", "002"],
#     "policy": { "allowed_commands": ["firewall-drop","restart-wazuh","disable-account"],
#                 "allow_all_agents": false }
#   }
#
# Outputs (data.thor.active_response.*): allow : bool, violations : set, warnings : set
package thor.active_response

default allow := false

allow if count(violations) == 0

command_allowed if input.command in input.policy.allowed_commands

violations contains "no command specified" if {
	input.command == ""
}

violations contains msg if {
	input.command != ""
	not command_allowed
	msg := sprintf("command '%s' is not in the Thor allowlist", [input.command])
}

violations contains "no target agents specified" if {
	count(input.agents) == 0
}

# Block mass actions / the manager node itself unless explicitly allowed.
violations contains msg if {
	input.policy.allow_all_agents == false
	some a in input.agents
	a in {"all", "*", "000"}
	msg := sprintf("targeting '%s' (mass action / manager node) is blocked by policy", [a])
}

warnings contains msg if {
	count(input.agents) > 5
	msg := sprintf("active response targets %d agents at once", [count(input.agents)])
}
