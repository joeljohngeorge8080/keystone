package keystone.authz_test

import data.keystone.authz

good_input := {
	"schema": 1,
	"identity": {
		"sub": "repo:acme/app:ref:refs/heads/main",
		"repository_owner": "acme",
		"repository": "acme/app",
		"ref": "refs/heads/main",
		"event_name": "push",
		"is_fork": false,
	},
	"request": {"grant": "deploy-prod", "requested_ttl_seconds": 900},
	"context": {},
}

test_allow_on_complete_identity if {
	d := authz.decision with input as good_input
	d.allow == true
	d.grant == "deploy_prod"
	d.deny_reasons == []
}

test_deny_when_claim_absent if {
	d := authz.decision with input as object.remove(good_input, ["identity"])
	d.allow == false
	count(d.deny_reasons) > 0
}

test_deny_on_fork if {
	d := authz.decision with input as object.union(good_input, {"identity": object.union(good_input.identity, {"is_fork": true})})
	d.allow == false
}

test_deny_on_wrong_type_claim if {
	d := authz.decision with input as object.union(good_input, {"identity": object.union(good_input.identity, {"ref": ["refs/heads/main"]})})
	d.allow == false
}

test_deny_on_wrong_org if {
	d := authz.decision with input as object.union(good_input, {"identity": object.union(good_input.identity, {"repository_owner": "evil"})})
	d.allow == false
}

test_deny_when_two_grants_match_is_ambiguous if {
	second := {"allow": true, "ttl_cap_seconds": 900, "session_policy_ref": "x", "obligations": {}}
	d := authz.decision with input as good_input with data.keystone.grants.second as second
	d.allow == false
	d.deny_reasons == ["AMBIGUOUS_GRANT"]
}
