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
		"repository_id": "42",
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

test_deny_on_other_repository_id if {
	d := authz.decision with input as object.union(good_input, {"identity": object.union(good_input.identity, {"repository_id": "43"})})
	d.allow == false
}

test_digest_is_unloaded_under_opa_test if {
	d := authz.decision with input as good_input
	d.loaded_bundle_digest == "unloaded"
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

test_digest_echoes_the_single_loaded_bundle_revision if {
	bundles := {"keystone": {"manifest": {"revision": "sha256:feed"}}}
	d := authz.decision with input as good_input with data.system.bundles as bundles
	d.loaded_bundle_digest == "sha256:feed"
}
