package keystone.grants.deploy_prod

import data.keystone.lib

default allow := false

allow if {
	lib.identity_present
	lib.request_well_formed
	input.request.grant == "deploy-prod"
	is_string(input.identity.repository)
	input.identity.repository == "acme/app"
	is_string(input.identity.ref)
	input.identity.ref == "refs/heads/main"
	is_string(input.identity.event_name)
	input.identity.event_name in {"push", "workflow_dispatch"}
	is_boolean(input.identity.is_fork)
	input.identity.is_fork == false
	prod := [e | some e in input.identity.environments; e == "production"]
	count(prod) == count(input.identity.environments)
}

ttl_cap_seconds := 900

session_policy_ref := "s3-deploy-narrow"

obligations := {"require_environment": "production"}
