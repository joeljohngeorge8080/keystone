# keystone.authz — the single decision entry point (spec Ch. 19). Exactly one decision per input;
# every deny carries a non-empty deny_reasons (F3).
package keystone.authz

import data.keystone.grants

matched contains name if {
	some name
	grants[name].allow == true
}

# The digest OPA actually has loaded (F7): recorded as policy_digest and compared to the DB pin.
loaded_bundle_digest := digest if {
	revisions := [r | some name; r := data.system.bundles[name].manifest.revision]
	count(revisions) == 1
	digest := revisions[0]
} else := "unloaded"

decision := {
	"allow": true,
	"grant": name,
	"ttl_cap_seconds": grants[name].ttl_cap_seconds,
	"session_policy_ref": grants[name].session_policy_ref,
	"rule_path": sprintf("keystone.grants.%s", [name]),
	"deny_reasons": [],
	"obligations": grants[name].obligations,
	"loaded_bundle_digest": loaded_bundle_digest,
} if {
	count(matched) == 1
	some name in matched
}

decision := {
	"allow": false,
	"grant": null,
	"ttl_cap_seconds": 0,
	"session_policy_ref": null,
	"rule_path": null,
	"deny_reasons": ["NO_GRANT_MATCHED"],
	"obligations": {},
	"loaded_bundle_digest": loaded_bundle_digest,
} if {
	count(matched) == 0
}

decision := {
	"allow": false,
	"grant": null,
	"ttl_cap_seconds": 0,
	"session_policy_ref": null,
	"rule_path": null,
	"deny_reasons": ["AMBIGUOUS_GRANT"],
	"obligations": {},
	"loaded_bundle_digest": loaded_bundle_digest,
} if {
	count(matched) > 1
}
