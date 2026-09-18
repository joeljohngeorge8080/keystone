# keystone.lib — shared presence/type guards. Every guard is a positive assertion; an absent or
# mistyped claim leaves the rule undefined, which can never satisfy an allow (spec Ch. 19/20, R2).
package keystone.lib

identity_present if {
	is_object(input.identity)
	is_string(input.identity.sub)
	is_string(input.identity.repository_owner)
	input.identity.repository_owner in {"acme"}
}

request_well_formed if {
	is_object(input.request)
	is_string(input.request.grant)
	is_number(input.request.requested_ttl_seconds)
}

not_true(v) if {
	not v
}
