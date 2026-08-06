# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

"""RFC 7643/7644 conformance and hardening tests.

These assert against literal RFC strings and observable behaviour rather than
the app's own constants, so a regression in either cannot be masked.
"""

from urllib.parse import quote

import frappe
import pytest

from saml.saml.scim_constants import (
	SCIM_ERROR_SCHEMA,
	SCIM_LIST_RESPONSE_SCHEMA,
	SCIM_PATCH_OP_SCHEMA,
	SCIM_SERVICE_USER_EMAIL,
	SCIM_USER_SCHEMA,
)
from saml.saml.scim_provisioning import set_scim_path
from saml.saml.scim_renderer import SCIMApiResponse, is_scim_request_path
from saml.tests.scim_helpers import build_scim_request, cleanup_scim_user, unique_scim_email

RFC_LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
RFC_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
RFC_PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"


def payload(email: str, **extra) -> dict:
	body = {
		"schemas": [SCIM_USER_SCHEMA],
		"userName": email,
		"name": {"givenName": "SCIM", "familyName": "RFC"},
		"active": True,
	}
	body.update(extra)
	return body


def enc(email: str) -> str:
	return quote(email, safe="")


# --------------------------------------------------------------------------
# Message envelopes (RFC 7644 3.4.2, 3.12)
# --------------------------------------------------------------------------


@pytest.mark.order(300)
def test_message_schema_constants_match_rfc():
	assert SCIM_LIST_RESPONSE_SCHEMA == RFC_LIST_RESPONSE
	assert SCIM_ERROR_SCHEMA == RFC_ERROR
	assert SCIM_PATCH_OP_SCHEMA == RFC_PATCH_OP


@pytest.mark.order(301)
def test_list_response_carries_rfc_message_urn():
	response = build_scim_request("GET", "/scim/v2/Users")
	assert response.code == 200
	assert response.data["schemas"] == [RFC_LIST_RESPONSE]


@pytest.mark.order(302)
def test_error_response_carries_rfc_message_urn():
	response = build_scim_request("GET", "/scim/v2/Users/absent@ambrosiapieco.example")
	assert response.code == 404
	assert response.data["schemas"] == [RFC_ERROR]


@pytest.mark.order(303)
def test_create_returns_location_header():
	"""RFC 7644 3.3: the URI of the created resource SHALL be in the Location header."""
	email = unique_scim_email("location")
	response = build_scim_request("POST", "/scim/v2/Users", payload(email))
	assert response.code == 201
	location = response.headers.get("Location")
	assert location, "201 response must carry a Location header"
	assert location.endswith(f"/scim/v2/Users/{enc(email)}")
	assert location == response.data["meta"]["location"]
	cleanup_scim_user(email)


# --------------------------------------------------------------------------
# Error handling must stay inside the SCIM envelope
# --------------------------------------------------------------------------


@pytest.mark.order(310)
def test_non_numeric_count_returns_scim_400():
	response = build_scim_request("GET", "/scim/v2/Users", query={"count": "abc"})
	assert response.code == 400
	assert response.data["scimType"] == "invalidValue"
	assert response.data["schemas"] == [RFC_ERROR]


@pytest.mark.order(311)
def test_non_numeric_start_index_returns_scim_400():
	response = build_scim_request("GET", "/scim/v2/Users", query={"startIndex": "xyz"})
	assert response.code == 400
	assert response.data["scimType"] == "invalidValue"


@pytest.mark.order(312)
def test_non_ascii_bearer_token_returns_401_not_500():
	with pytest.raises(SCIMApiResponse) as exc:
		build_scim_request("GET", "/scim/v2/Users", token="tökén")
	assert exc.value.code == 401


# --------------------------------------------------------------------------
# Delete semantics (RFC 7644 3.6)
# --------------------------------------------------------------------------


@pytest.mark.order(320)
def test_delete_then_get_returns_404():
	email = unique_scim_email("del404")
	build_scim_request("POST", "/scim/v2/Users", payload(email))
	assert build_scim_request("DELETE", f"/scim/v2/Users/{enc(email)}").code == 204

	response = build_scim_request("GET", f"/scim/v2/Users/{enc(email)}")
	assert response.code == 404, "RFC 7644 3.6: deleted resources MUST return 404"
	cleanup_scim_user(email)


@pytest.mark.order(321)
def test_deleted_user_omitted_from_query_results():
	email = unique_scim_email("delomit")
	build_scim_request("POST", "/scim/v2/Users", payload(email))
	build_scim_request("DELETE", f"/scim/v2/Users/{enc(email)}")

	response = build_scim_request("GET", "/scim/v2/Users", query={"filter": f'userName eq "{email}"'})
	assert response.code == 200
	assert response.data["totalResults"] == 0, "RFC 7644 3.6: MUST omit from future query results"
	cleanup_scim_user(email)


@pytest.mark.order(322)
def test_recreate_after_delete_succeeds():
	"""RFC 7644 3.6: a create reusing a deleted userName SHOULD NOT fail with 409.

	This is the re-hire / re-assign path.
	"""
	email = unique_scim_email("rehire")
	build_scim_request("POST", "/scim/v2/Users", payload(email, externalId="rehire-1"))
	build_scim_request("DELETE", f"/scim/v2/Users/{enc(email)}")

	response = build_scim_request(
		"POST", "/scim/v2/Users", payload(email, externalId="rehire-2")
	)
	assert response.code == 201, "re-provisioning a deactivated user must not 409"
	assert response.data["active"] is True
	assert response.data["externalId"] == "rehire-2"
	assert frappe.db.get_value("User", email, "enabled") == 1
	cleanup_scim_user(email)


@pytest.mark.order(323)
def test_patch_active_false_keeps_resource_visible():
	"""Regression guard: deactivation is NOT deletion; the resource stays addressable."""
	email = unique_scim_email("deact")
	build_scim_request("POST", "/scim/v2/Users", payload(email))
	build_scim_request(
		"PATCH",
		f"/scim/v2/Users/{enc(email)}",
		{"schemas": [RFC_PATCH_OP], "Operations": [{"op": "replace", "value": {"active": False}}]},
	)

	response = build_scim_request("GET", f"/scim/v2/Users/{enc(email)}")
	assert response.code == 200
	assert response.data["active"] is False

	listed = build_scim_request("GET", "/scim/v2/Users", query={"filter": f'userName eq "{email}"'})
	assert listed.data["totalResults"] == 1
	cleanup_scim_user(email)


# --------------------------------------------------------------------------
# Scoping: SCIM must not reach users it never provisioned
# --------------------------------------------------------------------------


@pytest.fixture
def unmanaged_user():
	email = "unmanaged.local@ambrosiapieco.example"
	cleanup_scim_user(email)
	user = frappe.get_doc(
		{
			"doctype": "User",
			"email": email,
			"first_name": "Unmanaged",
			"last_name": "Local",
			"enabled": 1,
			"send_welcome_email": 0,
			"user_type": "System User",
		}
	)
	user.insert(ignore_permissions=True)
	yield email
	cleanup_scim_user(email)


@pytest.mark.order(330)
def test_get_unmanaged_user_returns_404(unmanaged_user):
	assert build_scim_request("GET", f"/scim/v2/Users/{enc(unmanaged_user)}").code == 404


@pytest.mark.order(331)
def test_put_cannot_take_over_unmanaged_user(unmanaged_user):
	response = build_scim_request(
		"PUT",
		f"/scim/v2/Users/{enc(unmanaged_user)}",
		payload(unmanaged_user, name={"givenName": "PWNED", "familyName": "Takeover"}),
	)
	assert response.code == 404
	assert frappe.db.get_value("User", unmanaged_user, "first_name") == "Unmanaged"
	assert frappe.db.get_value("User", unmanaged_user, "scim_managed") == 0


@pytest.mark.order(332)
def test_delete_cannot_disable_unmanaged_user(unmanaged_user):
	assert build_scim_request("DELETE", f"/scim/v2/Users/{enc(unmanaged_user)}").code == 404
	assert frappe.db.get_value("User", unmanaged_user, "enabled") == 1


@pytest.mark.order(333)
def test_scim_service_user_is_not_a_system_manager():
	roles = frappe.get_all("Has Role", filters={"parent": SCIM_SERVICE_USER_EMAIL}, pluck="role")
	assert "System Manager" not in roles
	assert "Administrator" not in roles


# --------------------------------------------------------------------------
# Attribute mapping round-trip
# --------------------------------------------------------------------------


@pytest.mark.order(340)
def test_put_clears_attribute_omitted_from_full_replace():
	email = unique_scim_email("clear")
	build_scim_request(
		"POST",
		"/scim/v2/Users",
		payload(email, phoneNumbers=[{"type": "work", "value": "555-0100"}]),
	)
	assert frappe.db.get_value("User", email, "phone") == "555-0100"

	response = build_scim_request("PUT", f"/scim/v2/Users/{enc(email)}", payload(email))
	assert response.code == 200
	assert not frappe.db.get_value("User", email, "phone"), "PUT is a full replace"
	cleanup_scim_user(email)


@pytest.mark.order(341)
def test_patch_remove_clears_attribute():
	email = unique_scim_email("remove")
	build_scim_request(
		"POST",
		"/scim/v2/Users",
		payload(email, phoneNumbers=[{"type": "work", "value": "555-0100"}]),
	)
	response = build_scim_request(
		"PATCH",
		f"/scim/v2/Users/{enc(email)}",
		{"schemas": [RFC_PATCH_OP], "Operations": [{"op": "remove", "path": "phoneNumbers"}]},
	)
	assert response.code == 200
	assert not frappe.db.get_value("User", email, "phone")
	cleanup_scim_user(email)


@pytest.mark.order(342)
def test_display_name_round_trips():
	email = unique_scim_email("display")
	response = build_scim_request(
		"POST", "/scim/v2/Users", payload(email, displayName="Ambrosia Picker")
	)
	assert response.code == 201
	assert response.data["displayName"] == "Ambrosia Picker"

	updated = build_scim_request(
		"PUT", f"/scim/v2/Users/{enc(email)}", payload(email, displayName="Updated Display")
	)
	assert updated.data["displayName"] == "Updated Display"
	assert build_scim_request("GET", f"/scim/v2/Users/{enc(email)}").data["displayName"] == (
		"Updated Display"
	)
	cleanup_scim_user(email)


@pytest.mark.order(343)
def test_update_without_name_preserves_first_name():
	"""first_name is mandatory in Frappe, so an update that omits it keeps the current value."""
	email = unique_scim_email("firstname")
	build_scim_request("POST", "/scim/v2/Users", payload(email))
	assert frappe.db.get_value("User", email, "first_name") == "SCIM"

	nameless = payload(email)
	nameless.pop("name")
	response = build_scim_request("PUT", f"/scim/v2/Users/{enc(email)}", nameless)
	assert response.code == 200
	assert frappe.db.get_value("User", email, "first_name") == "SCIM", (
		"an update carrying no givenName must not fall back to the userName local-part"
	)
	cleanup_scim_user(email)


@pytest.mark.order(345)
def test_put_clears_omitted_extension_attribute():
	"""Mapped extension attributes obey full replace exactly as core attributes do."""
	email = unique_scim_email("extclear")
	build_scim_request(
		"POST",
		"/scim/v2/Users",
		payload(
			email,
			phoneNumbers=[{"type": "work", "value": "555-0100"}],
			**{ENTERPRISE_SCHEMA: {"department": "Portland Bakery"}},
		),
	)
	assert frappe.db.get_value("User", email, "location") == "Portland Bakery"

	response = build_scim_request("PUT", f"/scim/v2/Users/{enc(email)}", payload(email))
	assert response.code == 200
	assert not frappe.db.get_value("User", email, "phone")
	assert not frappe.db.get_value("User", email, "location"), (
		"an extension attribute omitted from a full replace must clear like a core one"
	)
	cleanup_scim_user(email)


@pytest.mark.order(344)
def test_put_rejects_username_change_instead_of_discarding_it():
	old_email = unique_scim_email("oldname")
	new_email = unique_scim_email("newname")
	build_scim_request("POST", "/scim/v2/Users", payload(old_email))

	response = build_scim_request("PUT", f"/scim/v2/Users/{enc(old_email)}", payload(new_email))
	assert response.code == 400
	assert response.data["scimType"] == "mutability"
	assert frappe.db.exists("User", old_email)
	assert not frappe.db.exists("User", new_email)
	cleanup_scim_user(old_email)


# --------------------------------------------------------------------------
# Adoption of pre-existing users (opt-in via Do Not Create New User)
# --------------------------------------------------------------------------


@pytest.fixture
def creates_disabled():
	settings = frappe.get_doc("SCIM Settings")
	settings.do_not_create_new_user = 1
	settings.save(ignore_permissions=True)
	frappe.clear_cache(doctype="SCIM Settings")
	yield settings
	settings.reload()
	settings.do_not_create_new_user = 0
	settings.save(ignore_permissions=True)
	frappe.clear_cache(doctype="SCIM Settings")


@pytest.mark.order(370)
def test_existing_user_is_not_adopted_by_default(unmanaged_user):
	"""Without the opt-in, a create colliding with an unmanaged user is refused."""
	response = build_scim_request("POST", "/scim/v2/Users", payload(unmanaged_user))
	assert response.code == 409
	assert response.data["scimType"] == "uniqueness"
	assert frappe.db.get_value("User", unmanaged_user, "scim_managed") == 0


@pytest.mark.order(371)
def test_existing_user_is_adopted_when_creates_are_disabled(unmanaged_user, creates_disabled):
	response = build_scim_request(
		"POST",
		"/scim/v2/Users",
		payload(unmanaged_user, externalId="adopted-1", displayName="Adopted User"),
	)
	assert response.code == 201
	assert response.data["externalId"] == "adopted-1"
	assert frappe.db.get_value("User", unmanaged_user, "scim_managed") == 1
	assert frappe.db.get_value("User", unmanaged_user, "first_name") == "SCIM"

	listed = build_scim_request(
		"GET", "/scim/v2/Users", query={"filter": f'userName eq "{unmanaged_user}"'}
	)
	assert listed.data["totalResults"] == 1


@pytest.mark.order(372)
def test_unknown_user_is_rejected_when_creates_are_disabled(creates_disabled):
	response = build_scim_request(
		"POST", "/scim/v2/Users", payload(unique_scim_email("nocreate"))
	)
	assert response.code == 404


# --------------------------------------------------------------------------
# PATCH path parsing (Entra dialect)
# --------------------------------------------------------------------------


@pytest.mark.order(350)
def test_set_scim_path_handles_complex_filter_without_value_suffix():
	data = {"emails": [{"type": "work", "value": "old@ambrosiapieco.example"}]}
	set_scim_path(data, 'emails[type eq "work"]', {"value": "new@ambrosiapieco.example"})

	assert 'emails[type eq "work"]' not in data, "must not create a literal filter-expression key"
	assert data["emails"] == [{"type": "work", "value": "new@ambrosiapieco.example"}]


@pytest.mark.order(351)
def test_set_scim_path_appends_complex_filter_entry_when_absent():
	data: dict = {}
	set_scim_path(data, 'emails[type eq "work"]', {"value": "new@ambrosiapieco.example"})
	assert data["emails"] == [{"type": "work", "value": "new@ambrosiapieco.example"}]


@pytest.mark.order(352)
def test_set_scim_path_does_not_fabricate_primary():
	data: dict = {"phoneNumbers": []}
	set_scim_path(data, 'phoneNumbers[type eq "mobile"].value', "555-0199")
	assert data["phoneNumbers"] == [{"type": "mobile", "value": "555-0199"}]


# --------------------------------------------------------------------------
# Mapping validation and path predicate
# --------------------------------------------------------------------------


@pytest.mark.order(360)
def test_extension_attribute_named_like_core_is_allowed():
	provider = frappe.get_doc("SAML Login Key", "keycloak")
	original = [row.as_dict() for row in provider.attribute_mappings]
	try:
		provider.set("attribute_mappings", [])
		provider.append(
			"attribute_mappings",
			{
				"source_attribute": "orgActive",
				"user_field": "location",
				"scim_path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:active",
			},
		)
		provider.validate_attribute_mappings()
	finally:
		provider.set("attribute_mappings", original)


@pytest.mark.order(361)
def test_bare_core_attribute_mapping_is_still_rejected():
	provider = frappe.get_doc("SAML Login Key", "keycloak")
	original = [row.as_dict() for row in provider.attribute_mappings]
	try:
		provider.set("attribute_mappings", [])
		provider.append(
			"attribute_mappings",
			{"source_attribute": "active", "user_field": "location", "scim_path": "active"},
		)
		with pytest.raises(frappe.ValidationError):
			provider.validate_attribute_mappings()
	finally:
		provider.set("attribute_mappings", original)


@pytest.mark.order(362)
def test_scim_path_predicate_covers_base_and_subpaths():
	assert is_scim_request_path("/scim/v2")
	assert is_scim_request_path("/scim/v2/")
	assert is_scim_request_path("/scim/v2/Users")
	assert not is_scim_request_path("/scim/v3/Users")
	assert not is_scim_request_path("/scimx/v2/Users")
	assert not is_scim_request_path("/api/method/ping")
