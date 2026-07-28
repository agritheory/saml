# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

from urllib.parse import quote

import frappe
import pytest

from saml.saml.scim_constants import (
	SCIM_LIST_RESPONSE_SCHEMA,
	SCIM_PATCH_OP_SCHEMA,
	SCIM_USER_SCHEMA,
)
from saml.saml.scim_renderer import SCIMApiResponse
from saml.tests.scim_helpers import (
	build_scim_request,
	cleanup_scim_user,
	unique_scim_email,
)


def scim_user_payload(email: str, external_id: str | None = None) -> dict:
	payload = {
		"schemas": [SCIM_USER_SCHEMA],
		"userName": email,
		"name": {"givenName": "SCIM", "familyName": "API"},
		"active": True,
	}
	if external_id:
		payload["externalId"] = external_id
	return payload


@pytest.mark.order(200)
def test_service_provider_config():
	response = build_scim_request("GET", "/scim/v2/ServiceProviderConfig")
	assert response.code == 200
	assert response.data["patch"]["supported"] is True
	assert response.data["filter"]["supported"] is True
	assert response.data["bulk"]["supported"] is False


@pytest.mark.order(201)
def test_create_user_returns_201():
	email = unique_scim_email("create")
	response = build_scim_request("POST", "/scim/v2/Users", scim_user_payload(email, "ext-create"))
	assert response.code == 201
	assert response.data["userName"] == email
	assert response.data["id"] == email
	assert response.data["externalId"] == "ext-create"
	assert frappe.db.get_value("User", email, "scim_managed") == 1
	cleanup_scim_user(email)


@pytest.mark.order(202)
def test_create_duplicate_user_returns_409():
	email = unique_scim_email("duplicate")
	build_scim_request("POST", "/scim/v2/Users", scim_user_payload(email))
	response = build_scim_request("POST", "/scim/v2/Users", scim_user_payload(email))
	assert response.code == 409
	assert response.data["scimType"] == "uniqueness"
	cleanup_scim_user(email)


@pytest.mark.order(203)
def test_filter_users_by_username():
	email = unique_scim_email("filter")
	build_scim_request("POST", "/scim/v2/Users", scim_user_payload(email))
	filter_query = {"filter": f'userName eq "{email}"'}
	response = build_scim_request("GET", "/scim/v2/Users", query=filter_query)
	assert response.code == 200
	assert response.data["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
	assert response.data["totalResults"] == 1
	assert response.data["Resources"][0]["userName"] == email
	cleanup_scim_user(email)


@pytest.mark.order(204)
def test_filter_users_by_external_id():
	email = unique_scim_email("external")
	external_id = "external-filter-id"
	build_scim_request("POST", "/scim/v2/Users", scim_user_payload(email, external_id))
	filter_query = {"filter": f'externalId eq "{external_id}"'}
	response = build_scim_request("GET", "/scim/v2/Users", query=filter_query)
	assert response.code == 200
	assert response.data["totalResults"] == 1
	assert response.data["Resources"][0]["externalId"] == external_id
	cleanup_scim_user(email)


@pytest.mark.order(205)
def test_okta_sequence_put_and_patch_deactivate():
	email = unique_scim_email("okta")
	create_response = build_scim_request(
		"POST", "/scim/v2/Users", scim_user_payload(email, "okta-ext")
	)
	assert create_response.code == 201

	update_payload = scim_user_payload(email, "okta-ext")
	update_payload["name"]["givenName"] = "Updated"
	put_response = build_scim_request(
		"PUT",
		f"/scim/v2/Users/{quote(email, safe='')}",
		update_payload,
	)
	assert put_response.code == 200
	assert put_response.data["name"]["givenName"] == "Updated"

	patch_response = build_scim_request(
		"PATCH",
		f"/scim/v2/Users/{quote(email, safe='')}",
		{
			"schemas": [SCIM_PATCH_OP_SCHEMA],
			"Operations": [{"op": "replace", "value": {"active": False}}],
		},
	)
	assert patch_response.code == 200
	assert patch_response.data["active"] is False
	assert frappe.db.get_value("User", email, "enabled") == 0
	cleanup_scim_user(email)


@pytest.mark.order(206)
def test_entra_sequence_patch_operations_and_delete():
	email = unique_scim_email("entra")
	external_id = "entra-ext"
	build_scim_request("POST", "/scim/v2/Users", scim_user_payload(email, external_id))

	patch_response = build_scim_request(
		"PATCH",
		f"/scim/v2/Users/{quote(email, safe='')}",
		{
			"schemas": [SCIM_PATCH_OP_SCHEMA],
			"Operations": [
				{"op": "replace", "path": "name.givenName", "value": "Entra"},
				{"op": "replace", "path": 'emails[type eq "work"].value', "value": email},
			],
		},
	)
	assert patch_response.code == 200
	assert patch_response.data["name"]["givenName"] == "Entra"

	delete_response = build_scim_request("DELETE", f"/scim/v2/Users/{quote(email, safe='')}")
	assert isinstance(delete_response, SCIMApiResponse)
	assert delete_response.code == 204
	assert frappe.db.get_value("User", email, "enabled") == 0
	cleanup_scim_user(email)


@pytest.mark.order(207)
def test_create_user_applies_fixture_attribute_mapping():
	email = unique_scim_email("department")
	payload = scim_user_payload(email)
	payload["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"] = {
		"department": "Portland Bakery",
	}
	response = build_scim_request("POST", "/scim/v2/Users", payload)
	assert response.code == 201
	assert (
		response.data["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["department"]
		== "Portland Bakery"
	)
	assert frappe.db.get_value("User", email, "location") == "Portland Bakery"
	cleanup_scim_user(email)


@pytest.mark.order(208)
def test_schemas_and_resource_types():
	schemas = build_scim_request("GET", "/scim/v2/Schemas")
	assert schemas.code == 200
	assert schemas.data["totalResults"] == 2

	resource_types = build_scim_request("GET", "/scim/v2/ResourceTypes")
	assert resource_types.code == 200
	assert resource_types.data["Resources"][0]["name"] == "User"


@pytest.mark.order(209)
def test_invalid_token_returns_401():
	with pytest.raises(SCIMApiResponse) as exc:
		build_scim_request("GET", "/scim/v2/ServiceProviderConfig", token="invalid-token")
	assert exc.value.code == 401
	assert exc.value.data["detail"] == "Invalid token"
