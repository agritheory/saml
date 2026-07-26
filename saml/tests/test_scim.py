# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

import pytest

import frappe

from saml.saml.scim_constants import SCIM_PATCH_OP_SCHEMA, SCIM_USER_SCHEMA, scim_active_to_enabled
from saml.saml.identity_mappings import sync_provider_roles_from_scim
from saml.saml.scim_paths import deep_get, extract_scim_path
from saml.saml.scim_provisioning import (
	SCIMProvisioningError,
	apply_patch_operation,
	parse_filter_expression,
	scim_to_user_data,
	set_scim_path,
	user_to_scim,
)
from saml.tests.scim_helpers import unique_scim_email


@pytest.mark.order(100)
def test_scim_to_user_data_requires_email():
	settings = frappe.get_doc("SCIM Settings")
	with pytest.raises(SCIMProvisioningError) as exc:
		scim_to_user_data({}, settings)
	assert exc.value.scim_type == "invalidValue"


@pytest.mark.order(101)
def test_scim_to_user_data_rejects_non_email_username():
	settings = frappe.get_doc("SCIM Settings")
	with pytest.raises(SCIMProvisioningError) as exc:
		scim_to_user_data({"userName": "not-an-email"}, settings)
	assert exc.value.scim_type == "invalidValue"


@pytest.mark.order(102)
def test_scim_to_user_data_maps_core_fields():
	settings = frappe.get_doc("SCIM Settings")
	user_data = scim_to_user_data(
		{
			"userName": "scim.core@ambrosiapieco.example",
			"externalId": "ext-123",
			"name": {"givenName": "SCIM", "familyName": "User", "middleName": "Middle"},
			"active": False,
			"phoneNumbers": [
				{"type": "work", "value": "555-0100"},
				{"type": "mobile", "value": "555-0101"},
			],
			"preferredLanguage": "en-US",
		},
		settings,
	)
	assert user_data["email"] == "scim.core@ambrosiapieco.example"
	assert user_data["scim_external_id"] == "ext-123"
	assert user_data["first_name"] == "SCIM"
	assert user_data["last_name"] == "User"
	assert user_data["middle_name"] == "Middle"
	assert user_data["enabled"] == 0
	assert user_data["phone"] == "555-0100"
	assert user_data["mobile_no"] == "555-0101"
	assert user_data["language"] == "en"


@pytest.mark.order(113)
def test_scim_active_to_enabled_handles_string_booleans():
	assert scim_active_to_enabled(True) == 1
	assert scim_active_to_enabled(False) == 0
	assert scim_active_to_enabled("False") == 0
	assert scim_active_to_enabled("false") == 0
	assert scim_active_to_enabled("True") == 1
	assert scim_active_to_enabled(None) == 1


@pytest.mark.order(114)
def test_scim_to_user_data_deactivates_entra_string_active():
	settings = frappe.get_doc("SCIM Settings")
	user_data = scim_to_user_data(
		{"userName": "scim.inactive@ambrosiapieco.example", "active": "False"},
		settings,
	)
	assert user_data["enabled"] == 0


@pytest.mark.order(103)
def test_extract_scim_path_supports_extension_attributes():
	data = {
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
			"department": "Engineering",
		}
	}
	value = extract_scim_path(
		data,
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
	)
	assert value == "Engineering"
	assert deep_get(data, "name.givenName") is None


@pytest.mark.order(104)
def test_parse_filter_expression():
	field, value = parse_filter_expression('userName eq "scim.user@ambrosiapieco.example"')
	assert field == "userName"
	assert value == "scim.user@ambrosiapieco.example"

	field, value = parse_filter_expression('externalId eq "abc-123"')
	assert field == "externalId"
	assert value == "abc-123"


@pytest.mark.order(105)
def test_parse_filter_expression_rejects_unsupported_filters():
	with pytest.raises(SCIMProvisioningError) as exc:
		parse_filter_expression('displayName co "foo"')
	assert exc.value.scim_type == "invalidFilter"


@pytest.mark.order(106)
def test_patch_operation_replace_active():
	scim_data = {
		"schemas": [SCIM_USER_SCHEMA],
		"userName": "scim.patch@ambrosiapieco.example",
		"active": True,
	}
	apply_patch_operation(
		scim_data,
		{"op": "replace", "value": {"active": False}},
	)
	assert scim_data["active"] is False


@pytest.mark.order(107)
def test_patch_operation_replace_nested_name():
	scim_data = {"name": {"givenName": "Old", "familyName": "Name"}}
	apply_patch_operation(
		scim_data,
		{"op": "replace", "path": "name.givenName", "value": "New"},
	)
	assert scim_data["name"]["givenName"] == "New"


@pytest.mark.order(108)
def test_patch_operation_value_filter_email():
	scim_data = {"emails": []}
	set_scim_path(scim_data, 'emails[type eq "work"].value', "work@ambrosiapieco.example")
	assert scim_data["emails"][0]["type"] == "work"
	assert scim_data["emails"][0]["value"] == "work@ambrosiapieco.example"


@pytest.mark.order(109)
def test_user_to_scim_separates_id_and_external_id(db_instance):
	email = unique_scim_email("shape")
	user = frappe.get_doc(
		{
			"doctype": "User",
			"email": email,
			"first_name": "Shape",
			"last_name": "Test",
			"enabled": 1,
			"send_welcome_email": 0,
			"scim_managed": 1,
			"scim_external_id": "external-shape-id",
		}
	)
	user.insert(ignore_permissions=True)

	resource = user_to_scim(user)
	assert resource["id"] == email
	assert resource["externalId"] == "external-shape-id"
	assert resource["meta"]["resourceType"] == "User"
	assert resource["meta"]["created"].endswith("Z")
	assert "T" in resource["meta"]["created"]

	frappe.delete_doc("User", email, force=1, ignore_permissions=True)


@pytest.mark.order(111)
def test_scim_to_user_data_maps_fixture_attribute_mapping():
	settings = frappe.get_doc("SCIM Settings")
	user_data = scim_to_user_data(
		{
			"userName": "scim.dept@ambrosiapieco.example",
			"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
				"department": "Portland Bakery",
			},
		},
		settings,
	)
	assert user_data["location"] == "Portland Bakery"


@pytest.mark.order(112)
def test_user_to_scim_includes_fixture_attribute_mapping(db_instance):
	email = unique_scim_email("location")
	user = frappe.get_doc(
		{
			"doctype": "User",
			"email": email,
			"first_name": "Location",
			"last_name": "Test",
			"location": "Portland Bakery",
			"enabled": 1,
			"send_welcome_email": 0,
			"scim_managed": 1,
		}
	)
	user.insert(ignore_permissions=True)

	resource = user_to_scim(user)
	enterprise = resource["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]
	assert enterprise["department"] == "Portland Bakery"

	frappe.delete_doc("User", email, force=1, ignore_permissions=True)


@pytest.mark.order(110)
def test_sync_scim_roles_adds_and_removes_mapped_roles(db_instance):
	provider = frappe.get_doc("SAML Login Key", "keycloak")
	email = unique_scim_email("roles")
	user = frappe.get_doc(
		{
			"doctype": "User",
			"email": email,
			"first_name": "Role",
			"last_name": "Sync",
			"enabled": 1,
			"send_welcome_email": 0,
			"user_type": "System User",
			"scim_managed": 1,
		}
	)
	user.insert(ignore_permissions=True)
	user.add_roles("Report Manager")

	sync_provider_roles_from_scim(
		user,
		{"customRoles": ["System Administrator"]},
		provider,
	)
	user.reload()
	roles = {row.role for row in user.roles}
	assert "System Manager" in roles
	assert "Report Manager" not in roles

	frappe.delete_doc("User", email, force=1, ignore_permissions=True)
