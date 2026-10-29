# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

"""SCIM table mapping tests.

Fixture chain (installed by saml.tests.setup.before_test, not conftest):

- tests/data/saml_login_key.json — Keycloak provider table_mappings row targets
  User.social_logins (value_field userid, scope provider=keycloak).
- setup.ensure_scim_test_settings — SCIM enabled, identity_provider=keycloak.
- setup.ensure_keycloak_test_files — realm-export.json + scim-keycloak-config.json.
- Stock Frappe User Social Login child table; no custom test doctype.

Integration tests POST/PUT/PATCH SCIM Users and assert rows on user.social_logins.
Planner tests (order 121–125) exercise pure dict reconciliation without HTTP.
Validation tests (order 117–120) mutate the Keycloak provider and restore it.
"""

from urllib.parse import quote

import frappe
import pytest

from saml.saml.credential_sync import (
	REVOCATION_SENTINEL,
	build_revoked_value,
	get_table_sync_configs,
	is_revoked_value,
	parse_table_sync_values,
	plan_table_sync,
)
from saml.saml.scim_constants import (
	SCIM_ENTERPRISE_USER_SCHEMA,
	SCIM_PATCH_OP_SCHEMA,
	SCIM_USER_SCHEMA,
)
from saml.saml.scim_provisioning import user_to_scim
from saml.tests.scim_helpers import build_scim_request, cleanup_scim_user, unique_scim_email

EMPLOYEE_NUMBER_PATH = f"{SCIM_ENTERPRISE_USER_SCHEMA}:employeeNumber"
KEYCLOAK_PROVIDER = "keycloak"


def keycloak_table_sync_config():
	configs = get_table_sync_configs(frappe.get_doc("SAML Login Key", KEYCLOAK_PROVIDER))
	assert configs
	return configs[0]


def scim_user_payload(email: str, employee_numbers: str | None) -> dict:
	payload = {
		"schemas": [SCIM_USER_SCHEMA],
		"userName": email,
		"name": {"givenName": "SCIM", "familyName": "Provisioned"},
		"active": True,
	}
	if employee_numbers is not None:
		payload[SCIM_ENTERPRISE_USER_SCHEMA] = {"employeeNumber": employee_numbers}
	return payload


def keycloak_social_login_rows(email: str) -> list[tuple[str, str]]:
	user = frappe.get_doc("User", email)
	return [
		(row.userid, row.provider) for row in user.social_logins if row.provider == KEYCLOAK_PROVIDER
	]


def active_keycloak_userids(email: str) -> set[str]:
	return {userid for userid, _ in keycloak_social_login_rows(email) if not is_revoked_value(userid)}


def snapshot_keycloak_table_mappings(provider):
	return [row.as_dict() for row in provider.table_mappings]


def restore_keycloak_table_mappings(original):
	provider = frappe.get_doc("SAML Login Key", KEYCLOAK_PROVIDER)
	provider.table_mappings = []
	for row in original:
		provider.append("table_mappings", row)
	provider.save(ignore_permissions=True)


@pytest.mark.order(117)
def test_table_sync_rejects_non_table_user_field():
	provider = frappe.get_doc("SAML Login Key", KEYCLOAK_PROVIDER)
	original = snapshot_keycloak_table_mappings(provider)
	provider.table_mappings[0].user_table_field = "first_name"
	with pytest.raises(frappe.ValidationError):
		provider.save(ignore_permissions=True)
	restore_keycloak_table_mappings(original)


@pytest.mark.order(118)
def test_table_sync_rejects_core_scim_source_attribute():
	provider = frappe.get_doc("SAML Login Key", KEYCLOAK_PROVIDER)
	original = snapshot_keycloak_table_mappings(provider)
	provider.table_mappings[0].scim_path = "userName"
	with pytest.raises(frappe.ValidationError):
		provider.save(ignore_permissions=True)
	restore_keycloak_table_mappings(original)


@pytest.mark.order(119)
def test_table_sync_rejects_blank_delimiter():
	provider = frappe.get_doc("SAML Login Key", KEYCLOAK_PROVIDER)
	original = snapshot_keycloak_table_mappings(provider)
	provider.table_mappings[0].delimiter = ""
	with pytest.raises(frappe.ValidationError):
		provider.save(ignore_permissions=True)
	restore_keycloak_table_mappings(original)


@pytest.mark.order(120)
def test_attribute_mapping_rejects_child_table_user_field():
	provider = frappe.get_doc("SAML Login Key", KEYCLOAK_PROVIDER)
	original_mappings = [row.as_dict() for row in provider.attribute_mappings]
	provider.append(
		"attribute_mappings",
		{
			"source_attribute": "employeeNumber",
			"user_field": "social_logins",
			"scim_path": EMPLOYEE_NUMBER_PATH,
		},
	)
	with pytest.raises(frappe.ValidationError):
		provider.save(ignore_permissions=True)
	provider.reload()
	provider.attribute_mappings = []
	for row in original_mappings:
		provider.append("attribute_mappings", row)
	provider.save(ignore_permissions=True)


@pytest.mark.order(121)
def test_parse_table_sync_values_splits_and_dedupes():
	assert parse_table_sync_values("APC-1, APC-2, APC-1") == ["APC-1", "APC-2"]
	assert parse_table_sync_values(["APC-3", "APC-4"]) == ["APC-3", "APC-4"]
	assert parse_table_sync_values(None) == []


@pytest.mark.order(122)
def test_plan_table_sync_issues_new_social_login_rows():
	config = keycloak_table_sync_config()
	plan = plan_table_sync(["APC-1001"], [], config)
	assert plan.issue == ["APC-1001"]
	assert plan.revoke == []


@pytest.mark.order(123)
def test_plan_table_sync_revokes_removed_social_login_rows():
	config = keycloak_table_sync_config()
	rows = [{"userid": "APC-1001", "provider": KEYCLOAK_PROVIDER}]
	plan = plan_table_sync([], rows, config)
	assert plan.issue == []
	assert len(plan.revoke) == 1
	assert plan.revoke[0][0] == "APC-1001"
	assert REVOCATION_SENTINEL in plan.revoke[0][1]


@pytest.mark.order(124)
def test_plan_table_sync_leaves_other_provider_social_login_rows():
	config = keycloak_table_sync_config()
	rows = [{"userid": "LOCAL-LOCKER", "provider": "local"}]
	plan = plan_table_sync(["APC-1001"], rows, config)
	assert plan.issue == ["APC-1001"]
	assert plan.revoke == []


@pytest.mark.order(125)
def test_plan_table_sync_idempotent_when_unchanged():
	config = keycloak_table_sync_config()
	rows = [{"userid": "APC-1001", "provider": KEYCLOAK_PROVIDER}]
	plan = plan_table_sync(["APC-1001"], rows, config)
	assert plan.is_empty


@pytest.mark.order(130)
def test_scim_post_appends_keycloak_social_login_row():
	email = unique_scim_email("social-login-create")
	response = build_scim_request("POST", "/scim/v2/Users", scim_user_payload(email, "APC-2001"))
	assert response.code == 201
	assert active_keycloak_userids(email) == {"APC-2001"}
	user = frappe.get_doc("User", email)
	assert any(
		row.provider == KEYCLOAK_PROVIDER and row.userid == "APC-2001" for row in user.social_logins
	)
	cleanup_scim_user(email)


@pytest.mark.order(131)
def test_scim_put_replaces_keycloak_social_login_set():
	email = unique_scim_email("social-login-replace")
	build_scim_request("POST", "/scim/v2/Users", scim_user_payload(email, "APC-2101"))
	response = build_scim_request(
		"PUT",
		f"/scim/v2/Users/{quote(email, safe='')}",
		scim_user_payload(email, "APC-2102"),
	)
	assert response.code == 200
	assert active_keycloak_userids(email) == {"APC-2102"}
	cleanup_scim_user(email)


@pytest.mark.order(132)
def test_scim_patch_updates_keycloak_social_login_set():
	email = unique_scim_email("social-login-patch")
	build_scim_request("POST", "/scim/v2/Users", scim_user_payload(email, "APC-2201"))
	response = build_scim_request(
		"PATCH",
		f"/scim/v2/Users/{quote(email, safe='')}",
		{
			"schemas": [SCIM_PATCH_OP_SCHEMA],
			"Operations": [
				{
					"op": "replace",
					"path": EMPLOYEE_NUMBER_PATH,
					"value": "APC-2202",
				}
			],
		},
	)
	assert response.code == 200
	assert active_keycloak_userids(email) == {"APC-2202"}
	cleanup_scim_user(email)


@pytest.mark.order(133)
def test_scim_post_issues_multiple_keycloak_social_login_rows():
	email = unique_scim_email("social-login-multi")
	response = build_scim_request(
		"POST", "/scim/v2/Users", scim_user_payload(email, "APC-2301,APC-2302")
	)
	assert response.code == 201
	assert active_keycloak_userids(email) == {"APC-2301", "APC-2302"}
	cleanup_scim_user(email)


@pytest.mark.order(134)
def test_scim_post_returns_409_when_userid_assigned_elsewhere():
	holder = unique_scim_email("social-login-holder")
	claimant = unique_scim_email("social-login-claimant")
	build_scim_request("POST", "/scim/v2/Users", scim_user_payload(holder, "APC-2401"))
	response = build_scim_request("POST", "/scim/v2/Users", scim_user_payload(claimant, "APC-2401"))
	assert response.code == 409
	assert response.data["scimType"] == "uniqueness"
	cleanup_scim_user(holder)
	cleanup_scim_user(claimant)


@pytest.mark.order(135)
def test_scim_empty_attribute_revokes_keycloak_social_login_rows():
	email = unique_scim_email("social-login-revoke")
	build_scim_request("POST", "/scim/v2/Users", scim_user_payload(email, "APC-2501"))
	response = build_scim_request(
		"PUT",
		f"/scim/v2/Users/{quote(email, safe='')}",
		scim_user_payload(email, ""),
	)
	assert response.code == 200
	assert active_keycloak_userids(email) == set()
	rows = keycloak_social_login_rows(email)
	assert len(rows) == 1
	assert REVOCATION_SENTINEL in rows[0][0]
	cleanup_scim_user(email)


@pytest.mark.order(136)
def test_scim_absent_attribute_leaves_social_login_rows_untouched():
	email = unique_scim_email("social-login-absent")
	build_scim_request("POST", "/scim/v2/Users", scim_user_payload(email, "APC-2601"))
	response = build_scim_request(
		"PUT",
		f"/scim/v2/Users/{quote(email, safe='')}",
		{
			"schemas": [SCIM_USER_SCHEMA],
			"userName": email,
			"name": {"givenName": "SCIM", "familyName": "Provisioned"},
			"active": True,
		},
	)
	assert response.code == 200
	assert active_keycloak_userids(email) == {"APC-2601"}
	cleanup_scim_user(email)


@pytest.mark.order(137)
def test_other_provider_social_login_row_survives_keycloak_sync():
	email = unique_scim_email("social-login-other-provider")
	build_scim_request("POST", "/scim/v2/Users", scim_user_payload(email, "APC-2701"))
	user = frappe.get_doc("User", email)
	user.append(
		"social_logins",
		{"provider": "local", "userid": "LOCAL-LOCKER"},
	)
	user.save(ignore_permissions=True)
	response = build_scim_request(
		"PUT",
		f"/scim/v2/Users/{quote(email, safe='')}",
		scim_user_payload(email, "APC-2702"),
	)
	assert response.code == 200
	assert active_keycloak_userids(email) == {"APC-2702"}
	user = frappe.get_doc("User", email)
	assert any(row.userid == "LOCAL-LOCKER" for row in user.social_logins)
	cleanup_scim_user(email)


@pytest.mark.order(141)
def test_patch_remove_leaves_keycloak_social_login_rows_untouched():
	email = unique_scim_email("social-login-remove")
	build_scim_request("POST", "/scim/v2/Users", scim_user_payload(email, "APC-3101"))
	response = build_scim_request(
		"PATCH",
		f"/scim/v2/Users/{quote(email, safe='')}",
		{
			"schemas": [SCIM_PATCH_OP_SCHEMA],
			"Operations": [{"op": "remove", "path": EMPLOYEE_NUMBER_PATH}],
		},
	)
	assert response.code == 200
	assert active_keycloak_userids(email) == {"APC-3101"}
	cleanup_scim_user(email)


@pytest.mark.order(142)
def test_get_user_returns_outbound_social_login_userids():
	email = unique_scim_email("social-login-get")
	build_scim_request("POST", "/scim/v2/Users", scim_user_payload(email, "APC-3201"))
	response = build_scim_request("GET", f"/scim/v2/Users/{quote(email, safe='')}")
	assert response.code == 200
	assert response.data[SCIM_ENTERPRISE_USER_SCHEMA]["employeeNumber"] == "APC-3201"
	user = frappe.get_doc("User", email)
	resource = user_to_scim(user)
	assert resource[SCIM_ENTERPRISE_USER_SCHEMA]["employeeNumber"] == "APC-3201"
	cleanup_scim_user(email)


@pytest.mark.order(143)
def test_revoked_value_helper():
	value = build_revoked_value("APC-9999")
	assert is_revoked_value(value)
	assert not is_revoked_value("APC-9999")
