# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import base64
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlparse

import frappe
import pytest
from frappe.utils.password import get_decrypted_password, update_password
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from saml.overrides.user import validate_reset_password
from saml.saml import acs, determine_provider_from_saml_response, get_request_data
from saml.tests.keycloak_helpers import (
	KEYCLOAK_BASE_URL,
	PROVIDER,
	build_saml_auth,
	complete_keycloak_login,
	invoke_acs,
	invoke_login,
	setup_acs_request,
	sync_keycloak_idp_certificate,
	wait_for_keycloak,
)

KEYCLOAK_ISSUER = "http://localhost:8080/realms/frappe"
VALID_SAML_RESPONSE = base64.b64encode(
	f"""<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{KEYCLOAK_ISSUER}</saml:Issuer>
</samlp:Response>""".encode()
).decode()


@pytest.fixture(scope="session")
def keycloak_session():
	wait_for_keycloak()
	sync_keycloak_idp_certificate()


@pytest.mark.order(10)
def test_determine_provider_from_valid_saml_response():
	provider = determine_provider_from_saml_response(VALID_SAML_RESPONSE)
	assert provider == PROVIDER


@pytest.mark.order(11)
def test_determine_provider_from_unknown_issuer():
	unknown_response = base64.b64encode(
		b"""<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://unknown.example.com/realms/other</saml:Issuer>
</samlp:Response>"""
	).decode()
	assert determine_provider_from_saml_response(unknown_response) is None


@pytest.mark.order(12)
def test_determine_provider_from_malformed_response():
	assert determine_provider_from_saml_response("not-valid-base64!!!") is None
	assert determine_provider_from_saml_response(None) is None


@pytest.mark.order(15)
def test_get_request_data_production_mode():
	from frappe.utils import set_request

	original_developer_mode = frappe.conf.get("developer_mode")
	original_host_name = frappe.conf.get("host_name")
	frappe.conf.developer_mode = False
	frappe.conf.host_name = "http://erp.ambrosiapieco.example"

	try:
		set_request(
			method="GET",
			path="/api/method/saml.saml.login",
			headers={"Host": "erp.ambrosiapieco.example"},
		)
		request_data = get_request_data(PROVIDER)
		assert request_data["https"] == "on"
		assert request_data["http_host"] == "erp.ambrosiapieco.example"
		assert "server_port" not in request_data
	finally:
		frappe.conf.developer_mode = original_developer_mode
		if original_host_name is not None:
			frappe.conf.host_name = original_host_name
		elif hasattr(frappe.conf, "host_name"):
			del frappe.conf.host_name


@pytest.mark.order(16)
def test_get_request_data_developer_mode():
	from frappe.utils import set_request

	original_developer_mode = frappe.conf.get("developer_mode")
	original_host_name = frappe.conf.get("host_name")
	frappe.conf.developer_mode = True
	frappe.conf.host_name = "http://localhost:8000"

	try:
		set_request(
			method="GET",
			path="/api/method/saml.saml.login",
			headers={"Host": "localhost:8000"},
		)
		frappe.local.request.environ["SERVER_PORT"] = "8000"
		request_data = get_request_data(PROVIDER)
		assert request_data["https"] == "off"
		assert request_data["http_host"] == "localhost:8000"
		assert request_data["server_port"] == "8000"
	finally:
		frappe.conf.developer_mode = original_developer_mode
		if original_host_name is not None:
			frappe.conf.host_name = original_host_name
		elif hasattr(frappe.conf, "host_name"):
			del frappe.conf.host_name


@pytest.mark.order(18)
def test_validate_reset_password_allows_new_user():
	user = frappe.new_doc("User")
	user.email = "new.hire@ambrosiapieco.example"
	validate_reset_password(user)


@pytest.mark.order(19)
def test_validate_reset_password_allows_non_saml_user():
	user = frappe.get_doc("User", "warehouse@ambrosiapieco.example")
	original = user.saml_managed
	user.saml_managed = False
	try:
		validate_reset_password(user)
	finally:
		user.saml_managed = original


@pytest.mark.order(20)
def test_validate_reset_password_blocks_saml_user():
	saml_key = frappe.get_doc("SAML Login Key", PROVIDER)
	original = saml_key.disallow_password_update
	saml_key.disallow_password_update = True
	saml_key.save(ignore_permissions=True)

	user = frappe.get_doc("User", "saml.existing@ambrosiapieco.example")
	user.saml_managed = True
	user._User__new_password = "should-not-apply"

	try:
		with pytest.raises(frappe.exceptions.ValidationError) as exc_info:
			validate_reset_password(user)
		assert "Password reset is not allowed" in str(exc_info.value)
	finally:
		saml_key.disallow_password_update = original
		saml_key.save(ignore_permissions=True)
		user._User__new_password = None


@pytest.mark.order(30)
def test_login_generates_redirect_to_keycloak(keycloak_session):
	response = invoke_login(PROVIDER)
	assert response["type"] == "redirect"
	parsed_url = urlparse(response["location"])
	assert KEYCLOAK_BASE_URL in f"{parsed_url.scheme}://{parsed_url.netloc}"
	query_params = parse_qs(parsed_url.query)
	saml_request = unquote(query_params["SAMLRequest"][0])
	decoded = OneLogin_Saml2_Utils.decode_base64_and_inflate(saml_request)
	if isinstance(decoded, bytes):
		decoded = decoded.decode()
	assert "AuthnRequest" in decoded
	assert "RequestedAuthnContext" not in decoded


@pytest.mark.order(35)
def test_acs_creates_new_user_from_keycloak(keycloak_session):
	email = "picker@ambrosiapieco.example"
	if frappe.db.exists("User", email):
		frappe.delete_doc("User", email, force=True, ignore_permissions=True)

	saml_response, relay_state, acs_url = complete_keycloak_login("picker", "apc-picker")
	invoke_acs(saml_response, relay_state)

	assert frappe.db.exists("User", email)
	user = frappe.get_doc("User", email)
	assert user.saml_managed
	assert user.first_name == "Orchard"
	assert user.last_name == "Picker"


@pytest.mark.order(36)
def test_acs_extracts_user_attributes_from_keycloak(keycloak_session):
	email = "kb.contributor@ambrosiapieco.example"
	saml_response, relay_state, acs_url = complete_keycloak_login(
		"kb.contributor", "apc-kb-contributor"
	)
	invoke_acs(saml_response, relay_state)

	user = frappe.get_doc("User", email)
	assert user.first_name == "Knowledge"
	assert user.last_name == "Contributor"


@pytest.mark.order(40)
def test_acs_marks_existing_user_saml_managed(keycloak_session):
	email = "warehouse@ambrosiapieco.example"
	user = frappe.get_doc("User", email)
	user.saml_managed = False
	user.save(ignore_permissions=True)
	update_password(email, "local-password")

	saml_response, relay_state, acs_url = complete_keycloak_login("warehouse", "apc-warehouse")
	invoke_acs(saml_response, relay_state)

	user.reload()
	assert user.saml_managed
	assert not get_decrypted_password("User", email, raise_exception=False)


@pytest.mark.order(41)
def test_acs_preserves_existing_saml_managed_user(keycloak_session):
	email = "saml.existing@ambrosiapieco.example"
	user = frappe.get_doc("User", email)
	assert user.saml_managed

	saml_response, relay_state, acs_url = complete_keycloak_login(
		"saml.existing", "apc-saml-existing"
	)
	invoke_acs(saml_response, relay_state)

	user.reload()
	assert user.saml_managed


@pytest.mark.order(55)
def test_acs_applies_role_from_keycloak(keycloak_session):
	email = "saml.admin@ambrosiapieco.example"
	if not frappe.db.exists("User", email):
		user = frappe.new_doc("User")
		user.update(
			{
				"email": email,
				"first_name": "SAML",
				"last_name": "Admin",
				"enabled": True,
				"send_welcome_email": False,
			}
		)
		user.insert(ignore_permissions=True)

	saml_response, relay_state, acs_url = complete_keycloak_login("saml.admin", "apc-saml-admin")
	invoke_acs(saml_response, relay_state)

	roles = {row.role for row in frappe.get_doc("User", email).roles}
	assert "System Manager" in roles


@pytest.mark.order(56)
def test_acs_applies_role_profile_from_keycloak(keycloak_session):
	email = "kb.contributor@ambrosiapieco.example"
	saml_response, relay_state, acs_url = complete_keycloak_login(
		"kb.contributor", "apc-kb-contributor"
	)
	invoke_acs(saml_response, relay_state)

	user = frappe.get_doc("User", email)
	assert user.role_profile_name == "Knowledge Base"


@pytest.mark.order(57)
def test_acs_removes_unmatched_roles_when_match_enabled(keycloak_session):
	email = "kb.contributor@ambrosiapieco.example"
	frappe.set_user("Administrator")
	user = frappe.get_doc("User", email)
	user.append("roles", {"role": "Purchase User"})
	user.save(ignore_permissions=True)

	saml_key = frappe.get_doc("SAML Login Key", PROVIDER)
	original_match = saml_key.match_saml_roles
	saml_key.match_saml_roles = True
	saml_key.save(ignore_permissions=True)

	try:
		saml_response, relay_state, acs_url = complete_keycloak_login(
			"kb.contributor", "apc-kb-contributor"
		)
		invoke_acs(saml_response, relay_state)
		roles = {row.role for row in frappe.get_doc("User", email).roles}
		assert "Purchase User" not in roles
	finally:
		saml_key.match_saml_roles = original_match
		saml_key.save(ignore_permissions=True)


@pytest.mark.order(60)
def test_acs_determines_provider_from_query_param(keycloak_session):
	saml_response, relay_state, acs_url = complete_keycloak_login("warehouse", "apc-warehouse")

	with patch("saml.saml.determine_provider_from_saml_response", return_value=None):
		invoke_acs(saml_response, relay_state)

	assert frappe.local.response.get("type") == "redirect"


@pytest.mark.order(61)
def test_acs_determines_provider_from_saml_issuer(keycloak_session):
	from frappe.auth import CookieManager, LoginManager

	saml_response, relay_state, acs_url = complete_keycloak_login("warehouse", "apc-warehouse")

	setup_acs_request(saml_response, relay_state, provider=None)
	frappe.local.cookie_manager = CookieManager()
	frappe.local.login_manager = LoginManager()
	frappe.response = frappe._dict()
	frappe.set_user("Guest")
	acs()

	assert frappe.local.response.get("type") == "redirect"
	assert frappe.db.exists("User", "warehouse@ambrosiapieco.example")
