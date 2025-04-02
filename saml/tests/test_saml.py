# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

from urllib.parse import parse_qs, unquote, urlparse

import pytest
import frappe
from onelogin.saml2.auth import OneLogin_Saml2_Auth, OneLogin_Saml2_Utils


@pytest.fixture
def saml_auth():
	saml_key = frappe.get_last_doc("SAML Login Key")
	base_url = "https://example.com"
	acs_path = f"/api/method/frappe.integrations.saml2.acs"

	# Request data format needs to match what the OneLogin library expects
	request_data = {
		"http_host": "example.com",
		"script_name": acs_path,
		"get_data": {"provider": saml_key.name},
		"server_port": 443,
		"https": "on",
	}

	acs_url = f"{base_url}{acs_path}"
	saml_settings = saml_key.get_settings(acs_url)
	return OneLogin_Saml2_Auth(request_data, saml_settings)


def test_saml_request(saml_auth):
	redirect_url = saml_auth.login()
	parsed_url = urlparse(redirect_url)
	query_params = parse_qs(parsed_url.query)
	saml_request = unquote(query_params["SAMLRequest"][0])
	decoded_inflated_string = OneLogin_Saml2_Utils.decode_base64_and_inflate(saml_request)
	assert decoded_inflated_string is not None
