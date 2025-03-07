# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import json
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import pytest
import frappe
from onelogin.saml2.auth import OneLogin_Saml2_Auth, OneLogin_Saml2_Utils


@pytest.fixture
def saml_auth():
	settings_file = Path(frappe.get_app_path("saml")) / "tests" / "settings.json"
	settings_info = json.loads(settings_file.read_text())
	saml_key = frappe.get_doc(settings_info).insert()

	# Create a fully qualified URL - the library requires an absolute URL
	# with proper scheme, host, and path
	base_url = "https://example.com"
	acs_path = f"/api/method/frappe.integrations.saml2.acs"
	acs_url = f"{base_url}{acs_path}"

	saml_settings = {
		"sp": {
			"entityId": saml_key.sp_entity_id,
			"assertionConsumerService": {
				"url": acs_url,
				"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
			},
			"privateKey": saml_key.get_password("sp_private_key"),
			"x509cert": saml_key.sp_x509cert,
		},
		"idp": {
			"entityId": saml_key.idp_entity_id,
			"singleSignOnService": {
				"url": saml_key.idp_sso_url,
				"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
			"x509cert": saml_key.idp_x509cert,
		},
		"security": {
			"authnRequestsSigned": True,
			"signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			"digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
			"rejectUnsolicitedResponsesWithInResponseTo": False,
		},
		"debug": True,
		"strict": False,
	}

	# Request data format needs to match what the OneLogin library expects
	request_data = {
		"http_host": "example.com",
		"script_name": acs_path,
		"get_data": {"provider": saml_key.name},
		"server_port": 443,
		"https": "on",
	}

	return OneLogin_Saml2_Auth(request_data, saml_settings)


def test_saml_request(saml_auth):
	redirect_url = saml_auth.login()
	parsed_url = urlparse(redirect_url)
	query_params = parse_qs(parsed_url.query)
	saml_request = unquote(query_params["SAMLRequest"][0])
	assert OneLogin_Saml2_Utils.decode_base64_and_inflate(saml_request)
