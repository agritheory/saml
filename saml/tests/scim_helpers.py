# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

import json
from urllib.parse import urlencode

import frappe
from werkzeug.datastructures import ImmutableMultiDict

from saml.install import ensure_scim_service_user, ensure_scim_settings
from saml.saml.scim_constants import SCIM_CONTENT_TYPE
from saml.saml.scim_provisioning import SCIMProvisioningError
from saml.saml.scim_renderer import (
	authenticate_scim_token,
	dispatch_scim_request,
	provisioning_error_response,
)


TEST_SCIM_TOKEN = "test-scim-bearer-token"


def setup_scim_settings(enabled: bool = True, token: str = TEST_SCIM_TOKEN):
	ensure_scim_settings()
	settings = frappe.get_doc("SCIM Settings")
	settings.enabled = 1 if enabled else 0
	settings.bearer_token = token
	settings.service_user = ensure_scim_service_user()
	settings.default_user_type = "System User"
	settings.default_role = "System Manager"
	settings.save(ignore_permissions=True)
	frappe.clear_cache(doctype="SCIM Settings")
	return settings


def build_scim_request(
	method: str,
	path: str,
	body: dict | None = None,
	query_string: str = "",
	token: str = TEST_SCIM_TOKEN,
	query: dict | None = None,
):
	from werkzeug.test import EnvironBuilder
	from werkzeug.wrappers import Request

	if query:
		query_string = urlencode(query)

	builder_kwargs = {
		"method": method,
		"path": path,
		"environ_overrides": {"HTTP_AUTHORIZATION": f"Bearer {token}"},
	}
	if query_string:
		builder_kwargs["query_string"] = query_string
	if body is not None:
		builder_kwargs["content_type"] = SCIM_CONTENT_TYPE
		builder_kwargs["data"] = json.dumps(body)

	frappe.local.request = Request(EnvironBuilder(**builder_kwargs).get_environ())
	frappe.request = frappe.local.request

	if query:
		frappe.local.request.args = ImmutableMultiDict(list(query.items()))

	authenticate_scim_token()
	try:
		return dispatch_scim_request()
	except SCIMProvisioningError as error:
		return provisioning_error_response(error)


def cleanup_scim_user(email: str):
	if frappe.db.exists("User", email):
		frappe.delete_doc("User", email, force=1, ignore_permissions=True)


def unique_scim_email(label: str) -> str:
	return f"scim.{label}.{frappe.generate_hash(length=8)}@ambrosiapieco.example"
