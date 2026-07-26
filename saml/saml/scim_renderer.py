# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

"""
Custom Frappe page renderer for the /scim/v2/* SCIM 2.0 API.

Registered via hooks.py::page_renderer. GET/POST are handled here; PUT/PATCH/DELETE
are handled in handle_scim_methods() because app.py only routes GET/HEAD/POST to
page renderers.
"""

from __future__ import annotations

import json
import re
from urllib.parse import unquote

import frappe
from frappe.auth import validate_auth
from werkzeug.exceptions import HTTPException
from werkzeug.wrappers import Response

from saml.saml.doctype.scim_settings.scim_settings import get_scim_settings
from saml.saml.identity_mappings import get_identity_provider, scim_path_for_mapping
from saml.saml.scim_constants import (
	SCIM_BASE_PATH,
	SCIM_CONTENT_TYPE,
	SCIM_ENTERPRISE_USER_SCHEMA,
	SCIM_ERROR_SCHEMA,
	SCIM_LIST_RESPONSE_SCHEMA,
	SCIM_RESOURCE_TYPE_SCHEMA,
	SCIM_SCHEMA_SCHEMA,
	SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA,
	SCIM_USER_SCHEMA,
)
from saml.saml.scim_provisioning import (
	SCIMProvisioningError,
	create_scim_user,
	deactivate_scim_user,
	get_scim_user,
	list_scim_users,
	patch_scim_user,
	replace_scim_user,
	user_to_scim,
)

USER_ID_PATTERN = re.compile(r"^Users/(.+)$")


class SCIMApiResponse(HTTPException):
	def __init__(self, data: dict | None, status: int) -> None:
		super().__init__(data, status)
		self.data = data
		self.code = status

	def get_response(self, environ=None):
		return scim_response(self.data, self.code)


def scim_response(data: dict | None, status: int = 200) -> Response:
	body = "" if data is None else json.dumps(data)
	return Response(body, status=status, mimetype=SCIM_CONTENT_TYPE)


def scim_error(detail: str, status: int, scim_type: str | None = None) -> dict:
	error = {
		"schemas": [SCIM_ERROR_SCHEMA],
		"status": str(status),
		"detail": detail,
	}
	if scim_type:
		error["scimType"] = scim_type
	return error


def provisioning_error_response(error: SCIMProvisioningError) -> SCIMApiResponse:
	return SCIMApiResponse(
		scim_error(error.detail, error.status, error.scim_type),
		error.status,
	)


def get_request_json() -> dict:
	request = frappe.local.request
	content_type = request.content_type or ""
	if request.method in ("GET", "DELETE") and not request.get_data():
		return {}

	if request.get_data() and "json" not in content_type and SCIM_CONTENT_TYPE not in content_type:
		raise SCIMProvisioningError("Unsupported content type", 415)

	raw = request.get_data(as_text=True)
	if not raw:
		return {}
	try:
		return json.loads(raw)
	except json.JSONDecodeError as exc:
		raise SCIMProvisioningError("Invalid JSON body", 400, "invalidSyntax") from exc


def authenticate_scim_token() -> None:
	request = getattr(frappe.local, "request", None)
	if not request or not request.path.startswith(f"/{SCIM_BASE_PATH}/"):
		return

	settings = get_scim_settings()
	if not settings.enabled:
		raise SCIMApiResponse(scim_error("SCIM is not enabled", 403), 403)

	auth_header = request.headers.get("Authorization", "") if hasattr(request, "headers") else ""
	if not auth_header:
		auth_header = frappe.get_request_header("Authorization", "")
	if not auth_header.startswith("Bearer "):
		raise SCIMApiResponse(scim_error("Authentication required", 401), 401)

	import hmac

	token = auth_header[7:]
	expected = settings.get_password("bearer_token")
	if not expected or not hmac.compare_digest(token, expected):
		raise SCIMApiResponse(scim_error("Invalid token", 401), 401)

	service_user = settings.service_user
	if not service_user or not frappe.db.exists("User", service_user):
		raise SCIMApiResponse(scim_error("SCIM service user is not configured", 503), 503)

	frappe.set_user(service_user)


def handle_scim_methods() -> None:
	request = getattr(frappe.local, "request", None)
	if not request or request.method not in ("PUT", "PATCH", "DELETE"):
		return
	if not request.path.startswith(f"/{SCIM_BASE_PATH}/"):
		return

	validate_auth()
	try:
		response = dispatch_scim_request()
	except SCIMProvisioningError as error:
		response = provisioning_error_response(error)
	frappe.db.commit()
	raise response


def dispatch_scim_request() -> SCIMApiResponse:
	request = frappe.local.request
	settings = get_scim_settings()
	if not settings.enabled:
		raise SCIMProvisioningError("SCIM is not enabled", 403)

	relative_path = request.path.strip("/")
	if not relative_path.startswith(f"{SCIM_BASE_PATH}/"):
		raise SCIMProvisioningError("Not found", 404)

	subpath = relative_path[len(SCIM_BASE_PATH) + 1 :]
	method = request.method

	if subpath == "ServiceProviderConfig" and method == "GET":
		return SCIMApiResponse(service_provider_config(), 200)
	if subpath == "Schemas" and method == "GET":
		return SCIMApiResponse(schemas_response(), 200)
	if subpath == "ResourceTypes" and method == "GET":
		return SCIMApiResponse(resource_types_response(), 200)

	if subpath == "Users":
		if method == "GET":
			filter_expression = request.args.get("filter")
			start_index = int(request.args.get("startIndex") or 1)
			count = request.args.get("count")
			count_value = int(count) if count is not None else None
			return SCIMApiResponse(
				list_scim_users(filter_expression, start_index, count_value),
				200,
			)
		if method == "POST":
			body = get_request_json()
			user = create_scim_user(body, settings)
			return SCIMApiResponse(user_to_scim(user), 201)
		raise SCIMProvisioningError("Method not allowed", 405)

	user_match = USER_ID_PATTERN.match(subpath)
	if user_match:
		user_id = unquote(user_match.group(1))
		if method == "GET":
			user = get_scim_user(user_id)
			return SCIMApiResponse(user_to_scim(user), 200)
		if method == "PUT":
			body = get_request_json()
			user = replace_scim_user(user_id, body, settings)
			return SCIMApiResponse(user_to_scim(user), 200)
		if method == "PATCH":
			body = get_request_json()
			user = patch_scim_user(user_id, body, settings)
			return SCIMApiResponse(user_to_scim(user), 200)
		if method == "DELETE":
			deactivate_scim_user(user_id)
			return SCIMApiResponse(None, 204)

	raise SCIMProvisioningError("Not found", 404)


def service_provider_config() -> dict:
	return {
		"schemas": [SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA],
		"patch": {"supported": True},
		"bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
		"filter": {"supported": True, "maxResults": 200},
		"changePassword": {"supported": False},
		"sort": {"supported": False},
		"etag": {"supported": False},
		"authenticationSchemes": [
			{
				"type": "oauthbearertoken",
				"name": "OAuth Bearer Token",
				"description": "Authentication via bearer token configured in SCIM Settings",
			}
		],
	}


def schemas_response() -> dict:
	settings = get_scim_settings()
	provider = get_identity_provider(settings)
	attributes = [
		{"name": "userName", "type": "string", "required": True, "mutability": "readWrite"},
		{"name": "externalId", "type": "string", "required": False, "mutability": "readWrite"},
		{"name": "active", "type": "boolean", "required": False, "mutability": "readWrite"},
		{
			"name": "name",
			"type": "complex",
			"required": False,
			"mutability": "readWrite",
			"subAttributes": [
				{"name": "givenName", "type": "string", "required": False, "mutability": "readWrite"},
				{"name": "middleName", "type": "string", "required": False, "mutability": "readWrite"},
				{"name": "familyName", "type": "string", "required": False, "mutability": "readWrite"},
			],
		},
	]
	if provider:
		for mapping in provider.attribute_mappings:
			scim_path = scim_path_for_mapping(mapping)
			if ":" in scim_path:
				_, _, attribute = scim_path.rpartition(":")
				attributes.append(
					{
						"name": attribute,
						"type": "string",
						"required": False,
						"mutability": "readWrite",
					}
				)

	return {
		"schemas": [SCIM_LIST_RESPONSE_SCHEMA],
		"Resources": [
			{
				"schemas": [SCIM_SCHEMA_SCHEMA],
				"id": SCIM_USER_SCHEMA,
				"name": "User",
				"description": "User Account",
				"attributes": attributes,
				"meta": {
					"resourceType": "Schema",
					"location": f"{frappe.utils.get_url()}/scim/v2/Schemas",
				},
			},
			{
				"schemas": [SCIM_SCHEMA_SCHEMA],
				"id": SCIM_ENTERPRISE_USER_SCHEMA,
				"name": "EnterpriseUser",
				"description": "Enterprise User",
				"attributes": [],
				"meta": {
					"resourceType": "Schema",
					"location": f"{frappe.utils.get_url()}/scim/v2/Schemas",
				},
			},
		],
		"totalResults": 2,
		"startIndex": 1,
		"itemsPerPage": 2,
	}


def resource_types_response() -> dict:
	return {
		"schemas": [SCIM_LIST_RESPONSE_SCHEMA],
		"Resources": [
			{
				"schemas": [SCIM_RESOURCE_TYPE_SCHEMA],
				"id": "User",
				"name": "User",
				"endpoint": "/Users",
				"schema": SCIM_USER_SCHEMA,
				"meta": {
					"resourceType": "ResourceType",
					"location": f"{frappe.utils.get_url()}/scim/v2/ResourceTypes/User",
				},
			}
		],
		"totalResults": 1,
		"startIndex": 1,
		"itemsPerPage": 1,
	}


class SCIMApiRenderer:
	def __init__(self, path: str, http_status_code: int | None = None) -> None:
		self.path = path
		self.http_status_code = http_status_code or 200

	def can_render(self) -> bool:
		return self.path == SCIM_BASE_PATH or self.path.startswith(f"{SCIM_BASE_PATH}/")

	def render(self) -> Response:
		try:
			response = dispatch_scim_request()
		except SCIMProvisioningError as error:
			response = provisioning_error_response(error)

		frappe.db.commit()
		if response.code == 204:
			return scim_response(None, 204)
		return scim_response(response.data, response.code)
