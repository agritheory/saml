# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import frappe
from frappe.utils import validate_email_address

from saml.saml.identity_mappings import (
	apply_scim_attribute_mappings,
	get_identity_provider,
	scim_path_for_mapping,
	sync_provider_roles_from_scim,
)
from saml.saml.doctype.scim_settings.scim_settings import get_scim_settings
from saml.saml.scim_constants import (
	SCIM_LIST_RESPONSE_SCHEMA,
	SCIM_USER_SCHEMA,
	format_scim_datetime,
	scim_active_to_enabled,
	scim_language_to_frappe,
)
from saml.saml.scim_paths import deep_get, extract_scim_path, set_deep

if TYPE_CHECKING:
	from frappe.core.doctype.user.user import User
	from saml.saml.doctype.scim_settings.scim_settings import SCIMSettings

FILTER_PATTERN = re.compile(
	r'^(userName|externalId)\s+eq\s+"(.*)"$',
	re.IGNORECASE,
)
PATH_FILTER_PATTERN = re.compile(r"^(.+)\[(.+)\]$")
VALUE_FILTER_PATTERN = re.compile(r'^(\w+)\s+eq\s+"(.*)"$')


class SCIMProvisioningError(Exception):
	def __init__(self, detail: str, status: int = 400, scim_type: str | None = None):
		self.detail = detail
		self.status = status
		self.scim_type = scim_type
		super().__init__(detail, status, scim_type)


def get_email_from_scim(scim_data: dict) -> str | None:
	user_name = scim_data.get("userName")
	if user_name:
		return user_name

	for email in scim_data.get("emails") or []:
		if isinstance(email, dict) and email.get("primary"):
			return email.get("value")
	for email in scim_data.get("emails") or []:
		if isinstance(email, dict) and email.get("value"):
			return email.get("value")
	return None


def get_phone_by_type(scim_data: dict, phone_type: str) -> str | None:
	for phone in scim_data.get("phoneNumbers") or []:
		if isinstance(phone, dict) and (phone.get("type") or "").lower() == phone_type.lower():
			return phone.get("value")
	return None


def scim_to_user_data(scim_data: dict, settings: SCIMSettings) -> dict:
	email = get_email_from_scim(scim_data)
	if not email:
		raise SCIMProvisioningError("userName is required", 400, "invalidValue")

	if not validate_email_address(email, throw=False):
		raise SCIMProvisioningError(
			"userName must be a valid email address",
			400,
			"invalidValue",
		)

	user_data: dict[str, Any] = {
		"email": email,
		"first_name": deep_get(scim_data, "name.givenName") or email.split("@", 1)[0],
		"last_name": deep_get(scim_data, "name.familyName") or "",
		"middle_name": deep_get(scim_data, "name.middleName"),
		"enabled": scim_active_to_enabled(scim_data.get("active", True)),
		"phone": get_phone_by_type(scim_data, "work"),
		"mobile_no": get_phone_by_type(scim_data, "mobile"),
		"language": scim_language_to_frappe(scim_data.get("preferredLanguage")),
	}

	if scim_data.get("externalId"):
		user_data["scim_external_id"] = scim_data.get("externalId")

	provider = get_identity_provider(settings)
	if provider:
		apply_scim_attribute_mappings(user_data, scim_data, provider)

	return {key: value for key, value in user_data.items() if value is not None}


def user_to_scim(user: User) -> dict:
	resource = {
		"schemas": [SCIM_USER_SCHEMA],
		"id": user.name,
		"userName": user.email,
		"name": {
			"givenName": user.first_name or "",
			"familyName": user.last_name or "",
		},
		"active": bool(user.enabled),
		"emails": [{"value": user.email, "primary": True}],
		"meta": {
			"resourceType": "User",
			"created": format_scim_datetime(user.creation),
			"lastModified": format_scim_datetime(user.modified),
			"location": f"{frappe.utils.get_url()}/scim/v2/Users/{quote(user.name, safe='')}",
		},
	}

	if user.middle_name:
		resource["name"]["middleName"] = user.middle_name
	if user.get("scim_external_id"):
		resource["externalId"] = user.scim_external_id
	if user.phone:
		resource["phoneNumbers"] = [{"value": user.phone, "type": "work"}]
	if user.mobile_no:
		phones = resource.setdefault("phoneNumbers", [])
		phones.append({"value": user.mobile_no, "type": "mobile"})
	if user.language:
		resource["preferredLanguage"] = user.language

	settings = get_scim_settings()
	provider = get_identity_provider(settings)
	if provider:
		for mapping in provider.attribute_mappings:
			value = user.get(mapping.user_field)
			if value is None:
				continue
			scim_path = scim_path_for_mapping(mapping)
			if ":" in scim_path:
				extension_key, _, attribute = scim_path.rpartition(":")
				resource.setdefault(extension_key, {})[attribute] = value
			elif scim_path:
				resource[scim_path] = value

	return resource


def parse_filter_expression(filter_expression: str) -> tuple[str, str]:
	match = FILTER_PATTERN.match((filter_expression or "").strip())
	if not match:
		raise SCIMProvisioningError("Unsupported filter expression", 400, "invalidFilter")
	return match.group(1), match.group(2)


def list_scim_users(
	filter_expression: str | None = None,
	start_index: int = 1,
	count: int | None = None,
) -> dict:
	filters = [["scim_managed", "=", 1]]
	if filter_expression:
		field_name, value = parse_filter_expression(filter_expression)
		if field_name.lower() == "username":
			filters.append(["email", "=", value])
		elif field_name.lower() == "externalid":
			filters.append(["scim_external_id", "=", value])

	users = frappe.get_all(
		"User",
		filters=filters,
		fields=["name"],
		order_by="modified desc",
	)

	total_results = len(users)
	start_index = max(start_index, 1)
	page_size = count if count is not None and count >= 0 else total_results
	end_index = start_index - 1 + page_size
	page = users[start_index - 1 : end_index]

	resources = [user_to_scim(frappe.get_doc("User", row.name)) for row in page]

	return {
		"schemas": [SCIM_LIST_RESPONSE_SCHEMA],
		"totalResults": total_results,
		"startIndex": start_index,
		"itemsPerPage": len(resources),
		"Resources": resources,
	}


def find_user_for_create(scim_data: dict) -> str | None:
	external_id = scim_data.get("externalId")
	if external_id:
		existing = frappe.db.get_value("User", {"scim_external_id": external_id})
		if existing:
			return existing

	email = get_email_from_scim(scim_data)
	if email and frappe.db.exists("User", email):
		return email
	return None


def create_scim_user(scim_data: dict, settings: SCIMSettings) -> User:
	existing = find_user_for_create(scim_data)
	if existing:
		raise SCIMProvisioningError("User already exists", 409, "uniqueness")

	if settings.do_not_create_new_user:
		raise SCIMProvisioningError("User not found", 404)

	user_data = scim_to_user_data(scim_data, settings)
	doc = {
		"doctype": "User",
		"send_welcome_email": 0,
		"user_type": settings.default_user_type,
		"scim_managed": 1,
		**user_data,
	}

	frappe.flags.in_import = True
	try:
		user = frappe.get_doc(doc)
		user.insert(ignore_permissions=True)
	finally:
		frappe.flags.in_import = False

	apply_default_role(user, settings)
	provider = get_identity_provider(settings)
	if provider:
		sync_provider_roles_from_scim(user, scim_data, provider)
	return user


def replace_scim_user(user_id: str, scim_data: dict, settings: SCIMSettings) -> User:
	user = get_scim_user(user_id)
	user_data = scim_to_user_data(scim_data, settings)
	user_data["scim_managed"] = 1
	user.update(user_data)
	user.save(ignore_permissions=True)
	provider = get_identity_provider(settings)
	if provider:
		sync_provider_roles_from_scim(user, scim_data, provider)
	return user


def patch_scim_user(user_id: str, patch_body: dict, settings: SCIMSettings) -> User:
	user = get_scim_user(user_id)
	current = user_to_scim(user)
	operations = patch_body.get("Operations") or []
	if not isinstance(operations, list):
		raise SCIMProvisioningError("Operations must be an array", 400, "invalidSyntax")

	for operation in operations:
		apply_patch_operation(current, operation)

	user_data = scim_to_user_data(current, settings)
	user_data["scim_managed"] = 1
	user.update(user_data)
	user.save(ignore_permissions=True)
	provider = get_identity_provider(settings)
	if provider:
		sync_provider_roles_from_scim(user, current, provider)
	return user


def deactivate_scim_user(user_id: str) -> None:
	user = get_scim_user(user_id)
	user.enabled = 0
	user.save(ignore_permissions=True)


def get_scim_user(user_id: str) -> User:
	if not frappe.db.exists("User", user_id):
		raise SCIMProvisioningError("User not found", 404)
	return frappe.get_doc("User", user_id)


def apply_patch_operation(scim_data: dict, operation: dict) -> None:
	op_name = (operation.get("op") or "replace").lower()
	path = operation.get("path")
	value = operation.get("value")

	if op_name not in {"add", "replace", "remove"}:
		raise SCIMProvisioningError(f"Unsupported patch op: {op_name}", 400, "invalidSyntax")

	if op_name == "remove":
		if not path:
			raise SCIMProvisioningError("Remove operation requires path", 400, "invalidSyntax")
		remove_scim_path(scim_data, path)
		return

	if not path and isinstance(value, dict):
		merge_scim_dict(scim_data, value)
		return

	if not path:
		raise SCIMProvisioningError(
			"Patch operation requires path or value object", 400, "invalidSyntax"
		)

	set_scim_path(scim_data, path, value)


def merge_scim_dict(target: dict, source: dict) -> None:
	for key, value in source.items():
		if isinstance(value, dict) and isinstance(target.get(key), dict):
			merge_scim_dict(target[key], value)
		else:
			target[key] = value


def remove_scim_path(data: dict, path: str) -> None:
	attribute, filter_expr = split_path_filter(path)
	if filter_expr:
		items = data.get(attribute)
		if not isinstance(items, list):
			return
		filter_field, filter_value = parse_value_filter(filter_expr)
		data[attribute] = [
			item
			for item in items
			if not (isinstance(item, dict) and item.get(filter_field) == filter_value)
		]
		return

	if "." in attribute:
		parent_path, leaf = attribute.rsplit(".", 1)
		parent = deep_get(data, parent_path)
		if isinstance(parent, dict):
			parent.pop(leaf, None)
	else:
		data.pop(attribute, None)


def set_scim_path(data: dict, path: str, value: Any) -> None:
	attribute, filter_expr = split_path_filter(path)
	if filter_expr and path.endswith(".value"):
		filter_field, filter_value = parse_value_filter(filter_expr)
		items = data.setdefault(attribute, [])
		if not isinstance(items, list):
			items = []
			data[attribute] = items
		for item in items:
			if isinstance(item, dict) and item.get(filter_field) == filter_value:
				item["value"] = value
				return
		items.append({filter_field: filter_value, "value": value, "primary": filter_field == "type"})
		return

	if "." in path:
		set_deep(data, path, value)
	else:
		data[path] = value


def split_path_filter(path: str) -> tuple[str, str | None]:
	filter_path = path[:-6] if path.endswith(".value") else path
	match = PATH_FILTER_PATTERN.match(filter_path)
	if not match:
		return path, None
	return match.group(1), match.group(2)


def parse_value_filter(filter_expr: str) -> tuple[str, str]:
	match = VALUE_FILTER_PATTERN.match(filter_expr.strip())
	if not match:
		raise SCIMProvisioningError("Unsupported path filter", 400, "invalidSyntax")
	return match.group(1), match.group(2)


def apply_default_role(user: User, settings: SCIMSettings) -> None:
	if settings.default_role:
		user.add_roles(settings.default_role)
