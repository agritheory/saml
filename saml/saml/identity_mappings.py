# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import frappe

from saml.saml.scim_paths import extract_scim_path

if TYPE_CHECKING:
	from frappe.core.doctype.user.user import User
	from saml.saml.doctype.saml_login_key.saml_login_key import SAMLLoginKey
	from saml.saml.doctype.scim_settings.scim_settings import SCIMSettings


def get_identity_provider(settings: SCIMSettings) -> SAMLLoginKey | None:
	if not settings.identity_provider:
		return None
	return frappe.get_cached_doc("SAML Login Key", settings.identity_provider)


def scim_path_for_mapping(mapping) -> str:
	return (mapping.scim_path or mapping.source_attribute or "").strip()


def get_saml_attribute_value(
	attributes: dict | None,
	friendly_name: dict | None,
	source_attribute: str,
) -> Any:
	if friendly_name and source_attribute in friendly_name:
		values = friendly_name.get(source_attribute) or []
		if values:
			return values[0]

	if attributes and source_attribute in attributes:
		values = attributes.get(source_attribute) or []
		if values:
			return values[0]

	return None


def apply_scim_attribute_mappings(
	user_data: dict, scim_data: dict, provider: SAMLLoginKey
) -> None:
	"""Map provider-configured SCIM attributes onto Frappe User fields.

	An absent attribute maps to an empty value so mapped fields obey the same full
	replace semantics as the core attributes in `scim_to_user_data`.
	"""
	for mapping in provider.attribute_mappings:
		scim_path = scim_path_for_mapping(mapping)
		if not scim_path:
			continue
		value = extract_scim_path(scim_data, scim_path)
		user_data[mapping.user_field] = "" if value is None else value


def apply_saml_attribute_mappings(
	user,
	attributes: dict | None,
	friendly_name: dict | None,
	provider: SAMLLoginKey,
) -> bool:
	changed = False
	for mapping in provider.attribute_mappings:
		value = get_saml_attribute_value(attributes, friendly_name, mapping.source_attribute)
		if value is not None and user.get(mapping.user_field) != value:
			user.set(mapping.user_field, value)
			changed = True
	return changed


def sync_provider_roles_from_scim(user: User, scim_data: dict, provider: SAMLLoginKey) -> None:
	if not provider.roles or not provider.role_source_attribute:
		return

	raw_value = extract_scim_path(scim_data, provider.role_source_attribute)
	if isinstance(raw_value, list):
		role_names = [str(value) for value in raw_value if value]
	elif raw_value:
		role_names = [str(raw_value)]
	else:
		return

	current_roles = {row.role for row in user.get("roles")}
	all_mapped_roles = {row.user_role for row in provider.roles if row.role_or_role_profile == "Role"}
	lower_role_names = {name.lower() for name in role_names}
	matched_roles = {
		row.user_role
		for row in provider.roles
		if row.role_or_role_profile == "Role" and row.saml_role.lower() in lower_role_names
	}
	unmatched_mapped_roles = all_mapped_roles.difference(matched_roles)

	missing_roles = matched_roles.difference(current_roles)
	if missing_roles:
		user.add_roles(*missing_roles)

	roles_to_remove = current_roles.intersection(unmatched_mapped_roles)
	if roles_to_remove:
		user.remove_roles(*roles_to_remove)


def sync_provider_roles_from_saml(
	user: User, provider: SAMLLoginKey, attributes: dict | None
) -> None:
	if not provider.apply_saml_roles or not provider.roles:
		return

	role_attribute = provider.saml_role_attribute or "Role"
	roles = (attributes or {}).get(role_attribute) or []
	roles_to_apply = []
	user.flags.ignore_permissions = True

	for role in roles:
		for role_mapping in provider.roles:
			if role_mapping.saml_role != role:
				continue
			if role_mapping.role_or_role_profile == "Role Profile":
				if user.role_profile_name == role_mapping.user_role:
					break
				user.role_profile_name = role_mapping.user_role
				user.save(ignore_permissions=True)
				break
			if user.role_profile_name:
				user.roles = []
				user.role_profile_name = ""
				user.save(ignore_permissions=True)
			roles_to_apply.append(role_mapping.user_role)

	if roles_to_apply:
		user.add_roles(roles_to_apply)

	if provider.match_saml_roles:
		for has_role in reversed(user.roles):
			if has_role.role not in roles_to_apply:
				user.roles.remove(has_role)
		user.save(ignore_permissions=True)
