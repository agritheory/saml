# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

"""Provision multi-valued SCIM identifiers into child tables on User.

The identity provider is authoritative for which identifiers are currently valid. An identifier
it no longer lists is revoked in place rather than deleted: the stored value gains a sentinel
suffix so a scan of the physical card no longer matches, while the row survives as history.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import frappe
from frappe.utils import get_datetime, now_datetime

from saml.saml.scim_paths import extract_scim_path

if TYPE_CHECKING:
	from frappe.core.doctype.user.user import User
	from saml.saml.doctype.saml_login_key.saml_login_key import SAMLLoginKey

DEFAULT_TABLE_SYNC_DELIMITER = ","
REVOCATION_SENTINEL = "~REVOKED~"
REVOCATION_TIMESTAMP_FORMAT = "%Y%m%dT%H%M%S"


class CredentialConflictError(Exception):
	"""An identifier is already assigned elsewhere."""


@dataclass(frozen=True)
class TableSyncConfig:
	source_attribute: str
	table_field: str
	value_field: str
	delimiter: str = DEFAULT_TABLE_SYNC_DELIMITER
	scope_field: str | None = None
	scope_value: str | None = None


@dataclass
class TableSyncPlan:
	issue: list[str] = field(default_factory=list)
	revoke: list[tuple[str, str]] = field(default_factory=list)

	@property
	def is_empty(self) -> bool:
		return not self.issue and not self.revoke


def table_sync_config_from_row(row: Any) -> TableSyncConfig | None:
	source_attribute = (row.get("scim_path") or "").strip()
	table_field = (row.get("user_table_field") or "").strip()
	value_field = (row.get("value_field") or "").strip()
	if not (source_attribute and table_field and value_field):
		return None

	return TableSyncConfig(
		source_attribute=source_attribute,
		table_field=table_field,
		value_field=value_field,
		delimiter=(row.get("delimiter") or DEFAULT_TABLE_SYNC_DELIMITER),
		scope_field=(row.get("scope_field") or "").strip() or None,
		scope_value=(row.get("scope_value") or "").strip() or None,
	)


def get_table_sync_configs(provider: SAMLLoginKey) -> list[TableSyncConfig]:
	configs: list[TableSyncConfig] = []
	for row in provider.get("table_mappings") or []:
		config = table_sync_config_from_row(row)
		if config:
			configs.append(config)
	return configs


def parse_table_sync_values(raw: Any, delimiter: str = DEFAULT_TABLE_SYNC_DELIMITER) -> list[str]:
	"""Split an IdP-provided value into unique identifiers, preserving order."""
	if raw is None:
		return []

	if isinstance(raw, (list, tuple, set)):
		candidates = [str(value) for value in raw]
	else:
		candidates = str(raw).split(delimiter or DEFAULT_TABLE_SYNC_DELIMITER)

	values: list[str] = []
	seen: set[str] = set()
	for candidate in candidates:
		value = candidate.strip()
		if not value or value in seen:
			continue
		seen.add(value)
		values.append(value)

	return values


def is_revoked_value(value: Any) -> bool:
	return REVOCATION_SENTINEL in str(value or "")


def build_revoked_value(value: str, revoked_at=None) -> str:
	stamp = get_datetime(revoked_at) if revoked_at else now_datetime()
	return f"{value}{REVOCATION_SENTINEL}{stamp.strftime(REVOCATION_TIMESTAMP_FORMAT)}"


def table_row_in_scope(row: Any, config: TableSyncConfig) -> bool:
	if not config.scope_field:
		return True
	return str(row.get(config.scope_field) or "") == str(config.scope_value or "")


def plan_table_sync(
	desired: list[str],
	rows: list[dict],
	config: TableSyncConfig,
	revoked_at=None,
) -> TableSyncPlan:
	"""Diff the identity provider's identifier list against the rows this provider owns."""
	active_owned: dict[str, str] = {}
	for row in rows:
		value = str(row.get(config.value_field) or "")
		if not value or is_revoked_value(value):
			continue
		if not table_row_in_scope(row, config):
			continue
		active_owned[value] = value

	desired_set = set(desired)
	plan = TableSyncPlan()

	for value in desired:
		if value not in active_owned:
			plan.issue.append(value)

	for value in active_owned:
		if value not in desired_set:
			plan.revoke.append((value, build_revoked_value(value, revoked_at=revoked_at)))

	return plan


def get_table_sync_child_doctype(config: TableSyncConfig) -> str | None:
	user_table_field = frappe.get_meta("User").get_field(config.table_field)
	if not user_table_field or user_table_field.fieldtype != "Table":
		return None
	return user_table_field.options


def assert_values_available(
	values: list[str], config: TableSyncConfig, exclude_user: str | None = None
) -> None:
	"""Raise CredentialConflictError when any identifier is already assigned elsewhere."""
	if not values:
		return

	child_doctype = get_table_sync_child_doctype(config)
	if not child_doctype:
		return

	filters = [[config.value_field, "in", values]]
	if exclude_user:
		filters.append(["parent", "!=", exclude_user])

	conflicts = frappe.get_all(
		child_doctype,
		filters=filters,
		fields=["parent", config.value_field],
		limit=1,
	)
	if conflicts:
		row = conflicts[0]
		raise CredentialConflictError(
			f"Identifier {row.get(config.value_field)} is already assigned to {row.parent}"
		)


def assert_scim_table_mappings_available(
	scim_data: dict, provider: SAMLLoginKey, exclude_user: str | None = None
) -> None:
	for config in get_table_sync_configs(provider):
		raw = extract_scim_path(scim_data, config.source_attribute)
		if raw is None:
			continue

		desired = parse_table_sync_values(raw, config.delimiter)
		assert_values_available(desired, config, exclude_user=exclude_user)


def table_mapping_saml_attribute_name(config: TableSyncConfig) -> str:
	"""SAML assertions use short attribute names; SCIM paths use the same leaf."""
	path = config.source_attribute
	if ":" in path:
		return path.rpartition(":")[2]
	return path


def apply_table_sync_plan(user: User, plan: TableSyncPlan, config: TableSyncConfig) -> None:
	revocations = dict(plan.revoke)
	for row in user.get(config.table_field) or []:
		current = str(row.get(config.value_field) or "")
		if current in revocations:
			row.set(config.value_field, revocations[current])

	for value in plan.issue:
		row = {config.value_field: value}
		if config.scope_field and config.scope_value:
			row[config.scope_field] = config.scope_value
		user.append(config.table_field, row)


def sync_table_mapping_from_raw(user: User, raw: Any, config: TableSyncConfig) -> bool:
	"""Reconcile one User child table with a raw identity-provider value."""
	if not get_table_sync_child_doctype(config):
		return False

	if raw is None:
		return False

	desired = parse_table_sync_values(raw, config.delimiter)
	rows = [row.as_dict() for row in user.get(config.table_field) or []]
	plan = plan_table_sync(desired, rows, config)
	if plan.is_empty:
		return False

	assert_values_available(plan.issue, config, exclude_user=user.name)
	apply_table_sync_plan(user, plan, config)

	try:
		user.save(ignore_permissions=True)
	except (frappe.UniqueValidationError, frappe.DuplicateEntryError) as error:
		raise CredentialConflictError(str(error)) from error

	return True


def sync_table_mapping_from_scim(user: User, scim_data: dict, config: TableSyncConfig) -> bool:
	raw = extract_scim_path(scim_data, config.source_attribute)
	return sync_table_mapping_from_raw(user, raw, config)


def sync_table_mapping_from_saml(
	user: User,
	attributes: dict | None,
	friendly_name: dict | None,
	config: TableSyncConfig,
) -> bool:
	from saml.saml.identity_mappings import get_saml_attribute_raw

	attr_name = table_mapping_saml_attribute_name(config)
	raw = get_saml_attribute_raw(attributes, friendly_name, attr_name)
	return sync_table_mapping_from_raw(user, raw, config)


def sync_provider_table_mappings_from_scim(
	user: User, scim_data: dict, provider: SAMLLoginKey
) -> bool:
	"""Reconcile all configured child tables with the identity provider's current lists."""
	changed = False
	for config in get_table_sync_configs(provider):
		if sync_table_mapping_from_scim(user, scim_data, config):
			changed = True
	return changed


def sync_provider_table_mappings_from_saml(
	user: User,
	attributes: dict | None,
	friendly_name: dict | None,
	provider: SAMLLoginKey,
) -> bool:
	"""Reconcile child tables from SAML assertion attributes on login."""
	changed = False
	for config in get_table_sync_configs(provider):
		if sync_table_mapping_from_saml(user, attributes, friendly_name, config):
			changed = True
	return changed


def active_values_for_scim(user: User, config: TableSyncConfig) -> str | None:
	"""Return the delimited list of identifiers the provider owns, for outbound SCIM."""
	if not get_table_sync_child_doctype(config):
		return None

	values = []
	for row in user.get(config.table_field) or []:
		value = str(row.get(config.value_field) or "")
		if not value or is_revoked_value(value):
			continue
		if not table_row_in_scope(row, config):
			continue
		values.append(value)

	if not values:
		return None

	return config.delimiter.join(values)
