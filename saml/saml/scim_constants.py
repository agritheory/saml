# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

SCIM_CONTENT_TYPE = "application/scim+json"

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_ENTERPRISE_USER_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
SCIM_PATCH_OP_SCHEMA = "urn:ietf:params:scim:schemas:api:messages:2.0:PatchOp"
SCIM_LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:schemas:api:messages:2.0:ListResponse"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:schemas:api:messages:2.0:Error"
SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
SCIM_RESOURCE_TYPE_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
SCIM_SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema"

SCIM_BASE_PATH = "scim/v2"

CORE_SCIM_PATHS = frozenset(
	{
		"username",
		"externalid",
		"name",
		"name.givenname",
		"name.middlename",
		"name.familyname",
		"active",
		"emails",
		"phonenumbers",
		"preferredlanguage",
		"id",
		"meta",
		"schemas",
		"groups",
	}
)

SCIM_SERVICE_USER_EMAIL = "scim-provisioner@system.local"


def format_scim_datetime(value) -> str:
	"""Return an RFC 7643 UTC dateTime string (ISO 8601 with Z suffix)."""
	from datetime import timezone

	from frappe.utils import get_datetime

	dt = get_datetime(value)
	if dt.tzinfo is None:
		dt = dt.replace(tzinfo=timezone.utc)
	else:
		dt = dt.astimezone(timezone.utc)
	return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def scim_active_to_enabled(active) -> int:
	"""Map SCIM active to Frappe User.enabled (handles Entra string booleans)."""
	if active is None:
		return 1
	if isinstance(active, str):
		return int(active.strip().lower() not in ("false", "0", "no"))
	return int(bool(active))


def scim_language_to_frappe(preferred_language: str | None) -> str | None:
	"""Map BCP 47 preferredLanguage to Frappe language code (primary subtag)."""
	if not preferred_language:
		return None
	return preferred_language.split("-", 1)[0].lower()
