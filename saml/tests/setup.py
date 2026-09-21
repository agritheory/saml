# Copyright (c) 2024, AgriTheory and contributors
# For license information, please see license.txt

import json
from pathlib import Path

import frappe
from frappe.desk.page.setup_wizard.setup_wizard import setup_complete
from frappe.utils.data import getdate

LOGIN_KEY_FIXTURE_SKIP_FIELDS = frozenset(
	{
		"name",
		"doctype",
		"owner",
		"creation",
		"modified",
		"modified_by",
		"docstatus",
		"idx",
	}
)


def before_test():
	frappe.flags.in_test = True
	frappe.clear_cache()
	setup_complete(
		{
			"currency": "USD",
			"full_name": "Administrator",
			"company_name": "Ambrosia Pie Company",
			"timezone": "America/New_York",
			"company_abbr": "APC",
			"domains": ["Distribution"],
			"country": "United States",
			"fy_start_date": getdate().replace(month=1, day=1).isoformat(),
			"fy_end_date": getdate().replace(month=12, day=31).isoformat(),
			"language": "english",
			"email": "support@agritheory.dev",
			"password": "admin",
		}
	)
	for module in frappe.get_all("Module Onboarding"):
		frappe.db.set_value("Module Onboarding", module, "is_complete", True)
	frappe.set_value("Website Settings", "Website Settings", "home_page", "login")
	frappe.db.commit()
	create_test_data()
	sync_keycloak_idp_certificate_if_available()


def create_test_data():
	create_role_profile()
	create_saml_login_key()
	create_test_users()
	ensure_scim_test_settings()
	ensure_keycloak_test_files()


def ensure_scim_test_settings():
	from saml.install import ensure_scim_service_user, ensure_scim_settings

	ensure_scim_settings()
	settings = frappe.get_doc("SCIM Settings")
	settings.enabled = 1
	settings.bearer_token = "test-scim-bearer-token"
	settings.identity_provider = "keycloak"
	settings.service_user = ensure_scim_service_user()
	settings.default_user_type = "System User"
	settings.default_role = "System Manager"
	settings.save(ignore_permissions=True)
	frappe.clear_cache(doctype="SCIM Settings")


def ensure_keycloak_test_files():
	"""Regenerate realm-export.json and scim-keycloak-config.json for the current bench port."""
	from saml.tests.process_realm import generate_keycloak_test_files

	tests_dir = Path(frappe.get_app_path("saml")) / "tests"
	bench_port = frappe.conf.get("webserver_port") or 8000
	bearer_token = "test-scim-bearer-token"
	if frappe.db.exists("SCIM Settings", "SCIM Settings"):
		bearer_token = (
			frappe.db.get_value("SCIM Settings", "SCIM Settings", "bearer_token") or bearer_token
		)

	generate_keycloak_test_files(tests_dir, bench_port, bearer_token=bearer_token)


def sync_keycloak_idp_certificate_if_available():
	"""Sync IdP cert from a running Keycloak container when docker compose is up."""
	try:
		from saml.tests.keycloak_helpers import sync_keycloak_idp_certificate, wait_for_keycloak

		wait_for_keycloak(timeout=10)
		sync_keycloak_idp_certificate()
	except Exception:
		return


def create_test_users():
	if not frappe.db.exists("User", "warehouse@ambrosiapieco.example"):
		user = frappe.new_doc("User")
		user.update(
			{
				"email": "warehouse@ambrosiapieco.example",
				"first_name": "Warehouse",
				"last_name": "Manager",
				"enabled": True,
				"send_welcome_email": False,
			}
		)
		user.insert(ignore_permissions=True)

	if not frappe.db.exists("User", "saml.existing@ambrosiapieco.example"):
		user = frappe.new_doc("User")
		user.update(
			{
				"email": "saml.existing@ambrosiapieco.example",
				"first_name": "SAML",
				"last_name": "Existing",
				"enabled": True,
				"send_welcome_email": False,
				"saml_managed": True,
			}
		)
		user.insert(ignore_permissions=True)

	frappe.clear_cache(doctype="User")


def create_role_profile():
	role_profile_name = "Knowledge Base"
	if frappe.db.exists("Role Profile", role_profile_name):
		return

	clear_document_lock("Role Profile", role_profile_name)

	role_profile = frappe.new_doc("Role Profile")
	role_profile.name = role_profile_name
	role_profile.role_profile = role_profile_name
	for role in [
		"Blogger",
		"Knowledge Base Contributor",
		"Knowledge Base Editor",
		"Newsletter Manager",
		"Website Manager",
	]:
		role_profile.append("roles", {"role": role})
	role_profile.save(ignore_permissions=True)


def clear_document_lock(doctype: str, name: str):
	import hashlib

	from frappe.utils import file_lock

	signature = hashlib.sha224(f"{doctype}:{name}".encode(), usedforsecurity=False).hexdigest()
	if file_lock.lock_exists(signature):
		file_lock.delete_lock(signature)


def create_saml_login_key():
	test_data_dir = Path(frappe.get_app_path("saml")) / "tests" / "data"
	settings_file = test_data_dir / "saml_login_key.json"
	login_keys = json.loads(settings_file.read_text())
	for login_key in login_keys:
		name = login_key["name"]
		fixture_data = {
			key: value for key, value in login_key.items() if key not in LOGIN_KEY_FIXTURE_SKIP_FIELDS
		}
		if frappe.db.exists("SAML Login Key", name):
			saml_key = frappe.get_doc("SAML Login Key", name)
			saml_key.update(fixture_data)
			saml_key.save(ignore_permissions=True)
		else:
			saml_key = frappe.get_doc({"doctype": "SAML Login Key", "name": name, **fixture_data})
			saml_key.insert(ignore_permissions=True)
