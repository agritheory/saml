# Copyright (c) 2024, AgriTheory and contributors
# For license information, please see license.txt

import json
from pathlib import Path

import frappe
from frappe.desk.page.setup_wizard.setup_wizard import setup_complete
from frappe.utils.data import getdate


def before_test():
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


def create_test_data():
	create_role_profile()
	create_saml_login_key()
	create_test_users()


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


def create_role_profile():
	role_profile = frappe.new_doc("Role Profile")
	role_profile.name = "Knowledge Base"
	role_profile.role_profile = "Knowledge Base"
	for role in [
		"Blogger",
		"Knowledge Base Contributor",
		"Knowledge Base Editor",
		"Newsletter Manager",
		"Website Manager",
	]:
		role_profile.append("roles", {"role": role})
	role_profile.save(ignore_permissions=True)


def create_saml_login_key():
	test_data_dir = Path(frappe.get_app_path("saml")) / "tests" / "data"
	settings_file = test_data_dir / "saml_login_key.json"
	login_keys = json.loads(settings_file.read_text())
	for login_key in login_keys:
		saml_key = frappe.get_doc(login_key)
		saml_key.insert()
