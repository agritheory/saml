# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

import frappe

from saml.saml.scim_constants import SCIM_SERVICE_USER_EMAIL


def after_install():
	ensure_scim_service_user()
	ensure_scim_settings()


def ensure_scim_service_user() -> str:
	if frappe.db.exists("User", SCIM_SERVICE_USER_EMAIL):
		return SCIM_SERVICE_USER_EMAIL

	user = frappe.get_doc(
		{
			"doctype": "User",
			"email": SCIM_SERVICE_USER_EMAIL,
			"first_name": "SCIM",
			"last_name": "Provisioner",
			"enabled": 1,
			"send_welcome_email": 0,
			"user_type": "System User",
		}
	)
	user.insert(ignore_permissions=True)
	user.add_roles("System Manager")
	return user.name


def ensure_scim_settings():
	if frappe.db.exists("SCIM Settings", "SCIM Settings"):
		settings = frappe.get_doc("SCIM Settings")
	else:
		settings = frappe.get_doc({"doctype": "SCIM Settings"})

	if not settings.service_user:
		settings.service_user = ensure_scim_service_user()

	if not settings.get_password("bearer_token", raise_exception=False):
		settings.bearer_token = frappe.generate_hash(length=32)

	if not settings.default_user_type:
		settings.default_user_type = "System User"

	settings.save(ignore_permissions=True)
