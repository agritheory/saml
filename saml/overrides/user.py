# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.utils import cint


def sync_notification_settings_for_scim_user(user, method=None):
	"""Align Notification Settings before User.validate toggles them.

	SCIM provisioning saves users with ignore_permissions, but Frappe's
	check_enable_disable still calls toggle_notifications without that flag.
	Pre-sync the settings so the toggle becomes a no-op.
	"""
	if user.is_new() or not user.scim_managed:
		return

	doc_before = user.get_doc_before_save()
	if not doc_before or cint(doc_before.enabled) == cint(user.enabled):
		return

	if not frappe.db.exists("Notification Settings", user.name):
		return

	settings = frappe.get_doc("Notification Settings", user.name)
	enable = cint(user.enabled)
	if settings.enabled != enable:
		settings.enabled = enable
		settings.save(ignore_permissions=True)


def validate_reset_password(user, method=None):
	"""Prevent password set / reset for SAML-managed users.

	Skip validation in the following cases:
	1. If the user is being created, in which case SAML status is unsure
	2. If the user authentication is not managed by SAML
	3. If there are no enabled SAML Login Keys with password update disallowed
	"""

	if user.is_new():
		return

	if user.scim_managed:
		error = {
			"message": _(
				"Password reset is not allowed for SCIM-managed users. Please use your identity provider's password management flow."
			),
			"title": _("Password Reset Not Allowed"),
		}
		if user.get("_User__new_password"):
			frappe.throw(msg=error["message"], title=error["title"])
		endpoint = frappe.request and frappe.request.path
		if endpoint and endpoint.split("/")[-1] in ("frappe.core.doctype.user.user.reset_password",):
			frappe.throw(msg=error["message"], title=error["title"])
		return

	if not user.saml_managed or not frappe.get_all(
		"SAML Login Key", filters={"enable_saml_login": True, "disallow_password_update": True}
	):
		return

	error = {
		"message": _(
			"Password reset is not allowed for SAML-managed users. Please use your identity provider's password management flow."
		),
		"title": _("Password Reset Not Allowed"),
	}

	# Prevent password reset attempt from the UI (User > Settings Section > Change Password > New Password);
	# This accesses the User class instance's `__new_password` variable since the actual `new_password`
	# field from the UI is unset before this method is called.
	if user.get("_User__new_password"):
		frappe.throw(msg=error["message"], title=error["title"])

	# Prevent password reset attempts from the following UI paths:
	# 1. Login > Forgot Password
	# 2. User > Password Dropdown > Reset Password
	endpoint = frappe.request and frappe.request.path
	if endpoint:
		method = endpoint.split("/")[-1]
		if method in ("frappe.core.doctype.user.user.reset_password"):
			frappe.throw(msg=error["message"], title=error["title"])
