# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import frappe
from frappe import _

from saml.saml.doctype.saml_login_key.saml_login_key import get_auto_saml_provider

LOGOUT_PAGE_PATH = "/logout"


def redirect_to_logout_page():
	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = LOGOUT_PAGE_PATH


@frappe.whitelist(allow_guest=True)
def logout():
	frappe.local.login_manager.logout()
	frappe.db.commit()


@frappe.whitelist(allow_guest=True)
def web_logout():
	frappe.local.login_manager.logout()
	frappe.db.commit()

	if get_auto_saml_provider():
		redirect_to_logout_page()
		return

	frappe.respond_as_web_page(
		_("Logged Out"), _("You have been successfully logged out"), indicator_color="green"
	)
