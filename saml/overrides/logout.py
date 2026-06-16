# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import frappe
from frappe import _

from saml.saml.logout import LOGOUT_PAGE_PATH, clear_local_session, get_logout_redirect_url


def redirect_to_url(url: str):
	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = url


@frappe.whitelist(allow_guest=True)
def logout():
	redirect_url = get_logout_redirect_url()
	clear_local_session()
	if redirect_url:
		return {"redirect_to": redirect_url}


@frappe.whitelist(allow_guest=True)
def web_logout():
	redirect_url = get_logout_redirect_url()
	clear_local_session()

	if redirect_url:
		redirect_to_url(redirect_url)
		return

	frappe.respond_as_web_page(
		_("Logged Out"), _("You have been successfully logged out"), indicator_color="green"
	)
