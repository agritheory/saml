# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.core.doctype.navbar_settings.navbar_settings import get_app_logo
from frappe.utils import cint

no_cache = True


def get_context(context):
	context.no_header = True
	context.title = _("Logged Out")
	context.message = _("You have been logged out of {0}.").format(
		frappe.get_website_settings("app_name") or frappe.get_system_settings("app_name") or _("Frappe")
	)
	context.logo = get_app_logo()
	context.app_name = (
		frappe.get_website_settings("app_name") or frappe.get_system_settings("app_name") or _("Frappe")
	)
	context.show_footer_on_login = cint(frappe.get_website_settings("show_footer_on_login"))
