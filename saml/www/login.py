# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import frappe
from frappe.utils import get_url
from frappe.www.login import get_context as frappe_get_context
from frappe.www.login import no_cache, sanitize_redirect


def get_context(context):
	"""
	APP: saml
	HASH: c39dab2f46c3ecfed56db788f5e4880f39964ff4
	REPO: https://github.com/frappe/frappe/
	PATH: frappe/www/login.py
	METHOD: get_context
	"""
	frappe_get_context(context)
	add_saml_provider_logins(context)


def add_saml_provider_logins(context):
	redirect_to = sanitize_redirect(frappe.local.request.args.get("redirect-to"))
	saml_providers = []

	for provider in frappe.get_all(
		"SAML Login Key",
		filters={"enable_saml_login": 1},
		fields=["name", "provider_name"],
		order_by="name",
	):
		login_url = f"/api/method/saml.saml.login?provider={provider.name}"
		if redirect_to:
			login_url = f"{login_url}&redirect-to={redirect_to}"

		saml_providers.append(
			{
				"name": provider.name,
				"provider_name": provider.provider_name,
				"auth_url": get_url(login_url),
			}
		)

	if not saml_providers:
		return

	context["saml_login"] = True
	context.provider_logins = saml_providers + context.provider_logins
