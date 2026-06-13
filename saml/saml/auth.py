# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import frappe

from saml.saml.doctype.saml_login_key.saml_login_key import get_auto_saml_provider


def before_request():
	if frappe.session.user != "Guest":
		return

	request = frappe.local.request
	if not request or request.method != "GET":
		return

	path = request.path or ""
	if not should_auto_saml_login(path):
		return

	provider = get_auto_saml_provider()
	if not provider:
		return

	initiate_saml_login(provider, redirect_to=path, passive=True)


def website_path_resolver(path):
	if frappe.local.flags.get("saml_auto_redirect_url"):
		frappe.flags.redirect_location = frappe.local.flags.saml_auto_redirect_url
		raise frappe.Redirect

	from frappe.website.path_resolver import resolve_path

	return resolve_path(path)


def should_auto_saml_login(path: str) -> bool:
	return path == "/app" or path.startswith("/app/")


def initiate_saml_login(
	provider: str,
	redirect_to: str,
	passive: bool = False,
	raise_redirect: bool = False,
):
	from saml.saml import build_saml_login_redirect

	redirect_url = build_saml_login_redirect(provider, redirect_to=redirect_to, is_passive=passive)

	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = redirect_url
	frappe.local.flags.saml_auto_redirect_url = redirect_url
	frappe.local.flags.redirect_location = redirect_url

	if raise_redirect:
		raise frappe.Redirect


def is_passive_auth_failure(errors: list | None, error_reason: str | None) -> bool:
	combined = " ".join(errors or []) + " " + (error_reason or "")
	combined_lower = combined.lower()
	passive_markers = (
		"nopassive",
		"no_passive",
		"urn:oasis:names:tc:saml:2.0:status:authnfailed",
	)
	return any(marker in combined_lower for marker in passive_markers)
