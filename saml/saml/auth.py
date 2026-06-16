# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import frappe

from saml.saml.doctype.saml_login_key.saml_login_key import (
	get_auto_saml_provider,
	get_auto_saml_settings,
)

AUTO_SAML_EXCLUDED_PREFIXES = (
	"/api/",
	"/assets/",
	"/files/",
	"/private/",
)

AUTO_SAML_EXCLUDED_PATHS = (
	"/api/method/saml.saml.login",
	"/api/method/saml.saml.acs",
	"/api/method/saml.saml.logout.slo",
	"/",
	"/logout",
	"/login",
)

AUTO_SAML_EXCLUDED_EXTENSIONS = (
	".css",
	".eot",
	".gif",
	".ico",
	".jpeg",
	".jpg",
	".js",
	".map",
	".png",
	".svg",
	".ttf",
	".webp",
	".woff",
	".woff2",
)

AUTO_SAML_SCOPE_ALL_GUEST_ROUTES = "All Guest Routes"
AUTO_SAML_SCOPE_CONFIGURED_PATHS = "Configured Paths"
AUTO_SAML_SCOPE_DESK_ONLY = "Desk Only"


def normalize_request_path(path: str) -> str:
	path = path or "/"
	if len(path) > 1:
		path = path.rstrip("/")
	return path


def extend_bootinfo(bootinfo):
	from saml.saml.logout import uses_custom_logout_redirect

	bootinfo["saml_auto_saml_login"] = bool(get_auto_saml_provider())
	bootinfo["saml_custom_logout_redirect"] = uses_custom_logout_redirect()


def before_request():
	if frappe.session.user != "Guest":
		return

	request = frappe.local.request
	if not request or request.method != "GET":
		return

	path = normalize_request_path(request.path or "")

	if path == "/" and get_auto_saml_provider():
		redirect_to_login_page(request)
		return

	if not should_auto_saml_login(path):
		return

	provider = get_auto_saml_provider()
	if not provider:
		return

	initiate_saml_login(provider, redirect_to=get_auto_saml_redirect_to(request), passive=True)


def website_path_resolver(path):
	if frappe.local.flags.get("saml_auto_redirect_url"):
		frappe.flags.redirect_location = frappe.local.flags.saml_auto_redirect_url
		raise frappe.Redirect

	from frappe.website.path_resolver import resolve_path

	return resolve_path(path)


def should_auto_saml_login(path: str) -> bool:
	path = normalize_request_path(path)
	if is_auto_saml_excluded_path(path):
		return False

	settings = get_auto_saml_settings()
	if not settings:
		return False

	scope = settings.get("auto_saml_scope") or AUTO_SAML_SCOPE_ALL_GUEST_ROUTES
	if scope == AUTO_SAML_SCOPE_ALL_GUEST_ROUTES:
		return True
	if scope == AUTO_SAML_SCOPE_DESK_ONLY:
		return path == "/app" or path.startswith("/app/")
	if scope == AUTO_SAML_SCOPE_CONFIGURED_PATHS:
		return path_matches_configured_auto_saml_paths(path, settings.get("auto_saml_paths") or "")
	return False


def is_auto_saml_excluded_path(path: str) -> bool:
	path = normalize_request_path(path)
	if path in AUTO_SAML_EXCLUDED_PATHS:
		return True
	if any(path.startswith(prefix) for prefix in AUTO_SAML_EXCLUDED_PREFIXES):
		return True
	lower_path = path.lower()
	return any(lower_path.endswith(extension) for extension in AUTO_SAML_EXCLUDED_EXTENSIONS)


def path_matches_configured_auto_saml_paths(path: str, paths: str) -> bool:
	for line in paths.splitlines():
		rule = line.strip()
		if not rule:
			continue
		if path_matches_auto_saml_rule(path, rule):
			return True
	return False


def path_matches_auto_saml_rule(path: str, rule: str) -> bool:
	if rule.endswith("/*"):
		base = rule[:-2]
		return path == base or path.startswith(f"{base}/")
	return path == rule


def get_auto_saml_redirect_to(request) -> str:
	path = request.path or ""
	query_string = request.query_string
	if isinstance(query_string, bytes):
		query_string = query_string.decode()
	if query_string:
		return f"{path}?{query_string}"
	return path


def redirect_to_login_page(request):
	login_path = "/login"
	query_string = request.query_string
	if isinstance(query_string, bytes):
		query_string = query_string.decode()
	if query_string:
		login_path = f"{login_path}?{query_string}"

	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = login_path
	frappe.local.flags.saml_auto_redirect_url = login_path
	frappe.local.flags.redirect_location = login_path


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
