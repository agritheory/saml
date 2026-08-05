# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import frappe
from frappe.www.login import sanitize_redirect
from urllib.parse import urlparse

SAML_REDIRECT_CACHE_PREFIX = "saml_redirect:"
SAML_REDIRECT_REQ_CACHE_PREFIX = "saml_redirect_req:"
SAML_REDIRECT_CACHE_TTL = 600
SAML_RELAY_STATE_MAX_LENGTH = 80


def sanitize_redirect_path(path: str | None) -> str:
	"""Ensure redirect path is a safe relative URL, not an open redirect."""
	if not path:
		return ""
	path = path.strip()
	if path.startswith("//") or "://" in path:
		return ""
	if not path.startswith("/"):
		return ""
	return path


def normalize_saml_redirect_to(redirect_to: str | None) -> str:
	"""Validate with Frappe sanitize_redirect and return a safe relative path+query."""
	if not redirect_to:
		return ""

	redirect_to = redirect_to.strip()
	if not redirect_to:
		return ""

	safe = sanitize_redirect(redirect_to)
	if not safe:
		return ""

	parsed = urlparse(safe)
	if parsed.scheme or parsed.netloc:
		if parsed.netloc and not hosts_match(parsed.netloc):
			return ""
		path = parsed.path or "/"
		if parsed.query:
			path = f"{path}?{parsed.query}"
		return sanitize_redirect_path(path)

	return sanitize_redirect_path(safe)


def hosts_match(redirect_host: str) -> bool:
	request_url = frappe.local.request.url if frappe.local.request else ""
	if not request_url:
		return False

	request_host = urlparse(request_url).netloc
	if redirect_host == request_host:
		return True

	host_name = frappe.conf.get("host_name")
	if not host_name:
		return False

	return urlparse(host_name).netloc == redirect_host


def prepare_saml_relay_state(redirect_to: str) -> str:
	"""Return RelayState sent to the IdP: a short path or an opaque cache token."""
	if not redirect_to:
		return ""

	if len(redirect_to) <= SAML_RELAY_STATE_MAX_LENGTH and redirect_to.startswith("/"):
		return redirect_to

	token = frappe.generate_hash(length=16)
	frappe.cache().set_value(
		f"{SAML_REDIRECT_CACHE_PREFIX}{token}",
		redirect_to,
		expires_in_sec=SAML_REDIRECT_CACHE_TTL,
	)
	return token


def store_pending_saml_redirect(request_id: str | None, redirect_to: str) -> None:
	if not request_id or not redirect_to:
		return

	frappe.cache().set_value(
		f"{SAML_REDIRECT_REQ_CACHE_PREFIX}{request_id}",
		redirect_to,
		expires_in_sec=SAML_REDIRECT_CACHE_TTL,
	)


def pop_cached_saml_redirect(cache_key: str, consume: bool = True) -> str | None:
	value = frappe.cache().get_value(cache_key)
	if value is not None and consume:
		frappe.cache().delete_value(cache_key)
	return value


def resolve_saml_redirect(
	relay_state: str | None, request_id: str | None = None, *, consume: bool = True
) -> str:
	"""Resolve post-login destination from request ID cache, token cache, or RelayState."""
	if request_id:
		cached = pop_cached_saml_redirect(
			f"{SAML_REDIRECT_REQ_CACHE_PREFIX}{request_id}", consume=consume
		)
		if cached:
			return cached

	if relay_state:
		relay_state = relay_state.strip()
		if relay_state:
			cached = pop_cached_saml_redirect(f"{SAML_REDIRECT_CACHE_PREFIX}{relay_state}", consume=consume)
			if cached:
				return cached

			path = sanitize_redirect_path(relay_state)
			if path:
				return path

			path = normalize_saml_redirect_to(relay_state)
			if path:
				return path

	return ""


def get_pending_saml_redirect_request_id(client) -> str | None:
	"""Return the AuthnRequest ID tied to a processed SAML response."""
	return client.get_last_response_in_response_to() or client.get_last_request_id()
