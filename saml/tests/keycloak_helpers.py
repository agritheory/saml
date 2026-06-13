# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import json
import re
import time
import base64
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import frappe
import requests
from onelogin.saml2.auth import OneLogin_Saml2_Auth

KEYCLOAK_BASE_URL = "http://localhost:8080"
KEYCLOAK_REALM = "frappe"
KEYCLOAK_HEALTH_URL = f"{KEYCLOAK_BASE_URL}/health/ready"
PROVIDER = "keycloak"


def get_webserver_port():
	port = frappe.get_conf().get("webserver_port")
	if port:
		return port
	config_path = Path(frappe.get_site_path("..", "common_site_config.json"))
	if config_path.is_file():
		return json.loads(config_path.read_text()).get("webserver_port", 8000)
	return 8000


def get_bench_base_url():
	port = get_webserver_port()
	host_name = frappe.conf.get("host_name") or ""
	if host_name:
		if not host_name.startswith("http"):
			host_name = f"http://{host_name}"
		parsed = urlparse(host_name)
		hostname = parsed.hostname or "localhost"
		scheme = parsed.scheme or "http"
		if hostname in ("localhost", "127.0.0.1"):
			return f"{scheme}://{hostname}:{port}"
		if parsed.port:
			return host_name.rstrip("/")
		return f"{scheme}://{hostname}:{port}"

	return f"http://localhost:{port}"


def get_bench_request_host():
	parsed = urlparse(get_bench_base_url())
	host = parsed.hostname or "localhost"
	if parsed.port:
		host = f"{host}:{parsed.port}"
	return host, parsed.port or 80, parsed.scheme == "https"


class SAMLFormParser(HTMLParser):
	def __init__(self):
		super().__init__()
		self.forms = []
		self.current_form = None

	def handle_starttag(self, tag, attrs):
		attrs_dict = dict(attrs)
		if tag == "form":
			self.current_form = {"action": attrs_dict.get("action", ""), "fields": {}}
		elif tag == "input" and self.current_form is not None:
			name = attrs_dict.get("name")
			if name:
				self.current_form["fields"][name] = attrs_dict.get("value", "")

	def handle_endtag(self, tag):
		if tag == "form" and self.current_form is not None:
			self.forms.append(self.current_form)
			self.current_form = None


def sync_keycloak_idp_certificate(provider=PROVIDER):
	"""Update SAML Login Key IdP cert from the running Keycloak realm descriptor."""
	saml_key = frappe.get_doc("SAML Login Key", provider)
	saml_key.sync_idp_certificate_from_descriptor()
	saml_key.save(ignore_permissions=True)


def wait_for_keycloak(timeout=120):
	deadline = time.time() + timeout
	while time.time() < deadline:
		try:
			response = requests.get(KEYCLOAK_HEALTH_URL, timeout=5)
			if response.status_code == 200:
				return
		except requests.RequestException:
			pass
		time.sleep(2)
	raise RuntimeError(f"Keycloak not ready at {KEYCLOAK_HEALTH_URL}")


def configure_site_for_keycloak():
	port = get_webserver_port()
	frappe.conf.host_name = f"http://localhost:{port}"


def build_saml_auth(provider=PROVIDER):
	from frappe.utils import set_request
	from werkzeug.datastructures import ImmutableMultiDict

	from saml.saml import get_request_data

	configure_site_for_keycloak()
	http_host, server_port, https_on = get_bench_request_host()
	set_request(
		method="GET",
		path="/api/method/saml.saml.login",
		query_string=f"provider={provider}",
		headers={"Host": http_host},
	)
	if frappe.conf.get("developer_mode"):
		frappe.local.request.environ["SERVER_PORT"] = str(server_port)
	frappe.local.request.args = ImmutableMultiDict([("provider", provider)])

	saml_key = frappe.get_doc("SAML Login Key", provider)
	acs_url = frappe.utils.get_url(f"/api/method/saml.saml.acs?provider={provider}")
	saml_settings = saml_key.get_settings(acs_url)
	return OneLogin_Saml2_Auth(get_request_data(provider), saml_settings), acs_url


def parse_forms(html, base_url):
	parser = SAMLFormParser()
	parser.feed(html)
	forms = []
	for form in parser.forms:
		action = form["action"] or base_url
		if not urlparse(action).netloc:
			action = urljoin(base_url, action)
		forms.append({"action": action, "fields": form["fields"]})
	return forms


def keycloak_error_message(html):
	match = re.search(
		r'id="kc-error-message"[^>]*>.*?<p class="instruction">([^<]+)',
		html,
		flags=re.IGNORECASE | re.DOTALL,
	)
	if match:
		return match.group(1).strip()
	return None


def extract_saml_response(html):
	saml_response = None
	relay_state = ""
	for match in re.finditer(
		r'<input[^>]*\bname=["\']([^"\']+)["\'][^>]*\bvalue=["\']([^"\']*)["\']',
		html,
		flags=re.IGNORECASE,
	):
		name, value = match.group(1), match.group(2)
		if name == "SAMLResponse":
			saml_response = value
		elif name == "RelayState":
			relay_state = value
	if not saml_response:
		for match in re.finditer(
			r'<input[^>]*\bvalue=["\']([^"\']*)["\'][^>]*\bname=["\']([^"\']+)["\']',
			html,
			flags=re.IGNORECASE,
		):
			value, name = match.group(1), match.group(2)
			if name == "SAMLResponse":
				saml_response = value
			elif name == "RelayState":
				relay_state = value
	return saml_response, relay_state


def has_authenticated_saml_assertion(saml_response: str) -> bool:
	try:
		root = ET.fromstring(base64.b64decode(saml_response))
	except (ValueError, TypeError, ET.ParseError):
		return False

	status_codes = [elem.get("Value", "") for elem in root.iter() if elem.tag.endswith("StatusCode")]
	if status_codes and not any("status:success" in value.lower() for value in status_codes):
		return False

	for elem in root.iter():
		if not elem.tag.endswith("Assertion"):
			continue
		for child in elem.iter():
			if child.tag.endswith("NameID") and (child.text or "").strip():
				return True

	return False


def complete_keycloak_login(username, password):
	configure_site_for_keycloak()
	auth, acs_url = build_saml_auth()
	redirect_url = auth.login(return_to="/app")
	session = requests.Session()
	response = session.get(redirect_url, timeout=30)
	attempts = 0

	while attempts < 10:
		attempts += 1
		error_message = keycloak_error_message(response.text)
		if error_message:
			raise RuntimeError(f"Keycloak error: {error_message} (url {response.url})")

		saml_response, relay_state = extract_saml_response(response.text)
		if saml_response:
			if not has_authenticated_saml_assertion(saml_response):
				raise RuntimeError("Expected silent SSO but Keycloak passive authentication failed")
			return saml_response, relay_state, acs_url

		forms = parse_forms(response.text, response.url)
		login_form = next(
			(form for form in forms if "username" in form["fields"] or "password" in form["fields"]),
			None,
		)
		if login_form:
			fields = login_form["fields"]
			fields["username"] = username
			fields["password"] = password
			response = session.post(login_form["action"], data=fields, timeout=30, allow_redirects=True)
			continue

		submit_form = next((form for form in forms if "SAMLResponse" in form["fields"]), None)
		if submit_form:
			response = session.post(
				submit_form["action"], data=submit_form["fields"], timeout=30, allow_redirects=True
			)
			continue

		feedback = re.search(
			r'class="[^"]*kc-feedback-text[^"]*"[^>]*>([^<]+)<',
			response.text,
			flags=re.IGNORECASE,
		)
		if feedback:
			raise RuntimeError(f"Keycloak login failed: {feedback.group(1).strip()}")

		raise RuntimeError(
			f"Unable to complete Keycloak SAML login flow (status {response.status_code}, url {response.url})"
		)

	raise RuntimeError("Keycloak SAML login exceeded maximum redirect attempts")


def setup_acs_request(saml_response, relay_state="", provider=PROVIDER):
	from urllib.parse import urlencode

	from frappe.utils import set_request
	from werkzeug.datastructures import ImmutableMultiDict

	configure_site_for_keycloak()
	http_host, server_port, https_on = get_bench_request_host()
	query_string = f"provider={provider}" if provider else ""
	set_request(
		method="POST",
		path="/api/method/saml.saml.acs",
		query_string=query_string,
		content_type="application/x-www-form-urlencoded",
		data=urlencode({"SAMLResponse": saml_response, "RelayState": relay_state}),
		headers={"Host": http_host},
	)
	if frappe.conf.get("developer_mode"):
		frappe.local.request.environ["SERVER_PORT"] = str(server_port)
	form_dict = frappe._dict(SAMLResponse=saml_response, RelayState=relay_state)
	if provider:
		form_dict.provider = provider
	frappe.local.form_dict = form_dict
	if provider:
		frappe.local.request.args = ImmutableMultiDict([("provider", provider)])
	else:
		frappe.local.request.args = ImmutableMultiDict()
	frappe.request = frappe.local.request


def invoke_acs(saml_response, relay_state="", provider=PROVIDER):
	from frappe.auth import CookieManager, LoginManager

	from saml.saml import acs

	setup_acs_request(saml_response, relay_state, provider)
	frappe.local.cookie_manager = CookieManager()
	frappe.local.login_manager = LoginManager()
	frappe.response = frappe._dict()
	frappe.set_user("Guest")
	acs()


def invoke_login(provider=PROVIDER, redirect_to="", passive=False):
	from frappe.utils import set_request

	from saml.saml import login

	configure_site_for_keycloak()
	query_string = f"provider={provider}"
	if redirect_to:
		query_string = f"{query_string}&redirect-to={redirect_to}"
	if passive:
		query_string = f"{query_string}&passive=1"
	set_request(method="GET", path="/api/method/saml.saml.login", query_string=query_string)
	form_dict = frappe._dict(provider=provider)
	if redirect_to:
		form_dict["redirect-to"] = redirect_to
	if passive:
		form_dict.passive = 1
	frappe.local.form_dict = form_dict
	frappe.local.request.args = form_dict
	frappe.response = frappe._dict()
	login(provider)
	return frappe.local.response


def fetch_keycloak_passive_failure_saml(redirect_to="/app/sales"):
	configure_site_for_keycloak()
	session = requests.Session()
	auth, acs_url = build_saml_auth()
	redirect_url = auth.login(return_to=redirect_to, is_passive=True)
	response = session.get(redirect_url, timeout=30, allow_redirects=True)
	attempts = 0

	while attempts < 10:
		attempts += 1
		error_message = keycloak_error_message(response.text)
		if error_message:
			raise RuntimeError(f"Keycloak error: {error_message} (url {response.url})")

		saml_response, relay_state = extract_saml_response(response.text)
		if saml_response:
			if has_authenticated_saml_assertion(saml_response):
				raise RuntimeError("Expected passive SAML failure but received authenticated assertion")
			return saml_response, relay_state, acs_url

		forms = parse_forms(response.text, response.url)
		submit_form = next((form for form in forms if "SAMLResponse" in form["fields"]), None)
		if submit_form:
			response = session.post(
				submit_form["action"], data=submit_form["fields"], timeout=30, allow_redirects=True
			)
			continue

		login_form = next(
			(form for form in forms if "username" in form["fields"] or "password" in form["fields"]),
			None,
		)
		if login_form:
			raise RuntimeError("Keycloak returned login form without a passive failure SAML response")

		raise RuntimeError(
			f"Unable to fetch passive failure SAML response (status {response.status_code}, url {response.url})"
		)

	raise RuntimeError("Fetching passive failure SAML response exceeded maximum redirect attempts")


def establish_keycloak_idp_session(username, password):
	configure_site_for_keycloak()
	session = requests.Session()
	auth, _ = build_saml_auth()
	redirect_url = auth.login(return_to="/app")
	response = session.get(redirect_url, timeout=30, allow_redirects=True)
	attempts = 0

	while attempts < 10:
		attempts += 1
		error_message = keycloak_error_message(response.text)
		if error_message:
			raise RuntimeError(f"Keycloak error: {error_message} (url {response.url})")

		saml_response, relay_state = extract_saml_response(response.text)
		if saml_response:
			return session

		forms = parse_forms(response.text, response.url)
		login_form = next(
			(form for form in forms if "username" in form["fields"] or "password" in form["fields"]),
			None,
		)
		if login_form:
			fields = login_form["fields"]
			fields["username"] = username
			fields["password"] = password
			response = session.post(login_form["action"], data=fields, timeout=30, allow_redirects=True)
			continue

		submit_form = next((form for form in forms if "SAMLResponse" in form["fields"]), None)
		if submit_form:
			return session

		feedback = re.search(
			r'class="[^"]*kc-feedback-text[^"]*"[^>]*>([^<]+)<',
			response.text,
			flags=re.IGNORECASE,
		)
		if feedback:
			raise RuntimeError(f"Keycloak login failed: {feedback.group(1).strip()}")

		raise RuntimeError(
			f"Unable to establish Keycloak IdP session (status {response.status_code}, url {response.url})"
		)

	raise RuntimeError("Establishing Keycloak IdP session exceeded maximum redirect attempts")


def complete_silent_saml_login(session, redirect_to="/app"):
	configure_site_for_keycloak()
	auth, acs_url = build_saml_auth()
	redirect_url = auth.login(return_to=redirect_to, is_passive=True)
	response = session.get(redirect_url, timeout=30, allow_redirects=True)
	attempts = 0

	while attempts < 10:
		attempts += 1
		error_message = keycloak_error_message(response.text)
		if error_message:
			raise RuntimeError(f"Keycloak error: {error_message} (url {response.url})")

		forms = parse_forms(response.text, response.url)
		login_form = next(
			(form for form in forms if "username" in form["fields"] or "password" in form["fields"]),
			None,
		)
		if login_form:
			raise RuntimeError("Expected silent SSO but Keycloak login form was shown")

		saml_response, relay_state = extract_saml_response(response.text)
		if saml_response:
			if not has_authenticated_saml_assertion(saml_response):
				raise RuntimeError("Expected silent SSO but Keycloak passive authentication failed")
			return saml_response, relay_state, acs_url

		submit_form = next((form for form in forms if "SAMLResponse" in form["fields"]), None)
		if submit_form:
			response = session.post(
				submit_form["action"], data=submit_form["fields"], timeout=30, allow_redirects=True
			)
			continue

		raise RuntimeError(
			f"Unable to complete silent Keycloak SAML login (status {response.status_code}, url {response.url})"
		)

	raise RuntimeError("Silent Keycloak SAML login exceeded maximum redirect attempts")


STALE_KEYCLOAK_IDP_CERT = "MIICmzCCAYMCBgGVswxgATANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZmcmFwcGUwHhcNMjUwMzIwMTAxMzA3WhcNMzUwMzIwMTAxNDQ3WjARMQ8wDQYDVQQDDAZmcmFwcGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCztca132gActAvTXMd4S2g+l1jgm2s0VWhdqXcZm2yDBJKqEgj1MxxcQt2xrSiKy99dlerQR/O1FwtCsaDKaMW+1aQ8tur3qIMxq1IM/QtayC8yiMBVPR/+2OCye51U48sJ7eqjU+7xhPYYNUSm48tiN8zm1U4oj7ZZmo79HjLW1ZKWodnkj4Rz6yhNrmh9+QXYb1a3gIu5exAE6PepcjUNjVC4YdokBad4JxpVI+o7j3xJftzhxt5wM6OT5Uwu4IIiRSwABCrlZ0s5b1gG7mQd+0YV1/59e+Zfdq6MUd5bdYF+lhTzxyl0aFgvglucKJL6q0FGFvsHdJXR0qoOB07AgMBAAEwDQYJKoZIhvcNAQELBQADggEBABRYzhFMJmXVX3AdkFzSxxjdUbxyynxbFLVI9MxVWhHEUsTBzXpDGS6nR8k1BSfyStCpWdClMu6kDC7FIHbAIKMpNNr68Zu3w3m6dfLmWpjBHYrqkslwAy873mV5aOWPqonsXHf06DUTKzsRuqIsK5DzdB2+E+FsaA/FiHr7B9ZMbGLh7641yXx8Yry+qOrMuDovJpMh4gF0BTezJuqrdgE+t/dYVyV4wKrNIZ5O7wK+J6rfhiYgh4sq1hw7+YrHwojlr6mxZadRursa1TQ+Tn5nhu/AZVpnugBmFdFI6mPKru8qDUas3KEjRHTKF6gJUj0GW0aCmKo5Zpgkv5Bs49g="


def render_pending_saml_redirect(path):
	from saml.saml.auth import website_path_resolver
	from frappe.website.page_renderers.redirect_page import RedirectPage

	try:
		website_path_resolver(path)
	except frappe.Redirect:
		return RedirectPage(path).render()

	raise RuntimeError("Expected frappe.Redirect from website_path_resolver")


def complete_guest_auto_saml_login(session, path="/app/user"):
	from saml.saml.auth import before_request

	setup_guest_get_request(path)
	before_request()
	redirect_url = frappe.local.flags.get("saml_auto_redirect_url")
	if not redirect_url:
		raise RuntimeError("auto SAML redirect URL was not prepared")

	response = session.get(redirect_url, timeout=30, allow_redirects=True)
	attempts = 0

	while attempts < 10:
		attempts += 1
		error_message = keycloak_error_message(response.text)
		if error_message:
			raise RuntimeError(f"Keycloak error: {error_message} (url {response.url})")

		forms = parse_forms(response.text, response.url)
		login_form = next(
			(form for form in forms if "username" in form["fields"] or "password" in form["fields"]),
			None,
		)
		if login_form:
			raise RuntimeError("Expected silent SSO but Keycloak login form was shown")

		saml_response, relay_state = extract_saml_response(response.text)
		if saml_response:
			if not has_authenticated_saml_assertion(saml_response):
				raise RuntimeError("Expected silent SSO but Keycloak passive authentication failed")
			return saml_response, relay_state

		submit_form = next((form for form in forms if "SAMLResponse" in form["fields"]), None)
		if submit_form:
			response = session.post(
				submit_form["action"], data=submit_form["fields"], timeout=30, allow_redirects=True
			)
			continue

		raise RuntimeError(
			f"Unable to complete guest auto SAML login (status {response.status_code}, url {response.url})"
		)

	raise RuntimeError("Guest auto SAML login exceeded maximum redirect attempts")


def setup_guest_get_request(path="/app"):
	from frappe.auth import CookieManager, LoginManager
	from frappe.utils import set_request

	configure_site_for_keycloak()
	http_host, server_port, https_on = get_bench_request_host()
	set_request(method="GET", path=path, headers={"Host": http_host})
	if frappe.conf.get("developer_mode"):
		frappe.local.request.environ["SERVER_PORT"] = str(server_port)
	frappe.local.cookie_manager = CookieManager()
	frappe.local.login_manager = LoginManager()
	frappe.set_user("Guest")


def resume_guest_get_request(path="/app", sid=None):
	from frappe.auth import CookieManager, LoginManager
	from frappe.utils import set_request

	configure_site_for_keycloak()
	http_host, server_port, https_on = get_bench_request_host()
	headers = {"Host": http_host}
	if sid:
		headers["Cookie"] = f"sid={sid}"
	set_request(method="GET", path=path, headers=headers)
	if frappe.conf.get("developer_mode"):
		frappe.local.request.environ["SERVER_PORT"] = str(server_port)
	if sid:
		frappe.local.form_dict = frappe._dict(sid=sid)
	frappe.local.cookie_manager = CookieManager()
	frappe.local.login_manager = LoginManager()
