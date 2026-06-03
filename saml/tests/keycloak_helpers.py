# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import json
import re
import time
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
	descriptor_url = f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}/protocol/saml/descriptor"
	response = requests.get(descriptor_url, timeout=30)
	response.raise_for_status()
	match = re.search(r"<ds:X509Certificate>([^<]+)</ds:X509Certificate>", response.text)
	if not match:
		raise RuntimeError(f"No X509Certificate found in Keycloak descriptor at {descriptor_url}")

	saml_key = frappe.get_doc("SAML Login Key", provider)
	saml_key.idp_x509cert = match.group(1)
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
	saml_key = frappe.get_doc("SAML Login Key", provider)
	base_url = get_bench_base_url()
	acs_url = f"{base_url}/api/method/saml.saml.acs"
	http_host, server_port, https_on = get_bench_request_host()
	request_data = {
		"http_host": http_host,
		"script_name": f"/api/method/saml.saml.acs?provider={provider}",
		"query_string": f"provider={provider}",
		"https": "on" if https_on else "off",
	}
	if frappe.conf.get("developer_mode"):
		request_data["server_port"] = server_port
	saml_settings = saml_key.get_settings(acs_url)
	return OneLogin_Saml2_Auth(request_data, saml_settings), acs_url


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


def invoke_login(provider=PROVIDER, redirect_to=""):
	from frappe.utils import set_request

	from saml.saml import login

	configure_site_for_keycloak()
	query_string = f"provider={provider}"
	if redirect_to:
		query_string = f"{query_string}&redirect-to={redirect_to}"
	set_request(method="GET", path="/api/method/saml.saml.login", query_string=query_string)
	frappe.local.form_dict = frappe._dict(provider=provider)
	frappe.local.request.args = frappe.local.form_dict
	frappe.response = frappe._dict()
	login(provider)
	return frappe.local.response
