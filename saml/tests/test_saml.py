# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import base64
import requests
from contextlib import contextmanager
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlparse

import frappe
import pytest
from frappe.utils.password import get_decrypted_password, update_password
from onelogin.saml2.utils import OneLogin_Saml2_Utils

import saml.tests.keycloak_helpers as keycloak
from saml.tests.keycloak_helpers import get_test_saml_login_key, get_test_saml_provider
from saml.overrides.user import validate_reset_password
from saml.saml import (
	acs,
	determine_provider_from_saml_response,
	get_request_data,
	is_passive_saml_status_response,
	saml_response_has_authenticated_assertion,
	sanitize_redirect_path,
	should_retry_interactive_saml_login,
)
from saml.saml.auth import (
	before_request,
	consume_skip_passive_saml_token,
	create_skip_passive_saml_token,
	is_auto_saml_excluded_path,
	is_login_relay_state,
	is_passive_auth_failure,
	path_matches_auto_saml_rule,
	should_auto_saml_login,
	website_path_resolver,
)
from saml.saml.redirects import (
	get_pending_saml_redirect_request_id,
	normalize_saml_redirect_to,
	prepare_saml_relay_state,
	resolve_saml_redirect,
	store_pending_saml_redirect,
)
from saml.saml.doctype.saml_login_key.saml_login_key import (
	SAMLLoginKey,
	get_auto_saml_provider,
	run_scheduled_idp_metadata_syncs,
	sync_idp_certificate,
)


UNKNOWN_SAML_ISSUER_RESPONSE = base64.b64encode(
	b"""<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://unknown.example.com/realms/other</saml:Issuer>
</samlp:Response>"""
).decode()


@pytest.fixture(scope="session")
def keycloak_session():
	keycloak.ensure_keycloak_test_environment()


def assert_redirect_targets_idp(redirect_url):
	idp_parsed = urlparse(get_test_saml_login_key().idp_sso_url)
	redirect_parsed = urlparse(redirect_url)
	assert redirect_parsed.netloc == idp_parsed.netloc


def decode_saml_request(redirect_url):
	query_params = parse_qs(urlparse(redirect_url).query)
	saml_request = unquote(query_params["SAMLRequest"][0])
	decoded = OneLogin_Saml2_Utils.decode_base64_and_inflate(saml_request)
	if isinstance(decoded, bytes):
		decoded = decoded.decode()
	return decoded


@contextmanager
def auto_saml_settings(enabled=True, scope=None, paths=None):
	saml_key = get_test_saml_login_key()
	original = {
		"auto_saml_login": saml_key.auto_saml_login,
		"auto_saml_scope": saml_key.auto_saml_scope,
		"auto_saml_paths": saml_key.auto_saml_paths,
	}
	saml_key.auto_saml_login = enabled
	if scope is not None:
		saml_key.auto_saml_scope = scope
	if paths is not None:
		saml_key.auto_saml_paths = paths
	saml_key.save(ignore_permissions=True)
	try:
		yield saml_key
	finally:
		saml_key.auto_saml_login = original["auto_saml_login"]
		saml_key.auto_saml_scope = original["auto_saml_scope"]
		saml_key.auto_saml_paths = original["auto_saml_paths"]
		saml_key.save(ignore_permissions=True)


def invoke_acs_as_guest(
	saml_response,
	relay_state="",
	provider=keycloak.USE_TEST_PROVIDER,
	query_provider=keycloak.USE_TEST_PROVIDER,
):
	from frappe.auth import CookieManager, LoginManager

	keycloak.setup_acs_request(
		saml_response,
		relay_state,
		provider=provider,
		query_provider=query_provider,
	)
	frappe.local.cookie_manager = CookieManager()
	frappe.local.login_manager = LoginManager()
	frappe.local.response = frappe._dict()
	frappe.set_user("Guest")
	acs()


@pytest.mark.order(1)
def test_sanitize_redirect_path():
	assert sanitize_redirect_path("https://evil.com") == ""
	assert sanitize_redirect_path("//evil.com") == ""
	assert sanitize_redirect_path("javascript:alert(1)") == ""
	assert sanitize_redirect_path("/app") == "/app"
	assert sanitize_redirect_path("/app/user") == "/app/user"
	assert sanitize_redirect_path(None) == ""
	assert sanitize_redirect_path("") == ""


@pytest.mark.order(3)
def test_normalize_saml_redirect_to_converts_same_host_absolute_url():
	from frappe.utils import set_request

	original_host_name = frappe.conf.get("host_name")
	frappe.conf.host_name = "http://erp.ambrosiapieco.example"
	try:
		set_request(
			method="GET",
			path="/login",
			headers={"Host": "erp.ambrosiapieco.example"},
		)
		assert normalize_saml_redirect_to("http://erp.ambrosiapieco.example/app/sales") == "/app/sales"
		assert (
			normalize_saml_redirect_to("http://erp.ambrosiapieco.example/app/user?tab=1")
			== "/app/user?tab=1"
		)
	finally:
		if original_host_name is not None:
			frappe.conf.host_name = original_host_name
		elif hasattr(frappe.conf, "host_name"):
			del frappe.conf.host_name


@pytest.mark.order(3)
def test_normalize_saml_redirect_to_rejects_external_host():
	from frappe.utils import set_request

	set_request(method="GET", path="/login", headers={"Host": "erp.ambrosiapieco.example"})
	assert normalize_saml_redirect_to("https://evil.com/app") == ""


@pytest.mark.order(3)
def test_prepare_saml_relay_state_uses_path_for_short_redirects():
	assert prepare_saml_relay_state("/app/sales") == "/app/sales"


@pytest.mark.order(3)
def test_prepare_saml_relay_state_uses_token_for_long_redirects():
	long_path = "/app/" + ("x" * 80)
	token = prepare_saml_relay_state(long_path)
	assert token != long_path
	assert resolve_saml_redirect(token, None) == long_path


@pytest.mark.order(3)
def test_resolve_saml_redirect_uses_request_id_cache():
	store_pending_saml_redirect("req-123", "/app/custom")
	assert resolve_saml_redirect("", "req-123") == "/app/custom"
	assert resolve_saml_redirect("", "req-123") == ""


@pytest.mark.order(3)
def test_resolve_saml_redirect_returns_empty_without_relay_state_or_cache():
	assert resolve_saml_redirect("", None) == ""
	assert resolve_saml_redirect(None, None) == ""


@pytest.mark.order(3)
def test_resolve_saml_redirect_normalizes_absolute_relay_state():
	from frappe.utils import set_request

	original_host_name = frappe.conf.get("host_name")
	frappe.conf.host_name = "http://erp.ambrosiapieco.example"
	try:
		set_request(
			method="GET",
			path="/api/method/saml.saml.acs",
			headers={"Host": "erp.ambrosiapieco.example"},
		)
		assert resolve_saml_redirect("http://erp.ambrosiapieco.example/app/sales", None) == "/app/sales"
	finally:
		if original_host_name is not None:
			frappe.conf.host_name = original_host_name
		elif hasattr(frappe.conf, "host_name"):
			del frappe.conf.host_name


@pytest.mark.order(3)
def test_get_pending_saml_redirect_request_id_prefers_in_response_to():
	class FakeSamlClient:
		def get_last_response_in_response_to(self):
			return "authn-req-warehouse-sales"

		def get_last_request_id(self):
			return None

	assert get_pending_saml_redirect_request_id(FakeSamlClient()) == "authn-req-warehouse-sales"


@pytest.mark.order(3)
def test_is_login_relay_state_resolves_token_for_login_path():
	long_login_path = "/login?" + ("redirect-to=%2Fapp&" * 20)
	token = prepare_saml_relay_state(long_login_path)
	assert is_login_relay_state(token, None) is True


@pytest.mark.order(4)
def test_get_settings_validation_modes():
	saml_key = get_test_saml_login_key()
	original = saml_key.allow_relaxed_saml_validation
	try:
		settings = saml_key.get_settings("https://example.com/acs")
		assert settings.is_strict() is True

		saml_key.allow_relaxed_saml_validation = True
		settings = saml_key.get_settings("https://example.com/acs")
		assert settings.is_strict() is False
	finally:
		saml_key.allow_relaxed_saml_validation = original


@pytest.mark.order(4)
def test_acs_hides_sensitive_errors_outside_developer_mode():
	original_dev_mode = frappe.conf.get("developer_mode")
	frappe.conf.developer_mode = 0
	try:
		invoke_acs_as_guest("invalid-response")
		assert frappe.local.response.get("type") == "page"
		response_text = str(frappe.local.response)
		assert "Traceback" not in response_text
		assert "traceback" not in response_text.lower()
	finally:
		if original_dev_mode:
			frappe.conf.developer_mode = original_dev_mode
		else:
			frappe.conf.pop("developer_mode", None)


@pytest.mark.order(5)
def test_get_auto_saml_provider():
	saml_key = get_test_saml_login_key()
	original = saml_key.auto_saml_login
	try:
		saml_key.auto_saml_login = True
		saml_key.save(ignore_permissions=True)
		assert get_auto_saml_provider() == saml_key.name

		saml_key.auto_saml_login = False
		saml_key.save(ignore_permissions=True)
		assert get_auto_saml_provider() is None
	finally:
		saml_key.auto_saml_login = original
		saml_key.save(ignore_permissions=True)


@pytest.mark.order(7)
def test_should_auto_saml_login_by_scope():
	with auto_saml_settings(scope="All Guest Routes"):
		assert not should_auto_saml_login("/")
		assert not should_auto_saml_login("/login")
		assert should_auto_saml_login("/app/user/user-001")
		assert not should_auto_saml_login("/api/method/saml.saml.login")
		assert not should_auto_saml_login("/website_script.js")

	with auto_saml_settings(scope="Desk Only"):
		assert should_auto_saml_login("/app")
		assert should_auto_saml_login("/app/workspace")
		assert not should_auto_saml_login("/login")
		assert not should_auto_saml_login("/")

	with auto_saml_settings(scope="Configured Paths", paths="/\n/login\n/app\n/app/*"):
		assert not should_auto_saml_login("/login")
		assert not should_auto_saml_login("/")
		assert should_auto_saml_login("/app/workspace")
		assert not should_auto_saml_login("/about")


@pytest.mark.order(7)
def test_auto_saml_path_rules_and_exclusions():
	assert path_matches_auto_saml_rule("/app/user/user-001", "/app/*")
	assert path_matches_auto_saml_rule("/app", "/app/*")
	assert path_matches_auto_saml_rule("/login", "/login")
	assert not path_matches_auto_saml_rule("/login-page", "/login")

	assert is_auto_saml_excluded_path("/api/method/saml.saml.login")
	assert is_auto_saml_excluded_path("/api/method/saml.saml.logout.slo")
	assert is_auto_saml_excluded_path("/assets/saml/css/login.css")
	assert is_auto_saml_excluded_path("/website_script.js")
	assert is_auto_saml_excluded_path("/logout")
	assert is_auto_saml_excluded_path("/login")
	assert is_auto_saml_excluded_path("/")
	assert not is_auto_saml_excluded_path("/about")


@pytest.mark.order(7)
def test_auto_saml_validate_requires_configured_paths():
	saml_key = get_test_saml_login_key()
	original_scope = saml_key.auto_saml_scope
	original_paths = saml_key.auto_saml_paths
	saml_key.auto_saml_scope = "Configured Paths"
	saml_key.auto_saml_paths = ""
	try:
		with pytest.raises(frappe.exceptions.ValidationError):
			saml_key.validate()
	finally:
		saml_key.auto_saml_scope = original_scope
		saml_key.auto_saml_paths = original_paths


def reset_auto_saml_request_flags():
	for key in ("saml_auto_redirect_url", "redirect_location"):
		frappe.local.flags.pop(key, None)


@pytest.mark.order(7)
def test_before_request_auto_saml_guest_routes():
	with auto_saml_settings(scope="All Guest Routes"):
		keycloak.setup_guest_get_request("/website_script.js")
		frappe.local.response = frappe._dict()
		before_request()
		assert frappe.local.response.get("type") != "redirect"

		reset_auto_saml_request_flags()
		keycloak.setup_guest_get_request("/login?skip_passive_saml=1")
		frappe.local.response = frappe._dict()
		before_request()
		assert frappe.local.response.get("type") == "redirect"

		reset_auto_saml_request_flags()
		keycloak.setup_guest_get_request("/login?redirect-to=%2Fapp%2Fsales")
		frappe.local.response = frappe._dict()
		before_request()
		redirect_url = frappe.local.response["location"]
		relay_state = parse_qs(urlparse(redirect_url).query).get("RelayState", [None])[0]
		assert relay_state == "/app/sales"

		reset_auto_saml_request_flags()
		token = create_skip_passive_saml_token()
		keycloak.setup_guest_get_request(f"/login?skip_passive_saml={token}")
		frappe.local.response = frappe._dict()
		before_request()
		assert frappe.local.response.get("type") != "redirect"
		assert not frappe.local.flags.get("saml_auto_redirect_url")

		reset_auto_saml_request_flags()
		keycloak.setup_guest_get_request("/login")
		frappe.local.response = frappe._dict()
		before_request()
		assert frappe.local.response.get("type") == "redirect"
		assert frappe.local.flags.get("saml_auto_redirect_url")

		reset_auto_saml_request_flags()
		keycloak.setup_guest_get_request("/logout")
		frappe.local.response = frappe._dict()
		before_request()
		assert frappe.local.response.get("type") != "redirect"

		reset_auto_saml_request_flags()
		keycloak.setup_guest_get_request("/")
		frappe.local.response = frappe._dict()
		before_request()
		assert frappe.local.response.get("location") == "/login"
		assert frappe.local.flags.get("saml_auto_redirect_url") == "/login"

		reset_auto_saml_request_flags()
		keycloak.setup_guest_get_request("/about")
		frappe.local.response = frappe._dict()
		before_request()
		redirect_url = frappe.local.response["location"]
		assert parse_qs(urlparse(redirect_url).query).get("RelayState", [None])[0] == "/about"


@pytest.mark.order(8)
def test_before_request_redirects_guest_on_app_when_auto_saml_enabled():
	with auto_saml_settings():
		keycloak.setup_guest_get_request("/app/workspace")
		before_request()
		assert frappe.local.response.get("type") == "redirect"
		assert frappe.local.flags.saml_auto_redirect_url
		assert frappe.local.flags.redirect_location
		assert_redirect_targets_idp(frappe.local.response["location"])


@pytest.mark.order(9)
def test_before_request_skips_redirect_when_auto_saml_disabled():
	with auto_saml_settings(enabled=False):
		keycloak.setup_guest_get_request("/app")
		frappe.local.response = frappe._dict()
		before_request()
		assert frappe.local.response.get("type") != "redirect"


@pytest.mark.order(10)
def test_login_passive_authn_request_includes_is_passive():
	response = keycloak.invoke_login(get_test_saml_provider(), passive=True)
	assert response["type"] == "redirect"
	parsed_url = urlparse(response["location"])
	query_params = parse_qs(parsed_url.query)
	saml_request = unquote(query_params["SAMLRequest"][0])
	decoded = OneLogin_Saml2_Utils.decode_base64_and_inflate(saml_request)
	if isinstance(decoded, bytes):
		decoded = decoded.decode()
	assert "IsPassive" in decoded


@pytest.mark.order(11)
def test_passive_saml_failure_helpers():
	assert is_passive_auth_failure(["SAML Response invalid"], "NoPassiveAuth")
	assert not is_passive_auth_failure(["signature invalid"], "bad signature")


@pytest.mark.order(12)
@pytest.mark.parametrize(
	"relay_state,expected_location",
	[
		("/app/sales", "interactive"),
		("/login", "login_skip"),
		("/", "home_relay"),
	],
)
def test_acs_passive_failure_by_relay_state(keycloak_session, relay_state, expected_location):
	saml_key = get_test_saml_login_key()
	saml_response, actual_relay_state, acs_url = keycloak.fetch_keycloak_passive_failure_saml(
		redirect_to=relay_state
	)
	assert actual_relay_state == relay_state
	assert f"provider={saml_key.name}" in acs_url
	assert not saml_response_has_authenticated_assertion(saml_response)
	assert should_retry_interactive_saml_login([], None, {"SAMLResponse": saml_response})
	assert is_passive_saml_status_response(saml_response)

	keycloak.invoke_acs(saml_response, relay_state)
	assert frappe.local.response.get("type") == "redirect"
	location = frappe.local.response["location"]

	if expected_location == "interactive":
		assert_redirect_targets_idp(location)
		decoded = decode_saml_request(location)
		assert 'IsPassive="true"' not in decoded
	elif expected_location == "login_skip":
		assert location.startswith("/login?skip_passive_saml=")
		token = parse_qs(urlparse(location).query).get("skip_passive_saml", [None])[0]
		assert token
		assert consume_skip_passive_saml_token(token)
	else:
		assert parse_qs(urlparse(location).query).get("RelayState", [None])[0] == "/"


@pytest.mark.order(13)
def test_determine_provider_from_saml_response():
	saml_key = get_test_saml_login_key()
	assert (
		determine_provider_from_saml_response(keycloak.get_saml_response_with_fixture_issuer())
		== saml_key.name
	)
	assert determine_provider_from_saml_response(UNKNOWN_SAML_ISSUER_RESPONSE) is None
	assert determine_provider_from_saml_response("not-valid-base64!!!") is None
	assert determine_provider_from_saml_response(None) is None


@pytest.mark.order(16)
def test_get_request_data_by_deployment_mode():
	from frappe.utils import set_request

	original_developer_mode = frappe.conf.get("developer_mode")
	original_host_name = frappe.conf.get("host_name")

	try:
		frappe.conf.developer_mode = False
		frappe.conf.host_name = "http://erp.ambrosiapieco.example"
		set_request(
			method="GET",
			path="/api/method/saml.saml.login",
			headers={"Host": "erp.ambrosiapieco.example"},
		)
		request_data = get_request_data(get_test_saml_provider())
		assert request_data["https"] == "on"
		assert request_data["http_host"] == "erp.ambrosiapieco.example"
		assert "server_port" not in request_data

		frappe.conf.developer_mode = True
		frappe.conf.host_name = "http://localhost:8000"
		set_request(
			method="GET",
			path="/api/method/saml.saml.login",
			headers={"Host": "localhost:8000"},
		)
		frappe.local.request.environ["SERVER_PORT"] = "8000"
		request_data = get_request_data(get_test_saml_provider())
		assert request_data["https"] == "off"
		assert request_data["http_host"] == "localhost:8000"
		assert request_data["server_port"] == "8000"
	finally:
		frappe.conf.developer_mode = original_developer_mode
		if original_host_name is not None:
			frappe.conf.host_name = original_host_name
		elif hasattr(frappe.conf, "host_name"):
			del frappe.conf.host_name


@pytest.mark.order(18)
def test_validate_reset_password():
	user = frappe.new_doc("User")
	user.email = "new.hire@ambrosiapieco.example"
	validate_reset_password(user)

	warehouse_user = frappe.get_doc("User", "warehouse@ambrosiapieco.example")
	original = warehouse_user.saml_managed
	warehouse_user.saml_managed = False
	try:
		validate_reset_password(warehouse_user)
	finally:
		warehouse_user.saml_managed = original

	saml_key = get_test_saml_login_key()
	original_disallow = saml_key.disallow_password_update
	saml_key.disallow_password_update = True
	saml_key.save(ignore_permissions=True)
	managed_user = frappe.get_doc("User", "saml.existing@ambrosiapieco.example")
	managed_user.saml_managed = True
	managed_user._User__new_password = "should-not-apply"
	try:
		with pytest.raises(frappe.exceptions.ValidationError) as exc_info:
			validate_reset_password(managed_user)
		assert "Password reset is not allowed" in str(exc_info.value)
	finally:
		saml_key.disallow_password_update = original_disallow
		saml_key.save(ignore_permissions=True)
		managed_user._User__new_password = None


@pytest.mark.order(22)
def test_website_path_resolver_raises_redirect_when_auto_saml_pending():
	redirect_url = get_test_saml_login_key().idp_sso_url
	frappe.local.flags.saml_auto_redirect_url = redirect_url
	with pytest.raises(frappe.Redirect):
		website_path_resolver("app/user")
	assert frappe.flags.redirect_location == redirect_url


@pytest.mark.order(23)
def test_website_path_resolver_resolves_path_when_no_auto_saml_pending():
	frappe.local.flags.saml_auto_redirect_url = None
	endpoint = website_path_resolver("app")
	assert endpoint == "app"


@pytest.mark.order(24)
def test_guest_app_redirect_response_via_website_stack():
	saml_key = get_test_saml_login_key()
	original = saml_key.auto_saml_login
	saml_key.auto_saml_login = True
	saml_key.save(ignore_permissions=True)
	try:
		keycloak.setup_guest_get_request("/app/workspace")
		before_request()
		response = keycloak.render_pending_saml_redirect("app/workspace")
		assert response.status_code in (301, 302)
		location = response.headers.get("Location")
		assert_redirect_targets_idp(location)
	finally:
		saml_key.auto_saml_login = original
		saml_key.save(ignore_permissions=True)


@pytest.mark.order(25)
def test_before_request_skips_authenticated_user():
	saml_key = get_test_saml_login_key()
	original = saml_key.auto_saml_login
	saml_key.auto_saml_login = True
	saml_key.save(ignore_permissions=True)
	try:
		keycloak.setup_guest_get_request("/app")
		frappe.set_user("warehouse@ambrosiapieco.example")
		frappe.local.response = frappe._dict()
		before_request()
		assert frappe.local.response.get("type") != "redirect"
	finally:
		saml_key.auto_saml_login = original
		saml_key.save(ignore_permissions=True)
		frappe.set_user("Guest")


@pytest.mark.order(26)
def test_before_request_skips_non_get_requests():
	from frappe.utils import set_request

	saml_key = get_test_saml_login_key()
	original = saml_key.auto_saml_login
	saml_key.auto_saml_login = True
	saml_key.save(ignore_permissions=True)
	try:
		from frappe.auth import CookieManager, LoginManager

		keycloak.configure_site_for_keycloak()
		http_host, server_port, https_on = keycloak.get_bench_request_host()
		set_request(method="POST", path="/app", headers={"Host": http_host})
		if frappe.conf.get("developer_mode"):
			frappe.local.request.environ["SERVER_PORT"] = str(server_port)
		frappe.local.cookie_manager = CookieManager()
		frappe.local.login_manager = LoginManager()
		frappe.set_user("Guest")
		frappe.local.response = frappe._dict()
		before_request()
		assert frappe.local.response.get("type") != "redirect"
	finally:
		saml_key.auto_saml_login = original
		saml_key.save(ignore_permissions=True)


@pytest.mark.order(27)
def test_hooks_register_auto_saml_handlers():
	hooks = frappe.get_hooks()
	assert "saml.saml.auth.before_request" in hooks.get("before_request", [])
	assert "saml.saml.auth.website_path_resolver" in hooks.get("website_path_resolver", [])


@pytest.mark.order(28)
def test_acs_settings_acs_url_includes_provider_query(keycloak_session):
	saml_key = get_test_saml_login_key()
	keycloak.configure_site_for_keycloak()
	acs_url = frappe.utils.get_url(f"/api/method/saml.saml.acs?provider={saml_key.name}")
	assert f"provider={saml_key.name}" in acs_url

	saml_settings = saml_key.get_settings(acs_url)
	assert saml_settings.get_sp_data()["assertionConsumerService"]["url"] == acs_url

	login_response = keycloak.invoke_login(saml_key.name, redirect_to="/app")
	parsed_url = urlparse(login_response["location"])
	saml_request = unquote(parse_qs(parsed_url.query)["SAMLRequest"][0])
	decoded = OneLogin_Saml2_Utils.decode_base64_and_inflate(saml_request)
	if isinstance(decoded, bytes):
		decoded = decoded.decode()
	assert f"/api/method/saml.saml.acs?provider={saml_key.name}" in decoded

	saml_response, relay_state, acs_url_from_login = keycloak.complete_keycloak_login(
		"warehouse", "apc-warehouse"
	)
	assert f"provider={saml_key.name}" in acs_url_from_login
	keycloak.invoke_acs(saml_response, relay_state)
	assert frappe.local.response.get("type") == "redirect"
	assert "/app" in frappe.local.response.get("location", "")


@pytest.mark.order(30)
def test_login_generates_redirect_to_keycloak(keycloak_session):
	response = keycloak.invoke_login(get_test_saml_provider())
	assert response["type"] == "redirect"
	assert_redirect_targets_idp(response["location"])
	query_params = parse_qs(urlparse(response["location"]).query)
	saml_request = unquote(query_params["SAMLRequest"][0])
	decoded = OneLogin_Saml2_Utils.decode_base64_and_inflate(saml_request)
	if isinstance(decoded, bytes):
		decoded = decoded.decode()
	assert "AuthnRequest" in decoded
	assert "RequestedAuthnContext" not in decoded


@pytest.mark.order(35)
def test_acs_provisions_keycloak_users(keycloak_session):
	email = "picker@ambrosiapieco.example"
	if frappe.db.exists("User", email):
		frappe.delete_doc("User", email, force=True, ignore_permissions=True)

	saml_response, relay_state, acs_url = keycloak.complete_keycloak_login("picker", "apc-picker")
	keycloak.invoke_acs(saml_response, relay_state)

	user = frappe.get_doc("User", email)
	assert user.saml_managed
	assert user.first_name == "Orchard"
	assert user.last_name == "Picker"
	assert "Workspace Manager" in {row.role for row in user.roles}


@pytest.mark.order(40)
def test_acs_manages_existing_users(keycloak_session):
	warehouse_email = "warehouse@ambrosiapieco.example"
	warehouse_user = frappe.get_doc("User", warehouse_email)
	warehouse_user.saml_managed = False
	warehouse_user.save(ignore_permissions=True)
	update_password(warehouse_email, "local-password")

	saml_response, relay_state, acs_url = keycloak.complete_keycloak_login(
		"warehouse", "apc-warehouse"
	)
	keycloak.invoke_acs(saml_response, relay_state)
	warehouse_user.reload()
	assert warehouse_user.saml_managed
	assert not get_decrypted_password("User", warehouse_email, raise_exception=False)

	existing_email = "saml.existing@ambrosiapieco.example"
	saml_response, relay_state, acs_url = keycloak.complete_keycloak_login(
		"saml.existing", "apc-saml-existing"
	)
	keycloak.invoke_acs(saml_response, relay_state)
	assert frappe.get_doc("User", existing_email).saml_managed


@pytest.mark.order(55)
@pytest.mark.parametrize(
	"keycloak_user,password,expected_role,create_user",
	[
		("saml.admin", "apc-saml-admin", "System Manager", True),
		("warehouse", "apc-warehouse", "Report Manager", False),
	],
)
def test_acs_applies_role_from_keycloak(
	keycloak_session, keycloak_user, password, expected_role, create_user
):
	email = f"{keycloak_user}@ambrosiapieco.example"
	if create_user and not frappe.db.exists("User", email):
		user = frappe.new_doc("User")
		user.update(
			{
				"email": email,
				"first_name": "SAML",
				"last_name": "Admin",
				"enabled": True,
				"send_welcome_email": False,
			}
		)
		user.insert(ignore_permissions=True)

	saml_response, relay_state, acs_url = keycloak.complete_keycloak_login(keycloak_user, password)
	keycloak.invoke_acs(saml_response, relay_state)
	roles = {row.role for row in frappe.get_doc("User", email).roles}
	assert expected_role in roles


@pytest.mark.order(56)
def test_acs_applies_role_profile_from_keycloak(keycloak_session):
	email = "kb.contributor@ambrosiapieco.example"
	saml_response, relay_state, acs_url = keycloak.complete_keycloak_login(
		"kb.contributor", "apc-kb-contributor"
	)
	keycloak.invoke_acs(saml_response, relay_state)

	user = frappe.get_doc("User", email)
	assert user.first_name == "Knowledge"
	assert user.last_name == "Contributor"
	assert user.role_profile_name == "Knowledge Base"


@pytest.mark.order(57)
def test_acs_removes_unmatched_roles_when_match_enabled(keycloak_session):
	email = "kb.contributor@ambrosiapieco.example"
	frappe.set_user("Administrator")
	user = frappe.get_doc("User", email)
	user.append("roles", {"role": "Purchase User"})
	user.save(ignore_permissions=True)

	saml_key = get_test_saml_login_key()
	original_match = saml_key.match_saml_roles
	saml_key.match_saml_roles = True
	saml_key.save(ignore_permissions=True)

	try:
		saml_response, relay_state, acs_url = keycloak.complete_keycloak_login(
			"kb.contributor", "apc-kb-contributor"
		)
		keycloak.invoke_acs(saml_response, relay_state)
		roles = {row.role for row in frappe.get_doc("User", email).roles}
		assert "Purchase User" not in roles
	finally:
		saml_key.match_saml_roles = original_match
		saml_key.save(ignore_permissions=True)
		user = frappe.get_doc("User", email)
		user.roles = [row for row in user.roles if row.role != "Purchase User"]
		user.save(ignore_permissions=True)


@pytest.mark.order(60)
def test_acs_resolves_provider_from_query_param(keycloak_session):
	saml_response, relay_state, acs_url = keycloak.complete_keycloak_login(
		"warehouse", "apc-warehouse"
	)
	invoke_acs_as_guest(
		saml_response,
		relay_state,
		provider=None,
		query_provider=get_test_saml_provider(),
	)
	assert frappe.local.response.get("type") == "redirect"


@pytest.mark.order(61)
def test_acs_determines_provider_from_saml_issuer(keycloak_session):
	saml_response, relay_state, acs_url = keycloak.complete_keycloak_login(
		"warehouse", "apc-warehouse"
	)
	invoke_acs_as_guest(saml_response, relay_state, provider=None, query_provider=None)
	assert frappe.local.response.get("type") == "redirect"
	assert frappe.db.exists("User", "warehouse@ambrosiapieco.example")


@pytest.mark.order(62)
def test_get_idp_metadata_url_fallback():
	saml_key = get_test_saml_login_key()
	original_url = saml_key.idp_metadata_url
	saml_key.idp_metadata_url = ""
	try:
		assert saml_key.get_idp_metadata_url() == (
			f"{saml_key.idp_entity_id.rstrip('/')}/protocol/saml/descriptor"
		)
	finally:
		saml_key.idp_metadata_url = original_url


@pytest.mark.order(63)
def test_invalid_idp_metadata_sync_cron_raises():
	saml_key = get_test_saml_login_key()
	original_sync = saml_key.sync_idp_metadata
	original_cron = saml_key.idp_metadata_sync_cron
	saml_key.sync_idp_metadata = True
	saml_key.idp_metadata_sync_cron = "not a cron"
	with pytest.raises(frappe.ValidationError):
		saml_key.save(ignore_permissions=True)

	saml_key = get_test_saml_login_key()
	saml_key.sync_idp_metadata = original_sync
	saml_key.idp_metadata_sync_cron = original_cron
	saml_key.save(ignore_permissions=True)


@pytest.mark.order(64)
def test_run_scheduled_idp_metadata_syncs_runs_due_providers():
	saml_key = get_test_saml_login_key()
	original_sync = saml_key.sync_idp_metadata
	original_last = saml_key.last_idp_metadata_sync
	saml_key.sync_idp_metadata = True
	saml_key.last_idp_metadata_sync = None
	saml_key.save(ignore_permissions=True)
	with patch.object(SAMLLoginKey, "is_idp_metadata_sync_due", return_value=True):
		with patch.object(SAMLLoginKey, "sync_idp_metadata_from_url") as mock_sync:
			run_scheduled_idp_metadata_syncs()
			mock_sync.assert_called_once()

	saml_key.reload()
	assert saml_key.last_idp_metadata_sync

	saml_key = get_test_saml_login_key()
	saml_key.sync_idp_metadata = original_sync
	saml_key.last_idp_metadata_sync = original_last
	saml_key.save(ignore_permissions=True)


@pytest.mark.order(65)
def test_sync_idp_certificate_from_descriptor(keycloak_session):
	import re

	frappe.set_user("Administrator")
	sync_idp_certificate(get_test_saml_provider())
	saml_key = get_test_saml_login_key()
	metadata_url = saml_key.get_idp_metadata_url()
	response = requests.get(metadata_url, timeout=30)
	response.raise_for_status()
	match = re.search(r"<ds:X509Certificate>([^<]+)</ds:X509Certificate>", response.text)
	assert match
	assert saml_key.idp_x509cert == match.group(1)
	assert saml_key.last_idp_metadata_sync


@pytest.mark.order(66)
def test_silent_saml_with_existing_idp_session(keycloak_session):
	session = keycloak.establish_keycloak_idp_session("warehouse", "apc-warehouse")
	saml_response, relay_state, acs_url = keycloak.complete_silent_saml_login(
		session, redirect_to="/app"
	)
	keycloak.invoke_acs(saml_response, relay_state)
	assert "/app" in frappe.local.response.get("location", "")
	assert frappe.db.exists("User", "warehouse@ambrosiapieco.example")


@pytest.mark.order(67)
def test_saml_session_allows_app_access_without_reauth(keycloak_session):
	saml_response, relay_state, acs_url = keycloak.complete_keycloak_login(
		"warehouse", "apc-warehouse"
	)
	keycloak.invoke_acs(saml_response, relay_state)
	sid = frappe.session.sid
	assert sid and sid != "Guest"

	keycloak.resume_guest_get_request("/app", sid=sid)
	assert frappe.session.user == "warehouse@ambrosiapieco.example"


@pytest.mark.order(68)
def test_silent_saml_without_idp_session_shows_login_form(keycloak_session):
	session = requests.Session()
	with pytest.raises(RuntimeError, match="Expected silent SSO"):
		keycloak.complete_silent_saml_login(session, redirect_to="/app")


@pytest.mark.order(69)
def test_silent_saml_preserves_redirect_to(keycloak_session):
	session = keycloak.establish_keycloak_idp_session("warehouse", "apc-warehouse")
	redirect_to = "/app/sales"
	saml_response, relay_state, acs_url = keycloak.complete_silent_saml_login(
		session, redirect_to=redirect_to
	)
	assert relay_state == redirect_to
	keycloak.invoke_acs(saml_response, relay_state)
	assert redirect_to in frappe.local.response["location"]


@pytest.mark.order(70)
@pytest.mark.parametrize(
	"path,scope",
	[
		("/app/user", None),
		("/login", "All Guest Routes"),
		("/app", "All Guest Routes"),
	],
)
def test_auto_saml_e2e_with_idp_session(keycloak_session, path, scope):
	kwargs = {"scope": scope} if scope else {}
	with auto_saml_settings(**kwargs):
		session = keycloak.establish_keycloak_idp_session("warehouse", "apc-warehouse")
		saml_response, relay_state = keycloak.complete_guest_auto_saml_login(session, path=path)
		assert relay_state == path
		keycloak.invoke_acs(saml_response, relay_state)
		assert frappe.db.exists("User", "warehouse@ambrosiapieco.example")


@pytest.mark.order(75)
def test_auto_saml_app_with_keycloak_login_form(keycloak_session):
	saml_key = get_test_saml_login_key()
	original_login = saml_key.auto_saml_login
	original_scope = saml_key.auto_saml_scope
	saml_key.auto_saml_login = True
	saml_key.auto_saml_scope = "All Guest Routes"
	saml_key.save(ignore_permissions=True)
	try:
		saml_response, relay_state = keycloak.complete_guest_auto_saml_login_with_credentials(
			"warehouse", "apc-warehouse", path="/app"
		)
		assert relay_state == "/app"
		keycloak.invoke_acs(saml_response, relay_state)
		assert frappe.local.response.get("type") == "redirect"
		assert frappe.db.exists("User", "warehouse@ambrosiapieco.example")
		assert "/app" in frappe.local.response.get(
			"location", ""
		) or "%2Fapp" in frappe.local.response.get("location", "")
	finally:
		saml_key.auto_saml_login = original_login
		saml_key.auto_saml_scope = original_scope
		saml_key.save(ignore_permissions=True)


@pytest.mark.order(76)
def test_acs_syncs_stale_idp_certificate_on_signature_failure(keycloak_session):
	saml_key = get_test_saml_login_key()
	original_cert = saml_key.idp_x509cert
	saml_key.idp_x509cert = "STALE_CERTIFICATE"
	saml_key.save(ignore_permissions=True)
	try:
		saml_response, relay_state, acs_url = keycloak.complete_keycloak_login(
			"warehouse", "apc-warehouse"
		)
		keycloak.invoke_acs(saml_response, relay_state)
		assert frappe.local.response.get("type") == "redirect"
		assert frappe.db.exists("User", "warehouse@ambrosiapieco.example")
		updated = get_test_saml_login_key()
		assert updated.idp_x509cert != "STALE_CERTIFICATE"
	finally:
		keycloak.set_saml_login_key_values({"idp_x509cert": original_cert})


@pytest.mark.order(77)
def test_auto_saml_home_http_flow_with_stale_idp_certificate(keycloak_session):
	from urllib.parse import unquote

	saml_key = get_test_saml_login_key()
	original_cert = saml_key.idp_x509cert
	original_login = saml_key.auto_saml_login
	original_scope = saml_key.auto_saml_scope
	keycloak.set_saml_login_key_values(
		{
			"idp_x509cert": "STALE_CERTIFICATE",
			"auto_saml_login": 1,
			"auto_saml_scope": "All Guest Routes",
		}
	)
	try:
		session, response = keycloak.complete_http_auto_saml_home_login("warehouse", "apc-warehouse")
		assert unquote(session.cookies.get("user_id") or "") == "warehouse@ambrosiapieco.example"
		assert response.status_code == 200
		keycloak.commit_db_changes()
		assert (
			frappe.db.get_value("SAML Login Key", get_test_saml_provider(), "idp_x509cert")
			!= "STALE_CERTIFICATE"
		)
	finally:
		keycloak.set_saml_login_key_values(
			{
				"idp_x509cert": original_cert,
				"auto_saml_login": original_login,
				"auto_saml_scope": original_scope,
			}
		)


@pytest.mark.order(78)
def test_logout_redirects_to_logout_page_when_auto_saml_enabled():
	from frappe.auth import CookieManager, LoginManager
	from frappe.utils import set_request

	from saml.overrides.logout import LOGOUT_PAGE_PATH, logout, web_logout

	saml_key = get_test_saml_login_key()
	original_login = saml_key.auto_saml_login
	original_scope = saml_key.auto_saml_scope
	saml_key.auto_saml_login = True
	saml_key.auto_saml_scope = "All Guest Routes"
	saml_key.save(ignore_permissions=True)
	try:
		set_request(method="GET", path="/app")
		frappe.local.cookie_manager = CookieManager()
		frappe.local.login_manager = LoginManager()
		frappe.local.login_manager.login_as("Administrator")
		frappe.local.response = frappe._dict()
		logout()
		assert frappe.local.response.get("type") == "redirect"
		assert frappe.local.response.get("location") == LOGOUT_PAGE_PATH
		assert frappe.session.user == "Guest"

		set_request(method="GET", path="/app")
		frappe.local.cookie_manager = CookieManager()
		frappe.local.login_manager = LoginManager()
		frappe.local.login_manager.login_as("Administrator")
		frappe.local.response = frappe._dict()
		web_logout()
		assert frappe.local.response.get("type") == "redirect"
		assert frappe.local.response.get("location") == LOGOUT_PAGE_PATH
		assert frappe.session.user == "Guest"
	finally:
		saml_key.auto_saml_login = original_login
		saml_key.auto_saml_scope = original_scope
		saml_key.save(ignore_permissions=True)


@pytest.mark.order(79)
def test_logout_page_renders_for_guest():
	from saml.www.logout import get_context

	keycloak.setup_guest_get_request("/logout")
	context = frappe._dict()
	get_context(context)
	assert context.title
	assert context.message
	assert context.logo


@pytest.mark.order(71)
def test_login_page_exposes_saml_providers():
	from frappe.utils import set_request

	from saml.www.login import add_saml_provider_logins, get_context

	set_request(method="GET", path="/login", query_string="redirect-to=%2Fapp")
	context = frappe._dict(
		provider_logins=[{"name": "google", "provider_name": "Google", "auth_url": "/oauth"}]
	)
	add_saml_provider_logins(context)
	saml_key = get_test_saml_login_key()
	assert context.saml_login is True
	assert context.provider_logins[0]["name"] == saml_key.name
	redirect_to = parse_qs(urlparse(context.provider_logins[0]["auth_url"]).query).get(
		"redirect-to", [""]
	)[0]
	assert redirect_to.endswith("/app")
	assert context.provider_logins[1]["name"] == "google"

	set_request(method="GET", path="/login")
	frappe.set_user("Guest")
	try:
		page_context = frappe._dict()
		get_context(page_context)
		assert page_context.title == "Login"
		assert page_context.saml_login is True
		assert any(provider["name"] == saml_key.name for provider in page_context.provider_logins)
	finally:
		frappe.set_user("Administrator")


@pytest.mark.order(80)
def test_get_settings_single_logout_service():
	saml_key = get_test_saml_login_key()
	original_terminate = saml_key.terminate_saml_session_on_logout
	acs_url = frappe.utils.get_url(f"/api/method/saml.saml.acs?provider={saml_key.name}")
	slo_url = frappe.utils.get_url(f"/api/method/saml.saml.logout.slo?provider={saml_key.name}")

	try:
		saml_key.terminate_saml_session_on_logout = True
		settings = saml_key.get_settings(acs_url, slo_url=slo_url)
		sp_data = settings.get_sp_data()
		idp_data = settings.get_idp_data()
		assert sp_data["singleLogoutService"]["url"] == slo_url
		assert idp_data["singleLogoutService"]["url"] == saml_key.idp_sso_url
		assert settings.get_security_data()["logoutRequestSigned"] is True

		saml_key.terminate_saml_session_on_logout = False
		settings = saml_key.get_settings(acs_url, slo_url=slo_url)
		sp_data = settings.get_sp_data()
		idp_data = settings.get_idp_data()
		assert sp_data.get("singleLogoutService", {}).get("url") != slo_url
		assert idp_data.get("singleLogoutService", {}).get("url") != saml_key.idp_sso_url
	finally:
		saml_key.terminate_saml_session_on_logout = original_terminate


@pytest.mark.order(82)
def test_logout_redirects_to_idp_when_saml_session_stored():
	from frappe.auth import CookieManager, LoginManager
	from frappe.utils import set_request

	from saml.overrides.logout import logout, web_logout
	from saml.saml.logout import (
		SAML_SESSION_INDEX_KEY,
		SAML_SESSION_NAME_ID_KEY,
		SAML_SESSION_PROVIDER_KEY,
	)

	saml_key = get_test_saml_login_key()
	original_terminate = saml_key.terminate_saml_session_on_logout
	keycloak.set_saml_login_key_values({"terminate_saml_session_on_logout": True})

	def seed_saml_session():
		set_request(method="GET", path="/app")
		frappe.local.cookie_manager = CookieManager()
		frappe.local.login_manager = LoginManager()
		frappe.local.login_manager.login_as("Administrator")
		frappe.local.session_obj.data.data[SAML_SESSION_PROVIDER_KEY] = saml_key.name
		frappe.local.session_obj.data.data[SAML_SESSION_NAME_ID_KEY] = "admin@example.com"
		frappe.local.session_obj.data.data[SAML_SESSION_INDEX_KEY] = "session-index-1"
		frappe.local.session_obj.update(force=True)

	try:
		seed_saml_session()
		result = logout()
		redirect_to = result["redirect_to"]
		assert redirect_to.startswith(saml_key.idp_sso_url)
		assert "SAMLRequest=" in redirect_to
		assert "%2Flogout" in redirect_to
		assert frappe.session.user == "Guest"

		seed_saml_session()
		frappe.local.response = frappe._dict()
		web_logout()
		redirect_to = frappe.local.response.get("location")
		assert frappe.local.response.get("type") == "redirect"
		assert redirect_to.startswith(saml_key.idp_sso_url)
		assert "SAMLRequest=" in redirect_to
		assert frappe.session.user == "Guest"
	finally:
		keycloak.set_saml_login_key_values({"terminate_saml_session_on_logout": original_terminate})


@pytest.mark.order(84)
def test_slo_sanitizes_relay_state_open_redirect():
	from frappe.utils import set_request

	from saml.saml.logout import slo

	provider = get_test_saml_provider()
	set_request(
		method="GET",
		path="/api/method/saml.saml.logout.slo",
		query_string=f"provider={provider}&RelayState=https%3A%2F%2Fevil.com",
	)
	frappe.form_dict = frappe._dict({"provider": provider, "RelayState": "https://evil.com"})
	frappe.local.response = frappe._dict()
	frappe.set_user("Guest")

	with patch("saml.saml.logout.OneLogin_Saml2_Auth") as mock_auth_cls:
		mock_client = mock_auth_cls.return_value
		mock_client.process_slo.return_value = None
		mock_client.get_errors.return_value = []
		slo()

	assert frappe.local.response.get("type") == "redirect"
	assert frappe.local.response.get("location") == frappe.utils.get_url("/logout")


@pytest.mark.order(92)
def test_login_uses_token_relay_state_for_long_redirects(keycloak_session):
	long_path = "/app/" + ("sales-" * 20)
	response = keycloak.invoke_login(get_test_saml_provider(), redirect_to=long_path)
	relay_state = parse_qs(urlparse(response["location"]).query).get("RelayState", [None])[0]
	assert relay_state != long_path
	assert resolve_saml_redirect(relay_state, None) == normalize_saml_redirect_to(long_path)


@pytest.mark.order(93)
def test_acs_resolves_same_host_absolute_relay_state(keycloak_session):
	saml_response, relay_state, acs_url = keycloak.complete_keycloak_login(
		"warehouse", "apc-warehouse"
	)
	site_url = frappe.utils.get_url("/app/sales")
	keycloak.invoke_acs(saml_response, site_url)
	assert frappe.local.response.get("location") == site_url


@pytest.mark.order(94)
def test_acs_resolves_redirect_from_request_id_when_relay_state_missing(keycloak_session):
	redirect_to = "/app/sales"
	login_response = keycloak.invoke_login(get_test_saml_provider(), redirect_to=redirect_to)
	saml_response, relay_state = keycloak.complete_keycloak_login_from_redirect(
		login_response, "warehouse", "apc-warehouse"
	)
	keycloak.invoke_acs(saml_response, "")
	assert frappe.local.response.get("location") == frappe.utils.get_url(redirect_to)
