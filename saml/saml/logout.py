# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.errors import OneLogin_Saml2_Error

from saml.saml import get_request_data

LOGOUT_PAGE_PATH = "/logout"

SAML_SESSION_PROVIDER_KEY = "saml_provider"
SAML_SESSION_NAME_ID_KEY = "saml_name_id"
SAML_SESSION_NAME_ID_FORMAT_KEY = "saml_name_id_format"
SAML_SESSION_INDEX_KEY = "saml_session_index"


def get_acs_url(provider: str) -> str:
	return frappe.utils.get_url(f"/api/method/saml.saml.acs?provider={provider}")


def get_slo_url(provider: str) -> str:
	return frappe.utils.get_url(f"/api/method/saml.saml.logout.slo?provider={provider}")


def store_saml_session_data(client: OneLogin_Saml2_Auth, provider: str):
	session_obj = frappe.local.session_obj
	if not session_obj or frappe.session.user == "Guest":
		return

	session_obj.data.data[SAML_SESSION_PROVIDER_KEY] = provider
	session_obj.data.data[SAML_SESSION_NAME_ID_KEY] = client.get_nameid()
	session_obj.data.data[SAML_SESSION_NAME_ID_FORMAT_KEY] = client.get_nameid_format()
	session_obj.data.data[SAML_SESSION_INDEX_KEY] = client.get_session_index()
	session_obj.update(force=True)


def get_stored_saml_session() -> dict | None:
	session_data = getattr(frappe.session, "data", None) or {}
	provider = session_data.get(SAML_SESSION_PROVIDER_KEY)
	name_id = session_data.get(SAML_SESSION_NAME_ID_KEY)
	if not provider or not name_id:
		return None

	return {
		"provider": provider,
		"name_id": name_id,
		"name_id_format": session_data.get(SAML_SESSION_NAME_ID_FORMAT_KEY),
		"session_index": session_data.get(SAML_SESSION_INDEX_KEY),
	}


def uses_custom_logout_redirect() -> bool:
	if frappe.get_all(
		"SAML Login Key",
		filters={"enable_saml_login": 1, "terminate_saml_session_on_logout": 1},
		limit=1,
	):
		return True

	from saml.saml.doctype.saml_login_key.saml_login_key import get_auto_saml_provider

	return bool(get_auto_saml_provider())


def build_saml_auth_client(saml_key, provider: str) -> OneLogin_Saml2_Auth:
	acs_url = get_acs_url(provider)
	slo_url = get_slo_url(provider)
	request_data = get_request_data(provider)
	return OneLogin_Saml2_Auth(
		request_data,
		saml_key.get_settings(acs_url, slo_url=slo_url),
	)


def build_saml_logout_redirect(
	provider: str,
	name_id: str,
	session_index: str | None,
	name_id_format: str | None = None,
) -> str:
	saml_key = frappe.get_doc("SAML Login Key", provider)
	if not saml_key.terminate_saml_session_on_logout or not saml_key.enable_saml_login:
		frappe.throw(_("SAML session termination is not enabled for provider {0}").format(provider))

	client = build_saml_auth_client(saml_key, provider)
	return client.logout(
		return_to=frappe.utils.get_url(LOGOUT_PAGE_PATH),
		name_id=name_id,
		session_index=session_index,
		name_id_format=name_id_format,
	)


def get_logout_redirect_url() -> str | None:
	saml_session = get_stored_saml_session()
	if saml_session:
		saml_key = frappe.get_doc("SAML Login Key", saml_session["provider"])
		if saml_key.terminate_saml_session_on_logout and saml_key.enable_saml_login:
			try:
				return build_saml_logout_redirect(
					saml_session["provider"],
					saml_session["name_id"],
					saml_session.get("session_index"),
					saml_session.get("name_id_format"),
				)
			except OneLogin_Saml2_Error:
				frappe.log_error(
					frappe.get_traceback(),
					_("SAML Single Logout is not configured for provider {0}").format(saml_key.name),
				)

	from saml.saml.doctype.saml_login_key.saml_login_key import get_auto_saml_provider

	if get_auto_saml_provider():
		return LOGOUT_PAGE_PATH

	return None


def clear_local_session():
	if frappe.session.user != "Guest":
		frappe.local.login_manager.logout()
		frappe.db.commit()


def build_slo_request_data(provider: str) -> dict:
	request_data = get_request_data(provider)
	request_data["get_data"] = dict(frappe.request.args.copy())
	return request_data


@frappe.whitelist(allow_guest=True)
def slo():
	provider = frappe.form_dict.get("provider")
	if not provider:
		frappe.respond_as_web_page(
			_("SAML Logout Failed"),
			_("Cannot determine SAML provider"),
			http_status_code=400,
		)
		return

	saml_key = frappe.get_doc("SAML Login Key", provider)
	if not saml_key.enable_saml_login:
		frappe.respond_as_web_page(
			_("SAML Logout Failed"),
			_("SAML login is not enabled for provider {0}").format(provider),
			http_status_code=400,
		)
		return

	request_data = build_slo_request_data(provider)
	acs_url = get_acs_url(provider)
	slo_url = get_slo_url(provider)
	client = OneLogin_Saml2_Auth(
		request_data,
		saml_key.get_settings(acs_url, slo_url=slo_url),
	)

	get_data = request_data.get("get_data") or {}
	is_idp_initiated = "SAMLRequest" in get_data

	redirect_url = None
	try:
		if is_idp_initiated:
			redirect_url = client.process_slo(
				keep_local_session=False, delete_session_cb=clear_local_session
			)
		else:
			redirect_url = client.process_slo(keep_local_session=True)
	except OneLogin_Saml2_Error:
		pass

	errors = client.get_errors()
	if errors:
		frappe.log_error(
			"\n".join(errors),
			_("SAML Single Logout failed for provider {0}: {1}").format(
				provider, client.get_last_error_reason() or ""
			),
		)

	if redirect_url:
		frappe.local.response["type"] = "redirect"
		frappe.local.response["location"] = redirect_url
		return

	relay_state = frappe.form_dict.get("RelayState")
	if relay_state and not errors:
		frappe.local.response["type"] = "redirect"
		frappe.local.response["location"] = relay_state
		return

	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = frappe.utils.get_url(LOGOUT_PAGE_PATH)
