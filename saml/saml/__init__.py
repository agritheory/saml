# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

from urllib.parse import urlparse

import frappe
from frappe import _
from frappe.utils import get_url
from onelogin.saml2.auth import (
	OneLogin_Saml2_Auth,
	OneLogin_Saml2_Settings,
)
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

from saml.saml.doctype.saml_login_key.saml_login_key import SAMLLoginKey


@frappe.whitelist(allow_guest=True)
def login(provider):
	saml_key: SAMLLoginKey = frappe.get_doc("SAML Login Key", provider)
	acs_url = get_url(f"/api/method/saml.saml.acs?provider={provider}")
	saml_settings = saml_key.get_settings(acs_url)
	auth = OneLogin_Saml2_Auth(get_request_data(provider), saml_settings)
	redirect_location = frappe.local.request.args.get("redirect-to", "")
	redirect_url = auth.login(return_to=redirect_location)
	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = redirect_url


def get_request_data(provider):
	return {
		"http_host": frappe.local.request.host,
		"script_name": get_url(f"/api/method/saml.saml.acs?provider={provider}"),
		"query_string": frappe.local.request.environ.get("QUERY_STRING"),
		"https": "on" if frappe.local.request.scheme == "https" else "off",
	}


@frappe.whitelist(allow_guest=True)
def acs():
	try:
		# Handle the SAML response
		post_data = dict(frappe.request.form.copy())
		query_data = dict(frappe.request.args.copy())
		request_data = {
			"http_host": frappe.local.request.host,
			"server_port": frappe.local.request.environ.get("SERVER_PORT"),
			"script_name": frappe.local.request.environ.get("PATH_INFO"),
			"post_data": post_data,
			"https": "on" if frappe.local.request.scheme == "https" else "off",
		}

		saml_key: SAMLLoginKey = frappe.get_doc("SAML Login Key", query_data.get("provider"))
		saml_settings = saml_key.get_settings(get_url("/api/method/saml.saml.acs"))

		auth = OneLogin_Saml2_Auth(request_data, saml_settings)
		auth.process_response()

		errors = auth.get_errors()
		if errors:
			error_reason = auth.get_last_error_reason()
			frappe.respond_as_web_page(
				_("SAML Login Failed"),
				_(f"Invalid SAML response: {error_reason}"),
				http_status_code=403,
			)
			return

		if not auth.is_authenticated():
			frappe.respond_as_web_page(
				_("SAML Login Failed"), _("User not authenticated"), http_status_code=403
			)
			return

		# Get user details
		friendly_name = auth.get_friendlyname_attributes()
		attributes = auth.get_attributes()
		if friendly_name:
			first_name = friendly_name.get("givenName", [None])[0]
			last_name = friendly_name.get("surname", [None])[0]
		elif attributes:
			first_name = attributes.get("firstName", [None])[0]
			last_name = attributes.get("lastName", [None])[0]
		else:
			first_name = last_name = None

		user_email = auth.get_nameid()
		if not user_email:
			frappe.respond_as_web_page(
				_("SAML Login Failed"), _("Email not found in SAML response"), http_status_code=403
			)
			return

		user = frappe.db.get_value("User", {"email": user_email})
		if not user:
			if not first_name:
				first_name = user_email
			user = frappe.new_doc("User")
			user.update(
				{
					"enabled": True,
					"email": user_email,
					"first_name": first_name,
					"last_name": last_name,
					"send_welcome_email": False,
				}
			)
			user.flags.ignore_permissions = True
			user.insert()

			if default_role := frappe.db.get_single_value("Portal Settings", "default_role"):
				user.add_roles(default_role)
		else:
			user = frappe.get_doc("User", user_email)

		# Map SAML roles to Role and Role Profile
		if saml_key.apply_saml_roles:
			roles = attributes.get("Role", [])
			roles_to_apply = []
			user.flags.ignore_permissions = True
			for role in roles:
				for role_mapping in saml_key.roles:
					if role_mapping.saml_role == role:
						if role_mapping.role_or_role_profile == "Role Profile":
							if user.role_profile_name == role_mapping.saml_role == role:
								break
							elif role_mapping.saml_role == role:
								user.role_profile_name = role_mapping.user_role
								user.save()
								break
						else:
							# reset role profile
							if user.role_profile_name:
								user.roles = []
								user.role_profile_name = ""
								user.save()
							roles_to_apply.append(role_mapping.user_role)

			if roles_to_apply:
				user.add_roles(roles_to_apply)
			if saml_key.match_saml_roles:
				for has_role in reversed(user.roles):
					if has_role.role not in roles_to_apply:
						user.roles.remove(has_role)
				user.save()

		# Log the user in
		frappe.local.login_manager.user = user.name
		frappe.local.login_manager.post_login()

		# Set session variables
		saml_session = {"provider": saml_key.name}
		if session_index := auth.get_session_index():
			saml_session.update({"session_index": session_index})
		frappe.local.session.data.saml = saml_session

		frappe.db.commit()
		redirect_to = post_data.get("RelayState")

		# Default to /me for website users or /app for desk users
		if not redirect_to:
			redirect_to = "/me" if user.user_type == "Website User" else "/app"
		frappe.local.response["type"] = "redirect"
		frappe.local.response["location"] = get_url(redirect_to)

	except Exception as e:
		frappe.log_error(frappe.get_traceback(), _("SAML Login Error"))
		frappe.respond_as_web_page(_("SAML Login Failed"), frappe.get_traceback(), http_status_code=500)


def logout(login_manager=None):
	"""Handle SAML logout when user logs out of Frappe"""
	saml_session = frappe.local.session.data.saml
	if not saml_session or not saml_session.get("provider"):
		return

	provider = saml_session.get("provider")
	saml_key: SAMLLoginKey = frappe.get_doc("SAML Login Key", provider)
	if not saml_key.terminate_saml_session_on_logout:
		return

	acs_url = get_url(f"/api/method/saml.saml.acs?provider={provider}")
	slo_url = get_url(f"/api/method/saml.saml.slo?provider={provider}")

	saml_settings = saml_key.get_settings(acs_url)
	idp_slo_url = saml_settings.get_idp_slo_url()
	parsed_slo_url = urlparse(idp_slo_url)
	request_data = {
		"https": "on" if parsed_slo_url.scheme == "https" else "off",
		"http_host": parsed_slo_url.netloc,
		"script_name": parsed_slo_url.path,
	}

	metadata = OneLogin_Saml2_IdPMetadataParser.parse_remote(f"{saml_key.idp_sso_url}/descriptor")
	settings = OneLogin_Saml2_Settings(
		{
			"sp": {
				**metadata.get("sp", {}),
				"entityId": saml_key.sp_entity_id,
				"assertionConsumerService": {
					"url": acs_url,
					"binding": OneLogin_Saml2_Constants.BINDING_HTTP_POST,
				},
				"singleLogoutService": {
					"url": slo_url,
					"binding": OneLogin_Saml2_Constants.BINDING_HTTP_POST,
				},
				"privateKey": saml_key.get_password("sp_private_key"),
				"x509cert": saml_key.sp_x509cert,
			},
			"idp": metadata.get("idp", {}),
		}
	)

	auth = OneLogin_Saml2_Auth(request_data, settings)
	logout_url = auth.logout(
		return_to=get_url(), name_id=frappe.session.user, session_index=saml_session.get("session_index")
	)
	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = get_url(logout_url)


@frappe.whitelist(allow_guest=True)
def slo(*args, **kwargs):
	pass
