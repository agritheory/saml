# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import base64
import xml.etree.ElementTree as ET

import frappe
from frappe import _
from frappe.utils.password import remove_encrypted_password
from onelogin.saml2.auth import OneLogin_Saml2_Auth, OneLogin_Saml2_Settings
from urllib.parse import parse_qs, urlparse


@frappe.whitelist(allow_guest=True)
def login(provider):
	saml_key = frappe.get_doc("SAML Login Key", provider)
	saml_settings = saml_key.get_settings(
		frappe.utils.get_url(f"/api/method/saml.saml.acs?provider={provider}")
	)
	client = OneLogin_Saml2_Auth(get_request_data(provider), saml_settings)
	redirect_location = frappe.local.request.args.get("redirect-to", "")
	redirect_url = client.login(return_to=redirect_location)
	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = redirect_url


def get_request_data(provider):
	https_on = not frappe.conf.get("developer_mode", False)

	# Use configured host_name instead of request host for proxied environments
	host = frappe.conf.get("host_name", frappe.local.request.host)
	if host.startswith("https://") or host.startswith("http://"):
		host = host.split("://", 1)[1]

	if not frappe.conf.get("developer_mode", False):
		host = host.split(":")[0]

	request_data = {
		"http_host": host,
		"script_name": f"/api/method/saml.saml.acs?provider={provider}",
		"query_string": frappe.local.request.environ.get("QUERY_STRING"),
		"https": "on" if https_on else "off",
	}

	# Only add server_port in developer mode
	if frappe.conf.get("developer_mode", False):
		request_data["server_port"] = frappe.local.request.environ.get("SERVER_PORT")

	return request_data


@frappe.whitelist(allow_guest=True)
def acs():
	https_on = not frappe.conf.get("developer_mode", False)
	try:
		post_data = dict(frappe.request.form.copy())
		query_data = dict(frappe.request.args.copy())
		provider = query_data.get("provider")
		if not provider:
			parsed_url = urlparse(frappe.local.request.url)
			query_params = parse_qs(parsed_url.query)
			provider = query_params.get("provider", [None])[0]

		if not provider:
			provider = determine_provider_from_saml_response(post_data.get("SAMLResponse"))

		if not provider:
			enabled_providers = frappe.get_all(
				"SAML Login Key", filters={"enable_saml_login": 1}, pluck="name"
			)

			if len(enabled_providers) == 1:
				provider = enabled_providers[0]
			elif len(enabled_providers) > 1:
				frappe.respond_as_web_page(
					_("SAML Login Failed"),
					_("Cannot determine SAML provider - multiple providers configured"),
					http_status_code=400,
				)
				return
			else:
				frappe.respond_as_web_page(
					_("SAML Login Failed"), _("No SAML providers configured"), http_status_code=400
				)
				return

		if not provider:
			frappe.respond_as_web_page(
				_("SAML Login Failed"), _("Cannot determine SAML provider"), http_status_code=400
			)
			return

		host = frappe.conf.get("host_name", frappe.local.request.host)
		if host.startswith("https://") or host.startswith("http://"):
			host = host.split("://", 1)[1]

		if not frappe.conf.get("developer_mode", False):
			host = host.split(":")[0]

		request_data = {
			"http_host": host,
			"script_name": frappe.local.request.environ.get("PATH_INFO"),
			"post_data": post_data,
			"https": "on" if https_on else "off",
		}

		if frappe.conf.get("developer_mode", False):
			request_data["server_port"] = frappe.local.request.environ.get("SERVER_PORT")

		saml_key = frappe.get_doc("SAML Login Key", provider)

		if https_on:
			acs_url = f"https://{host}/api/method/saml.saml.acs"
		else:
			acs_url = f"http://{host}/api/method/saml.saml.acs"

		saml_settings = OneLogin_Saml2_Settings(
			{
				"sp": {
					"entityId": saml_key.sp_entity_id,
					"assertionConsumerService": {
						"url": acs_url,
						"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					},
					"signatureAlgorithm": "RSA_SHA256",
				},
				"idp": {
					"entityId": saml_key.idp_entity_id,
					"singleSignOnService": {
						"url": saml_key.idp_sso_url,
						"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
					},
					"x509cert": saml_key.idp_x509cert,
				},
			}
		)

		client = OneLogin_Saml2_Auth(request_data, saml_settings)
		client.process_response()

		errors = client.get_errors()
		if errors:
			error_reason = client.get_last_error_reason()
			frappe.respond_as_web_page(
				_("SAML Login Failed"),
				_(f"Invalid SAML response: {error_reason}"),
				http_status_code=403,
			)
			return

		if not client.is_authenticated():
			frappe.respond_as_web_page(
				_("SAML Login Failed"), _("User not authenticated"), http_status_code=403
			)
			return

		friendly_name = client.get_friendlyname_attributes()
		attributes = client.get_attributes()
		if friendly_name:
			first_name = friendly_name.get("givenName", [None])[0]
			last_name = friendly_name.get("surname", [None])[0]
		elif attributes:
			first_name = attributes.get("firstName", [None])[0]
			last_name = attributes.get("lastName", [None])[0]
		else:
			first_name = last_name = None

		user_email = client.get_nameid()
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
					"saml_managed": True,
				}
			)
			user.insert(ignore_permissions=True)

			if default_role := frappe.db.get_single_value("Portal Settings", "default_role"):
				user.add_roles(default_role)
		else:
			user = frappe.get_doc("User", user_email)
			if not user.saml_managed:
				user.saml_managed = True
				user.save(ignore_permissions=True)
				remove_encrypted_password("User", user.name, "password")

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
								user.save(ignore_permissions=True)
								break
						else:
							if user.role_profile_name:
								user.roles = []
								user.role_profile_name = ""
								user.save(ignore_permissions=True)
							roles_to_apply.append(role_mapping.user_role)

			if roles_to_apply:
				user.add_roles(roles_to_apply)

			if saml_key.match_saml_roles:
				for has_role in reversed(user.roles):
					if has_role.role not in roles_to_apply:
						user.roles.remove(has_role)
				user.save(ignore_permissions=True)

		# Log the user in
		frappe.local.login_manager.user = user.name
		frappe.local.login_manager.post_login()
		frappe.db.commit()
		redirect_to = post_data.get("RelayState")

		if not redirect_to:
			redirect_to = "/me" if user.user_type == "Website User" else "/app"
		frappe.local.response["type"] = "redirect"
		frappe.local.response["location"] = frappe.utils.get_url(redirect_to)

	except Exception as e:
		frappe.log_error(frappe.get_traceback(), _("SAML Login Error"))
		frappe.respond_as_web_page(_("SAML Login Failed"), frappe.get_traceback(), http_status_code=500)


def determine_provider_from_saml_response(saml_response):
	if not saml_response:
		return None

	try:
		decoded_response = base64.b64decode(saml_response)
		root = ET.fromstring(decoded_response)
		issuer_elem = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
		if issuer_elem is not None:
			issuer = issuer_elem.text

			provider = frappe.db.get_value(
				"SAML Login Key", {"idp_entity_id": issuer, "enable_saml_login": 1}, "name"
			)

			if provider:
				return provider

	except Exception:
		pass

	return None
