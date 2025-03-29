# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from onelogin.saml2.auth import OneLogin_Saml2_Auth, OneLogin_Saml2_Settings


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
	request_data = {
		"http_host": frappe.local.request.host,
		"server_port": frappe.local.request.environ.get("SERVER_PORT"),
		"script_name": frappe.utils.get_url(f"/api/method/saml.saml.acs?provider={provider}"),
		"query_string": frappe.local.request.environ.get("QUERY_STRING"),
		"https": "on" if frappe.local.request.scheme == "https" else "off",
	}
	return request_data


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

		saml_key = frappe.get_doc("SAML Login Key", query_data.get("provider"))
		saml_settings = OneLogin_Saml2_Settings(
			{
				"sp": {
					"entityId": saml_key.sp_entity_id,
					"assertionConsumerService": {
						"url": frappe.utils.get_url("/api/method/saml.saml.acs"),
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

		# Get user details
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
		frappe.session.saml_provider = saml_key
		if session_index := client.get_session_index():
			frappe.session.saml_session_index = session_index
		frappe.db.commit()
		redirect_to = post_data.get("RelayState")

		# Default to /me for website users or /app for desk users
		if not redirect_to:
			redirect_to = "/me" if user.user_type == "Website User" else "/app"
		frappe.local.response["type"] = "redirect"
		frappe.local.response["location"] = frappe.utils.get_url(redirect_to)

	except Exception as e:
		frappe.log_error(frappe.get_traceback(), _("SAML Login Error"))
		frappe.respond_as_web_page(_("SAML Login Failed"), frappe.get_traceback(), http_status_code=500)


def logout(login_manager):
	"""Handle SAML logout when user logs out of Frappe"""
	# Check if user was logged in via SAML
	if frappe.session.get("saml_provider"):
		provider = frappe.session.get("saml_provider")
		logout_result = frappe.call("saml.saml.logout", provider=provider)

		# If successful and a logout URL was provided, redirect to it
		if logout_result.get("success") and logout_result.get("logout_url"):
			frappe.local.response["type"] = "redirect"
			frappe.local.response["location"] = logout_result.get("logout_url")
