# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from onelogin.saml2.auth import OneLogin_Saml2_Auth


@frappe.whitelist(allow_guest=True)
def login(provider):
	redirect_location = frappe.local.request.args.get("redirect-to", "")
	# Fetch the SAML provider settings
	saml_key = frappe.get_doc("SAML Login Key", provider)
	# Create the SAML settings dictionary
	saml_settings = {
		"sp": {
			"entityId": saml_key.sp_entity_id,
			"assertionConsumerService": {
				"url": frappe.utils.get_url(f"/api/method/saml.saml.acs?provider={provider}"),
				"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
			},
			"privateKey": saml_key.get_password("sp_private_key"),
			"x509cert": saml_key.sp_x509cert,
		},
		"idp": {
			"entityId": saml_key.idp_entity_id,
			"singleSignOnService": {
				"url": saml_key.idp_sso_url,
				"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
			"x509cert": saml_key.idp_x509cert,
		},
		"security": {
			"authnRequestsSigned": True,  # Sign SAML authentication requests
			"signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			"digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
			"rejectUnsolicitedResponsesWithInResponseTo": False,
		},
	}

	client = OneLogin_Saml2_Auth(get_request_data(provider), saml_settings)
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

		# Create the SAML settings dictionary
		saml_settings = {
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
		client = OneLogin_Saml2_Auth(request_data, saml_settings)
		client.process_response()

		errors = client.get_errors()
		if errors:
			frappe.respond_as_web_page(
				_("SAML Login Failed"), _("Invalid SAML response: ") + ", ".join(errors), http_status_code=403
			)
			return

		if not client.is_authenticated():
			frappe.respond_as_web_page(
				_("SAML Login Failed"), _("User not authenticated"), http_status_code=403
			)
			return
		attributes = client.get_attributes()
		first_name = attributes.get("firstName", [None])[0]
		last_name = attributes.get("lastName", [None])[0]
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
			user.first_name = first_name
			user.last_name = last_name
			user.email = user_email
			user.enabled = 1
			user.flags.ignore_permissions = True
			user.flags.no_welcome_mail = True
			if default_role := frappe.db.get_single_value("Portal Settings", "default_role"):
				user.add_roles(default_role)
			user.save()
		else:
			user = frappe.get_doc("User", user_email)

		# Log the user in
		frappe.local.login_manager.user = user.name
		frappe.local.login_manager.post_login()
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
