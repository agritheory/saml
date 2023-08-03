from pathlib import Path

import frappe
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

"""
Resources

Container with nice IDP test service, also mentioned in readme
https://medium.com/disney-streaming/setup-a-single-sign-on-saml-test-environment-with-docker-and-nodejs-c53fc1a984c9

Diagram:
https://stackoverflow.com/questions/66001339/python-saml-authentication-automation

Archived, but lightweight implementation, same as what we're trying to do here
https://github.com/mscherer/requests-saml/blob/master/requests_saml/saml.py

Lengthy video explanation, provisioning discussion around 15:00 is something we need
https://www.youtube.com/watch?v=l-6QSEqDJPo
"""


def authenticate(*args, **kwargs):
	# if user is logged in, don't authenticate
	base_path = Path(frappe.get_app_path("saml")) / "saml"
	request = {
		"http_host": frappe.request.host_url,
		"script_name": frappe.request.path,
		"get_data": frappe.request.get_data(),
		# 'post_data': request.POST.copy()
	}

	auth = OneLogin_Saml2_Auth(request, custom_base_path=str(base_path))
	saml_settings = auth.get_settings()
	metadata = saml_settings.get_sp_metadata()
	errors = saml_settings.validate_metadata(metadata)

	if errors:
		frappe.throw("Invalid SP metadata: %s" % (", ".join(errors)))

	saml_request_path = auth.login(return_to=frappe.request.host_url + "/app")
	print(saml_request_path)


"""
Assertion Consumer Service endpoint
"""


@frappe.whitelist()
def login_with_saml2(*args, **kwargs):
	print("saml.login_with_saml2")
	print(args)
	print(kwargs)
