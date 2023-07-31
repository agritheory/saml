import frappe
import saml2 # not clear that this is the right solution

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
	print('saml.authenticate')
	print(args)
	print(kwargs)


"""
Assertion Consumer Service endpoint
"""
@frappe.whitelist()
def login_with_saml2(*args, **kwargs):
	print('saml.login_with_saml2')
	print(args)
	print(kwargs)


