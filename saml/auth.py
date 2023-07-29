import frappe
import saml2


def authenticate(*args, **kwargs):
	print(args)
	print(kwargs)


@frappe.whitelist()
def login_with_saml2(*args, **kwargs):
	print(args)
	print(kwargs)
