// Copyright (c) 2026, AgriTheory and contributors
// For license information, please see license.txt

frappe.provide('frappe.saml')

frappe.saml.patch_logout_redirect = function () {
	if (
		!frappe.boot?.saml_auto_saml_login ||
		!frappe.Application?.prototype?.logout ||
		frappe.saml.logout_redirect_patched
	) {
		return
	}

	frappe.Application.prototype.logout = function () {
		this.logged_out = true
		return frappe.call({
			method: 'logout',
			callback() {
				window.location.href = '/logout'
			},
			error() {
				window.location.href = '/logout'
			},
		})
	}

	frappe.saml.logout_redirect_patched = true
}

frappe.saml.patch_logout_redirect()
