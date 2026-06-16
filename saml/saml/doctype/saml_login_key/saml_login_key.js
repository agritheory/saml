// Copyright (c) 2025, AgriTheory and contributors
// For license information, please see license.txt

frappe.ui.form.on('SAML Login Key', {
	idp_entity_id(frm) {
		if (frm.doc.idp_entity_id && !frm.doc.idp_metadata_url) {
			frm.set_value('idp_metadata_url', `${frm.doc.idp_entity_id.replace(/\/$/, '')}/protocol/saml/descriptor`)
		}
	},

	refresh(frm) {
		if (frm.is_new() || !frm.doc.enable_saml_login) {
			return
		}

		frm.add_custom_button(__('Sync IdP Metadata'), () => {
			frappe.dom.freeze(__('Syncing IdP metadata...'))
			frappe
				.call({
					method: 'saml.saml.doctype.saml_login_key.saml_login_key.sync_idp_certificate',
					args: { provider: frm.doc.name },
				})
				.then(() => {
					frappe.dom.unfreeze()
					frm.reload_doc().then(() => {
						frappe.show_alert({
							message: __('IdP metadata synced'),
							indicator: 'green',
						})
					})
				})
				.catch(() => {
					frappe.dom.unfreeze()
				})
		})
	},
})
