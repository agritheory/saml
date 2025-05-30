# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document

from onelogin.saml2.auth import OneLogin_Saml2_Settings


class SAMLLoginKey(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF
		from saml.saml.doctype.saml_group_mapping.saml_group_mapping import SAMLGroupMapping

		apply_saml_roles: DF.Check
		disallow_password_update: DF.Check
		enable_saml_login: DF.Check
		idp_entity_id: DF.Data | None
		idp_sso_url: DF.Data | None
		idp_x509cert: DF.Text | None
		match_saml_roles: DF.Check
		provider_name: DF.Data
		roles: DF.Table[SAMLGroupMapping]
		saml_domains: DF.Text | None
		sp_entity_id: DF.Data | None
		sp_private_key: DF.Password | None
		sp_x509cert: DF.SmallText | None
		terminate_saml_session_on_logout: DF.Check
	# end: auto-generated types

	@property
	def domains(self):
		"""Return the domains as a list."""
		if self.saml_domains:
			return self.saml_domains.split("\n")
		return []

	def autoname(self):
		self.name = frappe.scrub(self.provider_name)

	def validate(self):
		self.sort_by_role_profile()

	def sort_by_role_profile(self):
		roles, role_profiles = [], []
		for row in self.roles:
			if row.role_or_role_profile == "Role Profile":
				role_profiles.append(row)
			else:
				roles.append(row)
		if self.roles != role_profiles + roles:
			self.roles = []
			for index, row in enumerate(role_profiles + roles, start=1):
				row.idx = index
				self.roles.append(row)

	def get_settings(self, acs_url: str):
		return OneLogin_Saml2_Settings(
			{
				"strict": False,
				"sp": {
					"entityId": self.sp_entity_id,
					"assertionConsumerService": {
						"url": acs_url,
						"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					},
					"privateKey": self.get_password("sp_private_key"),
					"x509cert": self.sp_x509cert,
				},
				"idp": {
					"entityId": self.idp_entity_id,
					"singleSignOnService": {
						"url": self.idp_sso_url,
						"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
					},
					"x509cert": self.idp_x509cert,
				},
				"security": {
					"authnRequestsSigned": True,
					"signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
					"digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
					"rejectUnsolicitedResponsesWithInResponseTo": False,
				},
			}
		)


@frappe.whitelist(allow_guest=True)
def get_saml_domains():
	domains = []
	for key in frappe.get_all(
		"SAML Login Key", filters={"enable_saml_login": True}, pluck="name"
	):
		saml_key: SAMLLoginKey = frappe.get_doc("SAML Login Key", key)
		domains.extend(saml_key.domains)
	return domains
