# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class SAMLLoginKey(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		enable_saml_login: DF.Check
		idp_entity_id: DF.Data | None
		idp_sso_url: DF.Data | None
		idp_x509cert: DF.Text | None
		provider_name: DF.Data
		sp_entity_id: DF.Data | None
		sp_private_key: DF.Password | None
		sp_x509cert: DF.SmallText | None
	# end: auto-generated types

	def autoname(self):
		self.name = frappe.scrub(self.provider_name)
