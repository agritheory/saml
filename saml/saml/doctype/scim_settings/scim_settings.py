# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.model.document import Document


class SCIMSettings(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		bearer_token: DF.Password | None
		default_role: DF.Link | None
		default_user_type: DF.Link
		do_not_create_new_user: DF.Check
		enabled: DF.Check
		identity_provider: DF.Link | None
		service_user: DF.Link | None

	# end: auto-generated types

	def validate(self):
		if self.enabled and not self.identity_provider:
			frappe.throw(
				_("Identity Provider is required when SCIM is enabled."), title=_("Missing Provider")
			)
		if self.enabled and not frappe.db.exists("SAML Login Key", self.identity_provider):
			frappe.throw(_("Identity Provider {0} does not exist.").format(self.identity_provider))


def get_scim_settings() -> "SCIMSettings":
	return frappe.get_cached_doc("SCIM Settings")
