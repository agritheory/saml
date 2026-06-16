# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import re
from datetime import datetime

import frappe
from croniter import CroniterBadCronError, croniter
from frappe import _
from frappe.model.document import Document
from frappe.utils import get_datetime, now_datetime
from frappe.utils.caching import request_cache

import requests
from onelogin.saml2.auth import OneLogin_Saml2_Settings


class SAMLLoginKey(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF
		from saml.saml.doctype.saml_group_mapping.saml_group_mapping import SAMLGroupMapping

		allow_relaxed_saml_validation: DF.Check
		auto_saml_login: DF.Check
		auto_saml_paths: DF.SmallText | None
		auto_saml_scope: DF.Literal["All Guest Routes", "Configured Paths", "Desk Only"]
		apply_saml_roles: DF.Check
		disallow_password_update: DF.Check
		enable_saml_login: DF.Check
		idp_entity_id: DF.Data | None
		idp_metadata_sync_cron: DF.Data | None
		idp_metadata_url: DF.Data | None
		idp_sso_url: DF.Data | None
		idp_x509cert: DF.Text | None
		last_idp_metadata_sync: DF.Datetime | None
		match_saml_roles: DF.Check
		provider_name: DF.Data
		roles: DF.Table[SAMLGroupMapping]
		saml_domains: DF.Text | None
		sp_entity_id: DF.Data | None
		sp_private_key: DF.Password | None
		sp_x509cert: DF.SmallText | None
		sync_idp_metadata: DF.Check
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
		self.validate_auto_saml_login_exclusivity()
		self.validate_auto_saml_paths()
		self.validate_idp_metadata_sync_cron()

	def on_update(self):
		auto_saml_fields = (
			"enable_saml_login",
			"auto_saml_login",
			"auto_saml_scope",
			"auto_saml_paths",
		)
		if any(self.has_value_changed(field) for field in auto_saml_fields):
			clear_auto_saml_settings_cache()

	def validate_auto_saml_paths(self):
		if not self.auto_saml_login or not self.enable_saml_login:
			return
		if self.auto_saml_scope != "Configured Paths":
			return
		if not (self.auto_saml_paths or "").strip():
			frappe.throw(_("Auto SAML Paths is required when Auto SAML Scope is Configured Paths."))
		for line in self.auto_saml_paths.splitlines():
			path = line.strip()
			if not path:
				continue
			if not path.startswith("/"):
				frappe.throw(_("Each Auto SAML Path must start with /: {0}").format(path))

	def validate_auto_saml_login_exclusivity(self):
		if not self.auto_saml_login or not self.enable_saml_login:
			return

		existing = frappe.get_all(
			"SAML Login Key",
			filters={
				"enable_saml_login": 1,
				"auto_saml_login": 1,
				"name": ["!=", self.name],
			},
			pluck="name",
			limit=1,
		)
		if existing:
			frappe.throw(
				_(
					"Auto SAML Login is already enabled on {0}. Only one enabled provider may use this setting."
				).format(frappe.bold(existing[0]))
			)

	def validate_idp_metadata_sync_cron(self):
		if not self.sync_idp_metadata:
			return

		if not self.idp_metadata_sync_cron:
			frappe.throw(_("Cron format is required when Sync IdP Metadata is enabled."))

		try:
			croniter(self.idp_metadata_sync_cron)
		except CroniterBadCronError:
			frappe.throw(
				_("{0} is not a valid Cron expression.").format(f"<code>{self.idp_metadata_sync_cron}</code>"),
				title=_("Bad Cron Expression"),
			)

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

	def get_idp_slo_url(self) -> str | None:
		return self.idp_sso_url

	def get_settings(self, acs_url: str, slo_url: str | None = None):
		security = {
			"authnRequestsSigned": bool(self.sp_private_key),
			"requestedAuthnContext": False,
			"signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			"digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
			"rejectUnsolicitedResponsesWithInResponseTo": False,
		}
		sp = {
			"entityId": self.sp_entity_id,
			"assertionConsumerService": {
				"url": acs_url,
				"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
			},
			"privateKey": self.get_password("sp_private_key") if self.sp_private_key else "",
			"x509cert": self.sp_x509cert,
		}
		idp = {
			"entityId": self.idp_entity_id,
			"singleSignOnService": {
				"url": self.idp_sso_url,
				"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
			"x509cert": self.idp_x509cert,
		}

		if slo_url and self.terminate_saml_session_on_logout:
			idp_slo_url = self.get_idp_slo_url()
			if idp_slo_url:
				sp["singleLogoutService"] = {
					"url": slo_url,
					"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
				}
				idp["singleLogoutService"] = {
					"url": idp_slo_url,
					"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
				}
				if self.sp_private_key:
					security["logoutRequestSigned"] = True
					security["logoutResponseSigned"] = True

		return OneLogin_Saml2_Settings(
			{
				"strict": not self.allow_relaxed_saml_validation,
				"sp": sp,
				"idp": idp,
				"security": security,
			}
		)

	def get_idp_metadata_url(self) -> str:
		if self.idp_metadata_url:
			return self.idp_metadata_url

		idp_entity_id = self.idp_entity_id
		if not idp_entity_id:
			frappe.throw(_("IDP Entity ID is required to sync the certificate"))

		assert idp_entity_id is not None
		return f"{idp_entity_id.rstrip('/')}/protocol/saml/descriptor"

	def sync_idp_metadata_from_url(self):
		metadata_url = self.get_idp_metadata_url()
		response = requests.get(metadata_url, timeout=30)
		response.raise_for_status()
		match = re.search(r"<ds:X509Certificate>([^<]+)</ds:X509Certificate>", response.text)
		if not match:
			frappe.throw(_("No X509Certificate found in IdP metadata at {0}").format(metadata_url))

		self.idp_x509cert = match.group(1)

	def sync_idp_certificate_from_descriptor(self):
		self.sync_idp_metadata_from_url()

	def is_idp_metadata_sync_due(self, current_time=None) -> bool:
		last_sync = get_datetime(self.last_idp_metadata_sync or self.creation)
		next_sync = croniter(self.idp_metadata_sync_cron, last_sync).get_next(datetime)
		return next_sync <= (current_time or now_datetime())


@frappe.whitelist()
def sync_idp_certificate(provider: str):
	frappe.only_for("System Manager")
	saml_key: SAMLLoginKey = frappe.get_doc("SAML Login Key", provider)
	saml_key.sync_idp_metadata_from_url()
	saml_key.last_idp_metadata_sync = now_datetime()
	saml_key.save(ignore_permissions=True)
	return {
		"synced": True,
		"provider": provider,
		"last_idp_metadata_sync": saml_key.last_idp_metadata_sync,
	}


def run_scheduled_idp_metadata_syncs():
	for provider in frappe.get_all(
		"SAML Login Key",
		filters={"enable_saml_login": 1, "sync_idp_metadata": 1},
		pluck="name",
	):
		try:
			saml_key: SAMLLoginKey = frappe.get_doc("SAML Login Key", provider)
			if not saml_key.is_idp_metadata_sync_due():
				continue

			saml_key.sync_idp_metadata_from_url()
			saml_key.last_idp_metadata_sync = now_datetime()
			saml_key.save(ignore_permissions=True)
			frappe.db.commit()
		except Exception:
			frappe.log_error(
				frappe.get_traceback(),
				_("Scheduled IdP metadata sync failed for {0}").format(provider),
			)


def clear_auto_saml_settings_cache():
	if hasattr(frappe.local, "request_cache"):
		cached_func = getattr(get_auto_saml_settings, "__wrapped__", None)
		if cached_func:
			frappe.local.request_cache.pop(cached_func, None)


@request_cache
def get_auto_saml_settings() -> dict | None:
	providers = frappe.get_all(
		"SAML Login Key",
		filters={"enable_saml_login": 1, "auto_saml_login": 1},
		fields=["name", "auto_saml_scope", "auto_saml_paths"],
		order_by="name",
	)
	if len(providers) != 1:
		return None
	return providers[0]


get_auto_saml_settings.clear_cache = clear_auto_saml_settings_cache


def get_auto_saml_provider() -> str | None:
	settings = get_auto_saml_settings()
	if settings:
		return settings["name"]
	return None


@frappe.whitelist(allow_guest=True)
def get_saml_domains():
	domains = []
	for key in frappe.get_all("SAML Login Key", filters={"enable_saml_login": True}, pluck="name"):
		saml_key: SAMLLoginKey = frappe.get_doc("SAML Login Key", key)
		domains.extend(saml_key.domains)
	return domains
