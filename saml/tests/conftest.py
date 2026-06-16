# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import json
from pathlib import Path
from unittest.mock import MagicMock

import frappe
import pytest
from frappe.utils import get_bench_path


def _get_logger(*args, **kwargs):
	from frappe.utils.logger import get_logger

	return get_logger(
		module=None,
		with_more_info=False,
		allow_site=True,
		filter=None,
		max_size=100_000,
		file_count=20,
		stream_only=True,
	)


@pytest.fixture(scope="module")
def monkeymodule():
	with pytest.MonkeyPatch.context() as mp:
		yield mp


@pytest.fixture(scope="session", autouse=True)
def db_instance():
	frappe.logger = _get_logger

	currentsite = "test_site"
	sites = Path(get_bench_path()) / "sites"
	if (sites / "common_site_config.json").is_file():
		currentsite = json.loads((sites / "common_site_config.json").read_text()).get("default_site")

	frappe.init(site=currentsite, sites_path=sites)
	frappe.connect()
	frappe.db.commit = MagicMock()
	yield frappe.db


@pytest.fixture(autouse=True)
def reset_saml_request_state():
	from saml.saml.doctype.saml_login_key.saml_login_key import clear_auto_saml_settings_cache

	clear_auto_saml_settings_cache()
	for key in ("saml_auto_redirect_url", "redirect_location"):
		frappe.local.flags.pop(key, None)
	yield
	clear_auto_saml_settings_cache()
	for key in ("saml_auto_redirect_url", "redirect_location"):
		frappe.local.flags.pop(key, None)
