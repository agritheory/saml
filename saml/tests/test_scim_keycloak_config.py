# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

import json

import frappe
import pytest

from saml.tests.keycloak_scim_helpers import (
	SCIM_KEYCLOAK_CONFIG_PATH,
	generate_scim_keycloak_config_file,
	load_scim_keycloak_config,
	scim_config_matches_frappe_settings,
)
from saml.tests.scim_helpers import TEST_SCIM_TOKEN


@pytest.mark.order(150)
def test_scim_keycloak_config_is_generated_for_review():
	"""Warehouse team reviews saml/tests/scim-keycloak-config.json before enabling Keycloak SCIM."""
	config = generate_scim_keycloak_config_file()
	assert SCIM_KEYCLOAK_CONFIG_PATH.is_file()

	component = config["components"]["org.keycloak.storage.UserStorageProvider"][0]
	assert component["providerId"] == "scim"
	assert component["config"]["auth-mode"] == ["BEARER"]
	assert component["config"]["propagation-group"] == ["false"]
	assert "host.docker.internal" in component["config"]["endpoint"][0]


@pytest.mark.order(151)
def test_scim_keycloak_config_matches_frappe_scim_settings():
	config = load_scim_keycloak_config()
	settings = frappe.get_doc("SCIM Settings")
	component = config["components"]["org.keycloak.storage.UserStorageProvider"][0]

	assert component["config"]["auth-pass"][0] == settings.get_password("bearer_token")
	assert component["config"]["auth-pass"][0] == TEST_SCIM_TOKEN
	assert scim_config_matches_frappe_settings(config)


@pytest.mark.order(152)
def test_scim_keycloak_config_documents_review_users():
	config = load_scim_keycloak_config()
	usernames = {user["username"] for user in config.get("test_users", [])}
	assert "warehouse@ambrosiapieco.example" in usernames
	assert "scim.provision@ambrosiapieco.example" in usernames


@pytest.mark.order(153)
def test_scim_keycloak_config_serializes_cleanly():
	config = load_scim_keycloak_config()
	serialized = json.dumps(config, indent=2)
	assert "frappe-scim" in serialized
	assert "user-extension-mappings" in serialized
