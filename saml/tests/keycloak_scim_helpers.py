# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

import json
import subprocess
from pathlib import Path
from typing import Any

import frappe
import requests

from saml.tests.scim_helpers import TEST_SCIM_TOKEN, setup_scim_settings

TESTS_DIR = Path(__file__).resolve().parent
SCIM_KEYCLOAK_CONFIG_PATH = TESTS_DIR / "scim-keycloak-config.json"
SCIM_KEYCLOAK_TEMPLATE_PATH = TESTS_DIR / "data" / "scim_keycloak_config.template.json"


def render_scim_keycloak_config(
	template: dict[str, Any],
	scim_base_url: str,
	bearer_token: str,
) -> dict[str, Any]:
	config = json.loads(json.dumps(template))
	config.pop("_comment", None)

	component = config["components"]["org.keycloak.storage.UserStorageProvider"][0]
	component["config"]["endpoint"] = [scim_base_url]
	component["config"]["auth-pass"] = [bearer_token]
	return config


def load_scim_keycloak_config() -> dict:
	if not SCIM_KEYCLOAK_CONFIG_PATH.is_file():
		generate_scim_keycloak_config_file()
	return json.loads(SCIM_KEYCLOAK_CONFIG_PATH.read_text())


def generate_scim_keycloak_config_file(
	bench_port: int | None = None,
	bearer_token: str = TEST_SCIM_TOKEN,
) -> dict:
	bench_port = bench_port or int(frappe.conf.get("webserver_port") or 8000)
	template = json.loads(SCIM_KEYCLOAK_TEMPLATE_PATH.read_text())
	keycloak_scim_base_url = f"http://host.docker.internal:{bench_port}/scim/v2"
	config = render_scim_keycloak_config(template, keycloak_scim_base_url, bearer_token)
	SCIM_KEYCLOAK_CONFIG_PATH.write_text(json.dumps(config, indent=2))
	return config


def push_keycloak_scim_config(
	admin_url: str = "http://localhost:8080",
	admin_user: str = "admin",
	admin_password: str = "admin",
) -> None:
	"""Apply scim-keycloak-config.json via kcadm inside the Keycloak container.

	Requires the pelotech/keycloak-scim plugin JAR on the Keycloak server.
	"""
	config = load_scim_keycloak_config()
	component = config["components"]["org.keycloak.storage.UserStorageProvider"][0]
	component_config = component["config"]

	command = [
		"/opt/keycloak/bin/kcadm.sh",
		"create",
		"components",
		"-r",
		config["realm"],
		"--server",
		admin_url,
		"--realm",
		"master",
		"--user",
		admin_user,
		"--password",
		admin_password,
		"-s",
		f"name={component['name']}",
		"-s",
		f"providerId={component['providerId']}",
		"-s",
		"providerType=org.keycloak.storage.UserStorageProvider",
	]
	for key, values in component_config.items():
		command.extend(["-s", f"config.{key}={json.dumps(values)}"])

	subprocess.run(command, check=True)


def keycloak_admin_ready(admin_url: str = "http://localhost:8080") -> bool:
	try:
		response = requests.get(f"{admin_url}/health/ready", timeout=5)
		return response.status_code == 200
	except requests.RequestException:
		return False


def scim_config_matches_frappe_settings(config: dict | None = None) -> bool:
	config = config or load_scim_keycloak_config()
	settings = setup_scim_settings()
	component = config["components"]["org.keycloak.storage.UserStorageProvider"][0]
	endpoint = component["config"]["endpoint"][0]
	token = component["config"]["auth-pass"][0]
	return endpoint.endswith("/scim/v2") and token == settings.get_password("bearer_token")
