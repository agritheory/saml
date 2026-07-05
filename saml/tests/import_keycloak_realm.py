# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

"""Import the processed Keycloak realm export used by SAML integration tests."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import requests

DEFAULT_KEYCLOAK_URL = "http://localhost:8080"
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"
DEFAULT_REALM_NAME = "frappe"


def wait_for_keycloak(base_url: str, timeout: int = 120) -> None:
	deadline = time.time() + timeout
	while time.time() < deadline:
		try:
			response = requests.get(f"{base_url.rstrip('/')}/health/ready", timeout=5)
			if response.status_code == 200:
				return
		except requests.RequestException:
			pass
		time.sleep(2)
	raise RuntimeError(f"Keycloak not ready at {base_url}")


def wait_for_realm_saml(
	base_url: str, realm_name: str = DEFAULT_REALM_NAME, timeout: int = 120
) -> None:
	deadline = time.time() + timeout
	descriptor_url = f"{base_url.rstrip('/')}/realms/{realm_name}/protocol/saml/descriptor"
	while time.time() < deadline:
		try:
			response = requests.get(descriptor_url, timeout=5)
			if response.status_code == 200:
				return
		except requests.RequestException:
			pass
		time.sleep(2)
	raise RuntimeError(f"Keycloak SAML descriptor not ready at {descriptor_url}")


def get_admin_token(base_url: str, username: str, password: str) -> str:
	response = requests.post(
		f"{base_url.rstrip('/')}/realms/master/protocol/openid-connect/token",
		data={
			"grant_type": "password",
			"client_id": "admin-cli",
			"username": username,
			"password": password,
		},
		timeout=30,
	)
	response.raise_for_status()
	return response.json()["access_token"]


def import_realm(base_url: str, realm_path: Path, username: str, password: str) -> None:
	token = get_admin_token(base_url, username, password)
	headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
	realm = json.loads(realm_path.read_text())
	realm_name = realm["realm"]
	realm_url = f"{base_url.rstrip('/')}/admin/realms/{realm_name}"

	existing = requests.get(realm_url, headers=headers, timeout=30)
	if existing.status_code == 200:
		response = requests.put(realm_url, headers=headers, json=realm, timeout=60)
	else:
		response = requests.post(
			f"{base_url.rstrip('/')}/admin/realms",
			headers=headers,
			json=realm,
			timeout=60,
		)

	if response.status_code not in (201, 204):
		raise RuntimeError(f"Keycloak realm import failed ({response.status_code}): {response.text}")

	wait_for_realm_saml(base_url, realm_name)


def main() -> None:
	tests_dir = Path(__file__).resolve().parent
	base_url = os.environ.get("KEYCLOAK_URL", DEFAULT_KEYCLOAK_URL)
	realm_path = Path(os.environ.get("REALM_EXPORT", tests_dir / "realm-export.json"))
	username = os.environ.get("KEYCLOAK_ADMIN", DEFAULT_ADMIN_USER)
	password = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)

	wait_for_keycloak(base_url)
	import_realm(base_url, realm_path, username, password)
	print(f"Imported Keycloak realm from {realm_path}")


if __name__ == "__main__":
	try:
		main()
	except Exception as error:
		print(error, file=sys.stderr)
		raise
