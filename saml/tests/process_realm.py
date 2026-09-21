# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

import json
import os
from pathlib import Path
from typing import Any


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


def modify_realm_urls(realm_data: dict[str, Any], base_url: str) -> dict[str, Any]:
	modified_data = realm_data.copy()
	if "clients" in modified_data:
		for client in modified_data["clients"]:
			if client.get("clientId") == "frappe-saml":
				acs_path = "/api/method/saml.saml.acs"
				slo_path = "/api/method/saml.saml.logout.slo?provider=keycloak"
				client["rootUrl"] = base_url
				client["baseUrl"] = base_url
				client["redirectUris"] = [
					f"{base_url}/*",
					f"{base_url}{acs_path}",
					f"{base_url}{acs_path}?provider=keycloak",
				]
				client["webOrigins"] = [base_url]
				attributes = client.setdefault("attributes", {})
				attributes["saml_single_logout_service_url_redirect"] = f"{base_url}{slo_path}"
				attributes["saml_single_logout_service_url_post"] = f"{base_url}{slo_path}"
				break
	return modified_data


def generate_keycloak_test_files(
	tests_dir: Path,
	bench_port: int | str,
	bearer_token: str = "test-scim-bearer-token",
	keycloak_scim_base_url: str | None = None,
) -> None:
	"""Write realm-export.json and scim-keycloak-config.json for the test Keycloak stack."""
	tests_dir = Path(tests_dir)
	bench_port = str(bench_port)
	base_url = f"http://localhost:{bench_port}"
	if keycloak_scim_base_url is None:
		keycloak_scim_base_url = f"http://host.docker.internal:{bench_port}/scim/v2"

	realm_input = tests_dir / "realm-template.json"
	realm_output = tests_dir / "realm-export.json"
	scim_template_path = tests_dir / "data" / "scim_keycloak_config.template.json"
	scim_output = tests_dir / "scim-keycloak-config.json"

	realm_data = json.loads(realm_input.read_text())
	modified_realm = modify_realm_urls(realm_data, base_url)
	realm_output.write_text(json.dumps(modified_realm, indent=2))

	scim_template = json.loads(scim_template_path.read_text())
	scim_config = render_scim_keycloak_config(scim_template, keycloak_scim_base_url, bearer_token)
	scim_output.write_text(json.dumps(scim_config, indent=2))


def main():
	bench_port = os.environ.get("BENCH_PORT", "8000")
	keycloak_scim_base_url = os.environ.get(
		"KEYCLOAK_SCIM_BASE_URL",
		f"http://host.docker.internal:{bench_port}/scim/v2",
	)
	bearer_token = os.environ.get("SCIM_BEARER_TOKEN", "test-scim-bearer-token")
	tests_dir = Path("/app")

	print(f"Processing realm export with base URL: http://localhost:{bench_port}")
	print(f"Generating SCIM Keycloak config with endpoint: {keycloak_scim_base_url}")

	generate_keycloak_test_files(
		tests_dir,
		bench_port,
		bearer_token=bearer_token,
		keycloak_scim_base_url=keycloak_scim_base_url,
	)
	print(f"Modified realm exported to {tests_dir / 'realm-export.json'}")
	print(f"SCIM Keycloak config exported to {tests_dir / 'scim-keycloak-config.json'}")


if __name__ == "__main__":
	main()
