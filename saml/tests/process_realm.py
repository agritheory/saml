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
				print(f"Found frappe-saml client, updating URLs to {base_url}")

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


def main():
	bench_port = os.environ.get("BENCH_PORT", "8000")
	base_url = f"http://localhost:{bench_port}"
	keycloak_scim_base_url = os.environ.get(
		"KEYCLOAK_SCIM_BASE_URL",
		f"http://host.docker.internal:{bench_port}/scim/v2",
	)
	bearer_token = os.environ.get("SCIM_BEARER_TOKEN", "test-scim-bearer-token")

	print(f"Processing realm export with base URL: {base_url}")
	print(f"Generating SCIM Keycloak config with endpoint: {keycloak_scim_base_url}")

	realm_input = Path("/app/realm-template.json")
	realm_output = Path("/app/realm-export.json")
	scim_template_path = Path("/app/data/scim_keycloak_config.template.json")
	scim_output = Path("/app/scim-keycloak-config.json")

	with realm_input.open() as handle:
		realm_data = json.load(handle)
	modified_realm = modify_realm_urls(realm_data, base_url)
	realm_output.write_text(json.dumps(modified_realm, indent=2))
	print(f"Modified realm exported to {realm_output}")

	with scim_template_path.open() as handle:
		scim_template = json.load(handle)
	scim_config = render_scim_keycloak_config(scim_template, keycloak_scim_base_url, bearer_token)
	scim_output.write_text(json.dumps(scim_config, indent=2))
	print(f"SCIM Keycloak config exported to {scim_output}")


if __name__ == "__main__":
	main()
