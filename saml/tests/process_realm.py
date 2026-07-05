# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


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


def find_bench_sites_path() -> Path:
	tests_dir = Path(__file__).resolve().parent
	return (tests_dir / ".." / ".." / ".." / ".." / "sites").resolve()


def get_realm_base_url_from_bench_files(sites_path: Path | None = None) -> str:
	"""Build the SAML base URL from bench site config files."""
	sites_path = sites_path or find_bench_sites_path()
	common_config_path = sites_path / "common_site_config.json"
	if not common_config_path.is_file():
		raise FileNotFoundError(f"Bench config not found: {common_config_path}")

	common_config = json.loads(common_config_path.read_text())
	port = common_config.get("webserver_port", 8000)
	host_name = ""
	default_site = common_config.get("default_site")
	if default_site:
		site_config_path = sites_path / default_site / "site_config.json"
		if site_config_path.is_file():
			host_name = json.loads(site_config_path.read_text()).get("host_name") or ""

	if host_name:
		if not host_name.startswith("http"):
			host_name = f"http://{host_name}"
		parsed = urlparse(host_name)
		hostname = parsed.hostname or "localhost"
		scheme = parsed.scheme or "http"
		if hostname in ("localhost", "127.0.0.1"):
			return f"{scheme}://{hostname}:{port}"
		if parsed.port:
			return host_name.rstrip("/")
		return f"{scheme}://{hostname}:{port}"

	return f"http://localhost:{port}"


def get_realm_base_url() -> str:
	try:
		import frappe

		if getattr(frappe.local, "site", None):
			from saml.tests.keycloak_helpers import get_bench_base_url

			return get_bench_base_url()
	except Exception:
		pass

	return get_realm_base_url_from_bench_files()


def process_realm_export(
	base_url: str | None = None,
	input_file: Path | None = None,
	output_file: Path | None = None,
) -> Path:
	base_url = base_url or get_realm_base_url()
	print(f"Processing realm export with base URL: {base_url}")

	tests_dir = Path(__file__).resolve().parent
	input_file = input_file or tests_dir / "realm-template.json"
	output_file = output_file or tests_dir / "realm-export.json"

	with open(input_file) as file:
		realm_data = json.load(file)
	modified_data = modify_realm_urls(realm_data, base_url)
	with open(output_file, "w") as file:
		json.dump(modified_data, file, indent=2)

	print(f"Modified realm exported to {output_file}")
	return output_file


def main():
	process_realm_export()


if __name__ == "__main__":
	main()
