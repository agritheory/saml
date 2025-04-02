# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import json
import os
from typing import Any


def modify_realm_urls(realm_data: dict[str, Any], base_url: str) -> dict[str, Any]:
	modified_data = realm_data.copy()
	if "clients" in modified_data:
		for client in modified_data["clients"]:
			if client.get("clientId") == "frappe-saml":
				print(f"Found frappe-saml client, updating URLs to {base_url}")

				client["rootUrl"] = base_url
				client["baseUrl"] = base_url
				client["redirectUris"] = [f"{base_url}/*"]
				client["webOrigins"] = [base_url]
	return modified_data


def main():
	bench_port = os.environ.get("BENCH_PORT", "8000")
	base_url = f"http://localhost:{bench_port}"
	print(f"Processing realm export with base URL: {base_url}")

	input_file = "/app/realm-template.json"
	output_file = "/app/realm-export.json"

	with open(input_file) as f:
		realm_data = json.load(f)
		modified_data = modify_realm_urls(realm_data, base_url)
		with open(output_file, "w") as f:
			json.dump(modified_data, f, indent=2)

	print(f"Modified realm exported to {output_file}")


if __name__ == "__main__":
	main()
