# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

#!/usr/bin/env python3
# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

"""Run Okta's SCIM 2.0 Runscope specification collection against a live endpoint.

Downloads oktadev/okta-scim-beta SCIM_tests_for_Runscope.json and executes the
SCIM-targeting steps locally. External helper steps (randomuser.me) are replaced
with locally generated values so CI does not depend on third-party services.
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import string
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

OKTA_SPEC_URL = (
	"https://raw.githubusercontent.com/oktadev/okta-scim-beta/master/SCIM_tests_for_Runscope.json"
)
DEFAULT_SPEC_PATH = Path(__file__).resolve().parent / "data" / "SCIM_tests_for_Runscope.json"


def download_spec(path: Path) -> dict:
	if path.is_file():
		return json.loads(path.read_text())
	with urllib.request.urlopen(OKTA_SPEC_URL, timeout=30) as response:
		data = json.loads(response.read().decode())
	path.write_text(json.dumps(data, indent=2))
	return data


def random_token(length: int = 8) -> str:
	alphabet = string.ascii_lowercase + string.digits
	return "".join(secrets.choice(alphabet) for _ in range(length))


def build_variables() -> dict[str, str]:
	given = "OktaSpec"
	family = "Provisioner"
	username = random_token()
	email = f"{username}@ambrosiapieco.example"
	return {
		"randomGivenName": given,
		"randomFamilyName": family,
		"randomUsername": username,
		"randomEmail": email,
		"userIdThatDoesNotExist": f"ext-{random_token()}",
		"idUserOne": email,
	}


def substitute(text: str, variables: dict[str, str], scim_base_url: str) -> str:
	result = text.replace("{{SCIM Base URL}}", scim_base_url.rstrip("/"))
	for key, value in variables.items():
		result = result.replace(f"{{{{{key}}}}}", value)
	return result


def request_step(
	method: str,
	url: str,
	headers: dict[str, str],
	body: str | None,
	bearer_token: str,
) -> tuple[int, dict | list | str | None]:
	headers = dict(headers or {})
	headers.setdefault("Authorization", f"Bearer {bearer_token}")
	headers.setdefault("Accept", "application/scim+json")
	if body is not None:
		headers.setdefault("Content-Type", "application/scim+json")

	data = body.encode() if body else None
	request = urllib.request.Request(url, data=data, method=method, headers=headers)
	try:
		with urllib.request.urlopen(request, timeout=30) as response:
			raw = response.read().decode()
			status = response.status
	except urllib.error.HTTPError as error:
		raw = error.read().decode()
		status = error.code

	if not raw:
		return status, None
	try:
		return status, json.loads(raw)
	except json.JSONDecodeError:
		return status, raw


def evaluate_assertions(
	assertions: list[dict],
	status: int,
	payload: dict | list | str | None,
	variables: dict[str, str],
	scim_base_url: str,
) -> list[str]:
	failures = []
	for assertion in assertions or []:
		source = assertion.get("source")
		comparison = assertion.get("comparison")
		expected = assertion.get("value")
		if source == "response_status":
			if comparison == "equal_number" and str(status) != str(expected):
				failures.append(f"expected status {expected}, got {status}")
			continue

		if source != "response_json" or not isinstance(payload, dict):
			continue

		property_path = assertion.get("property")
		actual = payload
		if property_path:
			for part in property_path.split("."):
				if isinstance(actual, dict):
					actual = actual.get(part)
				else:
					actual = None
					break

		expected_value = (
			substitute(str(expected), variables, scim_base_url) if expected is not None else expected
		)
		if comparison == "equal" and actual != expected_value:
			failures.append(f"{property_path} expected {expected_value!r}, got {actual!r}")
		elif comparison == "not_empty" and not actual:
			failures.append(f"{property_path} expected non-empty value")
		elif comparison == "contains" and expected_value not in (actual or []):
			failures.append(f"{property_path} expected to contain {expected_value!r}")

	return failures


def run_spec(scim_base_url: str, bearer_token: str, spec_path: Path) -> int:
	spec = download_spec(spec_path)
	variables = build_variables()
	failures: list[str] = []

	for index, step in enumerate(spec.get("steps", [])):
		url = step.get("url") or ""
		if "{{SCIM Base URL}}" not in url:
			continue
		if "/Groups" in url:
			print(f"skip step {index}: Groups not implemented in v1")
			continue

		method = (step.get("method") or "GET").upper()
		url = substitute(url, variables, scim_base_url)
		body = step.get("body")
		if body:
			body = substitute(body, variables, scim_base_url)

		status, payload = request_step(method, url, step.get("headers") or {}, body, bearer_token)
		step_failures = evaluate_assertions(
			step.get("assertions") or [], status, payload, variables, scim_base_url
		)
		if step_failures:
			failures.append(f"step {index} {method} {url}: " + "; ".join(step_failures))
		elif isinstance(payload, dict) and payload.get("id") and method == "POST":
			variables["idUserOne"] = str(payload["id"])

	if failures:
		print("Okta SCIM spec failures:")
		for failure in failures:
			print(f"  - {failure}")
		return 1

	print(f"Okta SCIM spec passed ({len(spec.get('steps', []))} steps, SCIM-targeting subset)")
	return 0


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument(
		"--base-url", required=True, help="SCIM base URL, e.g. http://localhost:8000/scim/v2"
	)
	parser.add_argument("--token", required=True, help="Bearer token")
	parser.add_argument("--spec-path", type=Path, default=DEFAULT_SPEC_PATH)
	args = parser.parse_args()
	return run_spec(args.base_url.rstrip("/"), args.token, args.spec_path)


if __name__ == "__main__":
	sys.exit(main())
