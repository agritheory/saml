#!/usr/bin/env python3
# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

"""Run Okta's SCIM 2.0 Runscope specification collection against a live endpoint.

Executes the SCIM-targeting steps from the vendored oktadev/okta-scim-beta
SCIM_tests_for_Runscope.json. External helper steps (randomuser.me) are replaced
with locally generated values so CI does not depend on third-party services.
"""

from __future__ import annotations

import argparse
import json
import secrets
import string
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

OKTA_SPEC_URL = (
	"https://raw.githubusercontent.com/oktadev/okta-scim-beta/master/SCIM_tests_for_Runscope.json"
)
DEFAULT_SPEC_PATH = Path(__file__).resolve().parent / "data" / "SCIM_tests_for_Runscope.json"

SUPPORTED_COMPARISONS = frozenset(
	{"equal", "equal_number", "not_empty", "has_value", "is_a_number", "contains"}
)


def load_spec(path: Path) -> dict:
	"""Load the vendored collection, falling back to the upstream copy."""
	if path.is_file():
		return json.loads(path.read_text())
	with urllib.request.urlopen(OKTA_SPEC_URL, timeout=30) as response:
		return json.loads(response.read().decode())


def normalize_url(url: str) -> str:
	"""Percent-encode a spec URL; its filter expressions contain raw spaces and quotes."""
	parts = urllib.parse.urlsplit(url)
	return urllib.parse.urlunsplit(
		parts._replace(
			path=urllib.parse.quote(parts.path, safe="/%"),
			query=urllib.parse.quote(parts.query, safe="=&%"),
		)
	)


def flatten_headers(headers: dict[str, Any] | None) -> dict[str, str]:
	"""Collapse Runscope's `{name: [value]}` header form to `{name: value}`."""
	flattened = {}
	for key, value in (headers or {}).items():
		if isinstance(value, (list, tuple)):
			if not value:
				continue
			value = value[0]
		flattened[key] = str(value)
	return flattened


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
	headers = flatten_headers(headers)
	headers.pop("Authentication", None)
	headers.setdefault("Authorization", f"Bearer {bearer_token}")
	headers.setdefault("Accept", "application/scim+json")
	if body is not None:
		headers.setdefault("Content-Type", "application/scim+json")

	data = body.encode() if body else None
	request = urllib.request.Request(normalize_url(url), data=data, method=method, headers=headers)
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
		actual: Any = payload
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
		if comparison == "equal" and not values_equal(actual, expected_value):
			failures.append(f"{property_path} expected {expected_value!r}, got {actual!r}")
		elif comparison == "equal_number" and not numbers_equal(actual, expected):
			failures.append(f"{property_path} expected number {expected!r}, got {actual!r}")
		elif comparison == "not_empty" and not actual:
			failures.append(f"{property_path} expected non-empty value")
		elif comparison == "has_value" and not (
			values_equal(actual, expected_value) or contains(actual, expected_value)
		):
			failures.append(f"{property_path} expected to hold {expected_value!r}, got {actual!r}")
		elif comparison == "is_a_number" and not is_number(actual):
			failures.append(f"{property_path} expected a number, got {actual!r}")
		elif comparison == "contains" and not contains(actual, expected_value):
			failures.append(f"{property_path} expected to contain {expected_value!r}")
		elif comparison not in SUPPORTED_COMPARISONS:
			failures.append(f"{property_path} uses unsupported comparison {comparison!r}")

	return failures


def values_equal(actual: Any, expected: Any) -> bool:
	"""Compare a JSON value against a spec value, which is always stored as a string."""
	if isinstance(actual, bool):
		return str(actual).lower() == str(expected).strip().lower()
	if actual is None:
		return expected is None
	return actual == expected or str(actual) == str(expected)


def is_number(value: Any) -> bool:
	if isinstance(value, bool):
		return False
	if isinstance(value, (int, float)):
		return True
	try:
		float(value)
	except (TypeError, ValueError):
		return False
	return True


def numbers_equal(actual: Any, expected: Any) -> bool:
	if not is_number(actual) or not is_number(expected):
		return False
	return float(actual) == float(expected)


def contains(actual: Any, expected: Any) -> bool:
	if actual is None:
		return False
	if isinstance(actual, str):
		return str(expected) in actual
	try:
		return expected in actual
	except TypeError:
		return False


def seed_user(scim_base_url: str, bearer_token: str) -> str | None:
	"""Create one user so the collection's opening list assertions have data.

	Deliberately not `randomEmail`: a later step asserts that address is still absent.
	"""
	email = f"okta-spec-seed-{random_token()}@ambrosiapieco.example"
	body = json.dumps(
		{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": email,
			"name": {"givenName": "Seed", "familyName": "User"},
			"active": True,
		}
	)
	status, _ = request_step("POST", f"{scim_base_url}/Users", {}, body, bearer_token)
	if status not in (200, 201):
		print(f"warning: could not seed a user for the list assertions (status {status})")
		return None
	return email


def run_spec(scim_base_url: str, bearer_token: str, spec_path: Path) -> int:
	spec = load_spec(spec_path)
	variables = build_variables()
	seeded = seed_user(scim_base_url, bearer_token)
	failures: list[str] = []
	steps = spec.get("steps", [])
	executed = 0
	skipped: list[str] = []

	for index, step in enumerate(steps):
		url = step.get("url") or ""
		if "{{SCIM Base URL}}" not in url:
			skipped.append(f"step {index}: not a SCIM request")
			continue
		if "/Groups" in url:
			skipped.append(f"step {index}: /Groups is not implemented")
			continue

		method = (step.get("method") or "GET").upper()
		url = substitute(url, variables, scim_base_url)
		body = step.get("body")
		if body:
			body = substitute(body, variables, scim_base_url)

		status, payload = request_step(method, url, step.get("headers") or {}, body, bearer_token)
		executed += 1
		step_failures = evaluate_assertions(
			step.get("assertions") or [], status, payload, variables, scim_base_url
		)
		if method == "POST" and isinstance(payload, dict) and payload.get("id"):
			variables["idUserOne"] = str(payload["id"])
		if step_failures:
			failures.append(f"step {index} {method} {url}: " + "; ".join(step_failures))

	if seeded:
		request_step("DELETE", f"{scim_base_url}/Users/{urllib.parse.quote(seeded, safe='')}", {}, None, bearer_token)

	for note in skipped:
		print(f"skipped {note}")

	if not executed:
		print("Okta SCIM spec executed 0 steps - the collection did not load correctly")
		return 1

	if failures:
		print(f"Okta SCIM spec: {executed} steps executed, {len(failures)} failed")
		for failure in failures:
			print(f"  - {failure}")
		return 1

	print(f"Okta SCIM spec passed ({executed} of {len(steps)} steps executed, {len(skipped)} skipped)")
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
