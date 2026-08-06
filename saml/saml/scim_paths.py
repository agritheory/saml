# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

from __future__ import annotations

from typing import Any


def deep_get(data: dict, path: str) -> Any:
	current: Any = data
	for part in path.split("."):
		if not isinstance(current, dict):
			return None
		current = current.get(part)
	return current


def set_deep(data: dict, path: str, value: Any) -> None:
	parts = path.split(".")
	current = data
	for part in parts[:-1]:
		next_value = current.get(part)
		if not isinstance(next_value, dict):
			next_value = {}
			current[part] = next_value
		current = next_value
	current[parts[-1]] = value


def extract_scim_path(data: dict, path: str) -> Any:
	path = (path or "").strip()
	if not path:
		return None

	if ":" in path and not path.startswith("name."):
		extension_key, _, attribute = path.rpartition(":")
		if extension_key in data:
			extension = data.get(extension_key) or {}
			if isinstance(extension, dict):
				return extension.get(attribute)
		return None

	return deep_get(data, path)
