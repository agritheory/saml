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


def set_scim_resource_path(resource: dict, path: str, value: Any) -> None:
	"""Write a value onto a SCIM resource at the same paths extract_scim_path reads."""
	path = (path or "").strip()
	if not path:
		return

	if ":" in path and not path.startswith("name."):
		extension_key, _, attribute = path.rpartition(":")
		resource.setdefault(extension_key, {})[attribute] = value
		return

	if "." in path:
		set_deep(resource, path, value)
		return

	resource[path] = value


def remove_scim_resource_path(resource: dict, path: str) -> None:
	"""Remove a value from a SCIM resource at the same paths extract_scim_path reads."""
	path = (path or "").strip()
	if not path:
		return

	if ":" in path and not path.startswith("name."):
		extension_key, _, attribute = path.rpartition(":")
		extension = resource.get(extension_key)
		if isinstance(extension, dict):
			extension.pop(attribute, None)
		return

	if "." in path:
		parent_path, leaf = path.rsplit(".", 1)
		parent = deep_get(resource, parent_path)
		if isinstance(parent, dict):
			parent.pop(leaf, None)
		return

	resource.pop(path, None)
