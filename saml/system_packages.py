# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

"""Debian/Ubuntu system package helpers for Frappe install hooks.

Used from after_install so ``bench --site … install-app`` can suggest OS
dependencies without duplicating package lists in Ansible.
"""

from __future__ import annotations

import os
import subprocess
import sys
from getpass import getpass

ENV_NONINTERACTIVE = "FRAPPE_INSTALL_NONINTERACTIVE"

# Runtime packages satisfy the matching -dev package for install checks.
PACKAGE_ALTERNATIVES: dict[str, list[str]] = {
	"libxml2-dev": ["libxml2", "libxml2-dev"],
	"libxslt-dev": ["libxslt1.1", "libxslt-dev"],
	"libxmlsec1-dev": ["libxmlsec1", "libxmlsec1-dev"],
	"libxmlsec1-openssl": ["libxmlsec1-openssl"],
	"pkg-config": ["pkg-config"],
	"python3-lxml": ["python3-lxml"],
}


def is_noninteractive() -> bool:
	return os.environ.get(ENV_NONINTERACTIVE) == "1" or not sys.stdin.isatty()


def dpkg_installed(package: str) -> bool:
	return (
		subprocess.run(
			["dpkg", "-s", package],
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL,
		).returncode
		== 0
	)


def package_satisfied(package: str) -> bool:
	if package == "python3-lxml":
		try:
			import lxml.etree  # noqa: F401
		except ImportError:
			return dpkg_installed("python3-lxml")
		return True

	for candidate in PACKAGE_ALTERNATIVES.get(package, [package]):
		if dpkg_installed(candidate):
			return True
	return False


def missing_packages(packages: list[str]) -> list[str]:
	return [package for package in packages if not package_satisfied(package)]


def xml_stack_ready() -> bool:
	"""Return True when lxml and xmlsec load without a libxml2 mismatch."""
	try:
		import lxml.etree  # noqa: F401
		import xmlsec
	except Exception:
		return False

	try:
		xmlsec.init()
		xmlsec.shutdown()
	except xmlsec.InternalError:
		return False
	except Exception:
		# Older xmlsec builds may not expose init/shutdown; import success is enough.
		return True

	return True


def install_packages_with_sudo(packages: list[str], password: str = "") -> None:
	args = ["sudo", "-S", "apt-get", "install", "-y", *packages]
	kwargs: dict = {
		"stdout": subprocess.PIPE,
		"stderr": subprocess.PIPE,
		"text": True,
		"encoding": "ascii",
		"env": {**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
	}
	if password:
		kwargs["input"] = password
	result = subprocess.run(args, **kwargs)
	if result.returncode != 0:
		print(f"Could not install {', '.join(packages)}: {result.stderr.strip()}")


def ensure_debian_packages(packages: list[str]) -> None:
	"""Install missing Debian packages when possible; otherwise print instructions."""
	if sys.platform != "linux":
		print(f"Install system packages manually: {', '.join(packages)}")
		return

	missing = missing_packages(packages)
	if not missing:
		return

	install_command = f"sudo apt-get install -y {' '.join(missing)}"

	if os.geteuid() == 0:
		subprocess.run(
			["apt-get", "update"],
			check=False,
			env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
		)
		subprocess.run(
			["apt-get", "install", "-y", *missing],
			check=False,
			env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
		)
		return

	if is_noninteractive():
		print("SAML system packages are not fully installed. " f"Run: {install_command}")
		return

	password = getpass(
		f"SAML needs {', '.join(missing)}. Enter sudo password to install (leave blank to skip): "
	)
	if not password.strip():
		print(f"Skipped system package install. Run manually: {install_command}")
		return

	install_packages_with_sudo(missing, password)
