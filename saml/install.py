# Copyright (c) 2025, AgriTheory and contributors
# For license information, please see license.txt

import subprocess
import sys

from saml.system_packages import ensure_debian_packages, missing_packages, xml_stack_ready

# Keep lxml/xmlsec on the same system libxml2 (https://lxml.de/installation.html).
DEBIAN_PACKAGES = [
	"libxml2-dev",
	"libxslt-dev",
	"libxmlsec1-dev",
	"libxmlsec1-openssl",
	"pkg-config",
	"python3-lxml",
]


def after_install():
	if xml_stack_ready():
		return

	missing = missing_packages(DEBIAN_PACKAGES)
	if missing:
		print(
			"SAML lxml/xmlsec stack is not ready. " f"Install: sudo apt-get install -y {' '.join(missing)}"
		)

	ensure_debian_packages(DEBIAN_PACKAGES)

	if xml_stack_ready():
		return

	# Prefer the system libxml2 binding when python3-lxml is available; otherwise refresh pip lxml.
	subprocess.run(
		[sys.executable, "-m", "pip", "install", "--force-reinstall", "lxml"],
		check=False,
	)

	if not xml_stack_ready():
		print(
			"SAML installed, but lxml/xmlsec may still fail at runtime. "
			"See README for libxml2 mismatch troubleshooting."
		)
