# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

"""
SCIM conformance acceptance tests are executed by saml/tests/run_scim_conformance.sh
in CI (parallel Okta spec + Entra-style probe). This module documents the gate only.
"""

import shutil
from pathlib import Path

import pytest

CONFORMANCE_SCRIPT = Path(__file__).resolve().parent / "run_scim_conformance.sh"


@pytest.mark.conformance
def test_scim_conformance_runner_exists():
	assert CONFORMANCE_SCRIPT.is_file()
	assert shutil.which("bash") is not None
