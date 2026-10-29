#!/usr/bin/env bash
# Copyright (c) 2026, AgriTheory and contributors
# For license information, please see license.txt

set -euo pipefail

SCIM_BASE_URL="${SCIM_BASE_URL:-http://127.0.0.1:8000/scim/v2}"
SCIM_BEARER_TOKEN="${SCIM_BEARER_TOKEN:-test-scim-bearer-token}"
BENCH_DIR="${BENCH_DIR:-/home/runner/frappe-bench}"
SUITE="${1:-all}"

wait_for_scim() {
	for attempt in $(seq 1 60); do
		if curl -sf \
			-H "Authorization: Bearer ${SCIM_BEARER_TOKEN}" \
			"${SCIM_BASE_URL}/ServiceProviderConfig" >/dev/null; then
			echo "SCIM endpoint ready at ${SCIM_BASE_URL}"
			return 0
		fi
		sleep 2
	done
	echo "SCIM endpoint did not become ready at ${SCIM_BASE_URL}"
	return 1
}

start_bench_if_needed() {
	if curl -sf "${SCIM_BASE_URL}/ServiceProviderConfig" >/dev/null 2>&1; then
		return 0
	fi
	if [[ ! -d "${BENCH_DIR}" ]]; then
		echo "BENCH_DIR ${BENCH_DIR} not found; cannot start bench serve"
		return 1
	fi
	cd "${BENCH_DIR}"
	nohup bench serve --port 8000 >/tmp/bench-serve.log 2>&1 &
	wait_for_scim
}

run_okta() {
	python3 "$(dirname "$0")/run_okta_scim_spec.py" \
		--base-url "${SCIM_BASE_URL}" \
		--token "${SCIM_BEARER_TOKEN}"
}

run_entra() {
	scim-sanity probe "${SCIM_BASE_URL}" \
		--token "${SCIM_BEARER_TOKEN}" \
		--resource User \
		--profile entra \
		--user-domain ambrosiapieco.example \
		--compat \
		--i-accept-side-effects
}

prepare_scim_site() {
	if [[ -d "${BENCH_DIR}" ]]; then
		cd "${BENCH_DIR}"
		bench --site test_site execute saml.tests.setup.ensure_scim_test_settings
	fi
}

case "${SUITE}" in
	okta)
		prepare_scim_site
		start_bench_if_needed
		run_okta
		;;
	entra)
		prepare_scim_site
		start_bench_if_needed
		run_entra
		;;
	all)
		prepare_scim_site
		start_bench_if_needed
		run_okta &
		okta_pid=$!
		run_entra &
		entra_pid=$!
		okta_status=0
		entra_status=0
		wait "${okta_pid}" || okta_status=$?
		wait "${entra_pid}" || entra_status=$?
		exit $((okta_status + entra_status))
		;;
	*)
		echo "Usage: $0 [okta|entra|all]"
		exit 2
		;;
esac
