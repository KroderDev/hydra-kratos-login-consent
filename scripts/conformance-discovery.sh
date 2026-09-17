#!/usr/bin/env bash

set -euo pipefail

die() {
	printf '%s\n' "$1" >&2
	exit 1
}

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v jq >/dev/null 2>&1 || die "jq is required"

suite="${CONFORMANCE_SERVER:-}"
token="${CONFORMANCE_TOKEN:-}"
discovery_url="${CONFORMANCE_DISCOVERY_URL:-}"

[ -n "$suite" ] || die "CONFORMANCE_SERVER is required"
[ -n "$token" ] || die "CONFORMANCE_TOKEN is required"
[ -n "$discovery_url" ] || die "CONFORMANCE_DISCOVERY_URL is required"

case "$suite" in
	https://*)
		;;
	*)
		die "CONFORMANCE_SERVER must use HTTPS"
		;;
esac

case "$suite" in
	*$'\r'*|*$'\n'*|*\?*|*\#*)
		die "CONFORMANCE_SERVER must be an HTTPS base URL"
		;;
esac

case "$discovery_url" in
	https://*/.well-known/openid-configuration)
		;;
	*)
		die "CONFORMANCE_DISCOVERY_URL must be an HTTPS OIDC discovery URL"
		;;
esac

case "${discovery_url#https://}" in
	""|/*|*$'\r'*|*$'\n'*)
		die "CONFORMANCE_DISCOVERY_URL must include an HTTPS host"
		;;
esac

case "$token" in
	*$'\r'*|*$'\n'*)
		die "CONFORMANCE_TOKEN contains invalid control characters"
		;;
esac

while [ "${suite%/}" != "$suite" ]; do
	suite="${suite%/}"
done
case "$suite" in
	https://|https:///*)
		die "CONFORMANCE_SERVER must include an HTTPS host"
		;;
esac
umask 077
workdir="$(mktemp -d)"
plan_id=""

urlencode() {
	jq -nr --arg value "$1" '$value | @uri'
}

cleanup() {
	status=$?
	trap - EXIT INT TERM
	if [ -n "$plan_id" ]; then
		encoded_plan_id="$(urlencode "$plan_id")"
		curl --fail --silent --show-error --request DELETE \
			--header "Authorization: Bearer $token" \
			"$suite/api/plan/$encoded_plan_id" >/dev/null 2>&1 || true
	fi
	rm -rf "$workdir"
	exit "$status"
}
trap cleanup EXIT INT TERM

jq -n --arg discovery_url "$discovery_url" \
	'{description: "OIDC discovery check", server: {discoveryUrl: $discovery_url}}' \
	>"$workdir/config.json"

curl --fail --silent --show-error --request POST \
	--header "Authorization: Bearer $token" \
	--header 'Content-Type: application/json' \
	--data-binary "@$workdir/config.json" \
	"$suite/api/plan?planName=oidcc-config-certification-test-plan" \
	--output "$workdir/plan.json" || die "unable to create OIDC discovery plan"

plan_id="$(jq -er '.id // empty' "$workdir/plan.json" 2>/dev/null)" || die "OIDC discovery plan did not return an ID"
encoded_plan_id="$(urlencode "$plan_id")"

curl --fail --silent --show-error --request POST \
	--header "Authorization: Bearer $token" \
	"$suite/api/runner?test=$(urlencode "oidcc-discovery-endpoint-verification")&plan=$encoded_plan_id" \
	--output "$workdir/module.json" || die "unable to start OIDC discovery verification"

module_id="$(jq -er '.id // empty' "$workdir/module.json" 2>/dev/null)" || die "OIDC discovery module did not return an ID"
encoded_module_id="$(urlencode "$module_id")"

while :; do
	curl --fail --silent --show-error \
		--header "Authorization: Bearer $token" \
		"$suite/api/runner/$encoded_module_id/wait-state?states=FINISHED%2CINTERRUPTED&timeoutMs=30000" \
		--output "$workdir/wait.json" || die "unable to poll OIDC discovery verification"

	if jq -e '.timeout == true' "$workdir/wait.json" >/dev/null 2>&1; then
		continue
	fi

	state="$(jq -er '.state // empty' "$workdir/wait.json" 2>/dev/null)" || die "OIDC discovery verification returned no state"
	case "$state" in
		FINISHED|INTERRUPTED)
			break
		;;
		*)
			die "OIDC discovery verification returned an unexpected state"
		;;
	esac
done

curl --fail --silent --show-error \
	--header "Authorization: Bearer $token" \
	"$suite/api/info/$encoded_module_id" \
	--output "$workdir/info.json" || die "unable to read OIDC discovery verification result"

status="$(jq -er '.status // empty' "$workdir/info.json" 2>/dev/null)" || die "OIDC discovery verification returned no status"
result="$(jq -er '.result // empty' "$workdir/info.json" 2>/dev/null)" || die "OIDC discovery verification returned no result"

if [ "$status" != "FINISHED" ] || [ "$result" != "PASSED" ]; then
	printf 'OIDC discovery verification failed (status=%s result=%s)\n' "$status" "$result" >&2
	exit 1
fi

printf '%s\n' "OIDC discovery verification passed"
