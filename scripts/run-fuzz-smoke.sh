#!/usr/bin/env bash

set -euo pipefail

fuzztime="${FUZZTIME:-5s}"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/wgf-fuzz.XXXXXX")"
trap 'rm -rf "$workdir"' EXIT

targets=(
	"FuzzParse ./internal/config"
	"FuzzParse ./internal/core/innerip"
	"FuzzParseRoundTrip ./internal/core/carrier"
	"FuzzParseEnvelope ./internal/core/carrier"
	"FuzzCodecParseRoundTrip ./internal/core/control"
	"FuzzReceiverAcceptCarrier ./internal/core/datapath"
	"FuzzAcceptAndExpire ./internal/core/reassembly"
	"FuzzHandleInbound ./internal/controlplane"
)

run_target() {
	local target="$1"
	local package="$2"
	local log="$3"

	set +e
	GOMAXPROCS=2 go test -run='^$' -parallel=1 \
		-fuzz="$target" -fuzztime="$fuzztime" "$package" 2>&1 | tee "$log"
	local status="${PIPESTATUS[0]}"
	set -e
	return "$status"
}

for entry in "${targets[@]}"; do
	read -r target package <<<"$entry"
	log="$workdir/${target}-$(basename "$package").log"
	if run_target "$target" "$package" "$log"; then
		continue
	fi

	# The Go fuzz coordinator can occasionally report its own deadline as a
	# test failure when a short fuzz run ends. Retry only that exact failure;
	# panics, saved crashers, assertions, and repeated deadlines still fail.
	if [[ "$(grep -Ec '^[[:space:]]+context deadline exceeded$' "$log")" -ne 1 ]] ||
		! grep -Eq "^--- FAIL: ${target} \\([0-9.]+s\\)$" "$log" ||
		grep -Eq 'panic:|Failing input written to|fuzzing process hung or terminated unexpectedly' "$log"; then
		exit 1
	fi

	echo "retrying ${target} after fuzz coordinator deadline"
	if ! run_target "$target" "$package" "$log.retry"; then
		exit 1
	fi
done
