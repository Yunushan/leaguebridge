#!/bin/sh
set -eu
set -f

export LC_ALL=C
umask 077

usage() {
	printf '%s\n' "usage: linux-bsd-remote-smoke.sh BINARY EVIDENCE_DIR CONFIG [EXPECTED_APPLICATION]" >&2
	exit 2
}

if [ "$#" -ne 3 ] && [ "$#" -ne 4 ]; then
	usage
fi

binary=$1
evidence_dir=$2
config=$3
expected_application=${4-}

if [ "$#" -eq 4 ] && [ -z "$expected_application" ]; then
	printf '%s\n' "linux-bsd-remote-smoke: EXPECTED_APPLICATION must not be empty" >&2
	exit 2
fi

fail() {
	printf '%s\n' "linux-bsd-remote-smoke: $*" >&2
	exit 1
}

if [ -L "$binary" ] || [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
	printf '%s\n' "linux-bsd-remote-smoke: target binary is not a regular executable file" >&2
	exit 2
fi
if [ -L "$config" ] || [ ! -f "$config" ]; then
	printf '%s\n' "linux-bsd-remote-smoke: configuration must be a regular, non-symlink file" >&2
	exit 2
fi

case "$(uname -s)" in
	Linux) expected_goos=linux ;;
	FreeBSD) expected_goos=freebsd ;;
	OpenBSD) expected_goos=openbsd ;;
	NetBSD) expected_goos=netbsd ;;
	DragonFly) expected_goos=dragonfly ;;
	*)
		printf '%s\n' "linux-bsd-remote-smoke: unsupported kernel; run this only on Linux or a supported BSD" >&2
		exit 1
		;;
esac
case "$(uname -m)" in
	x86_64|amd64) expected_goarch=amd64 ;;
	*)
		printf '%s\n' "linux-bsd-remote-smoke: machine architecture is not amd64" >&2
		exit 1
		;;
esac

if [ -L "$evidence_dir" ] || { [ -e "$evidence_dir" ] && [ ! -d "$evidence_dir" ]; }; then
	fail "evidence path is not a real directory"
fi
mkdir -p "$evidence_dir"
if [ -L "$evidence_dir" ] || [ ! -d "$evidence_dir" ]; then
	fail "evidence path changed into a non-directory after creation"
fi
for output in \
	version.json \
	status.json \
	readiness.json \
	manifest-verify.json \
	kernel.txt \
	doctor.json \
	stream-plan.json \
	result.txt; do
	if [ -e "$evidence_dir/$output" ] || [ -L "$evidence_dir/$output" ]; then
		fail "refusing to overwrite existing evidence output: $evidence_dir/$output"
	fi
done

"$binary" version --json > "$evidence_dir/version.json"
"$binary" status --json > "$evidence_dir/status.json"
"$binary" readiness --json > "$evidence_dir/readiness.json"
"$binary" manifest verify --json > "$evidence_dir/manifest-verify.json"

{
	printf 'sysname=%s\n' "$(uname -s)"
	printf 'release=%s\n' "$(uname -r)"
	printf 'machine=%s\n' "$(uname -m)"
} > "$evidence_dir/kernel.txt"

doctor_exit=0
if "$binary" doctor --profile client --json > "$evidence_dir/doctor.json"; then
	doctor_exit=0
else
	doctor_exit=$?
fi
if [ "$doctor_exit" -ne 0 ]; then
	printf '%s\n' "linux-bsd-remote-smoke: client preflight did not pass; inspect doctor.json" >&2
	exit 1
fi

require_fixed() {
	file=$1
	value=$2
	description=$3
	if ! grep -F -- "$value" "$file" >/dev/null; then
		printf '%s\n' "linux-bsd-remote-smoke: $description was not found in $file" >&2
		exit 1
	fi
}

require_json_success() {
	file=$1
	command=$2
	require_fixed "$file" "\"command\": \"$command\"" "command $command"
	require_fixed "$file" '"ok": true' "successful JSON envelope"
}

require_json_success "$evidence_dir/version.json" version
require_json_success "$evidence_dir/status.json" status
require_json_success "$evidence_dir/readiness.json" readiness
require_json_success "$evidence_dir/manifest-verify.json" "manifest verify"
require_json_success "$evidence_dir/doctor.json" doctor
require_fixed "$evidence_dir/doctor.json" "\"os\": \"$expected_goos\"" "runtime GOOS $expected_goos"
require_fixed "$evidence_dir/doctor.json" '"architecture": "amd64"' "runtime architecture amd64"

for check_id in client.platform client.moonlight client.graphical-session client.input; do
	if ! awk -v wanted="$check_id" '
		index($0, "\"id\": \"" wanted "\"") > 0 { in_check = 1; seen = 1; next }
		in_check && /"status": "pass"/ { passed = 1 }
		in_check && /^[[:space:]]*}[,]?[[:space:]]*$/ { in_check = 0 }
		END { if (!(seen && passed)) exit 1 }
	' "$evidence_dir/doctor.json"; then
		printf '%s\n' "linux-bsd-remote-smoke: $check_id did not PASS" >&2
		exit 1
	fi
done

# Listing is the first route-bound operation that reaches the configured,
# already-paired physical host. Its output remains on the operator's terminal;
# only the exit status is retained so host/application names are not copied
# into the evidence directory by this helper. The configured stream
# application is always required; when EXPECTED_APPLICATION is supplied, the
# command also requires that exact entry and LeagueBridge rejects a mismatch
# with the configured application before reaching the host.
list_exit=0
if [ "$#" -eq 4 ]; then
	if "$binary" remote list --config "$config" --require-configured-app --require-app "$expected_application"; then
		list_exit=0
	else
		list_exit=$?
	fi
elif "$binary" remote list --config "$config" --require-configured-app; then
	list_exit=0
else
	list_exit=$?
fi
if [ "$list_exit" -ne 0 ]; then
	printf '%s\n' "linux-bsd-remote-smoke: remote list failed; verify pairing, host reachability, and the physical-host confirmation" >&2
	exit 1
fi

# A dry run validates the stream-specific Moonlight argv without starting an
# interactive stream. Actual League/Vanguard behavior still requires the
# operator to run remote stream and observe a real Practice Tool session.
stream_dry_run_exit=0
if "$binary" remote stream \
	--config "$config" \
	--resolution 1080 \
	--fps 60 \
	--bitrate 20000 \
	--packet-size 1392 \
	--codec h264 \
	--dry-run --json --acknowledge-unverified-handoff > "$evidence_dir/stream-plan.json"; then
	stream_dry_run_exit=0
else
	stream_dry_run_exit=$?
fi
if [ "$stream_dry_run_exit" -ne 0 ]; then
	printf '%s\n' "linux-bsd-remote-smoke: stream dry run failed; inspect stream-plan.json" >&2
	exit 1
fi
require_json_success "$evidence_dir/stream-plan.json" "remote stream"
require_fixed "$evidence_dir/stream-plan.json" '"route": "physical-' "physical remote route"
require_fixed "$evidence_dir/stream-plan.json" '"-1080"' "1080p stream option"
require_fixed "$evidence_dir/stream-plan.json" '"-fps"' "FPS stream option"
require_fixed "$evidence_dir/stream-plan.json" '"60"' "60 FPS value"
require_fixed "$evidence_dir/stream-plan.json" '"-bitrate"' "bitrate stream option"
require_fixed "$evidence_dir/stream-plan.json" '"20000"' "20 Mbps bitrate value"
require_fixed "$evidence_dir/stream-plan.json" '"1392"' "1392-byte packet-size option"

{
	printf 'goos=%s\n' "$expected_goos"
	printf 'goarch=%s\n' "$expected_goarch"
	printf 'kernel_release=%s\n' "$(uname -r)"
	printf 'doctor_exit=%s\n' "$doctor_exit"
	printf 'remote_list_exit=%s\n' "$list_exit"
	printf 'required_application_check=pass\n'
	printf 'stream_dry_run_exit=%s\n' "$stream_dry_run_exit"
	printf 'gameplay=not-tested\n'
} > "$evidence_dir/result.txt"

printf '%s\n' "Linux/BSD remote-client smoke passed for $expected_goos/$expected_goarch"
printf '%s\n' "Run remote stream separately and verify a real Practice Tool session; this smoke does not prove League or Vanguard behavior."
