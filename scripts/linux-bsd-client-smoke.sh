#!/bin/sh
set -eu
set -f

export LC_ALL=C
umask 077

usage() {
	printf '%s\n' 'usage: linux-bsd-client-smoke.sh BINARY EVIDENCE_DIR' >&2
	exit 2
}

if [ "$#" -ne 2 ]; then
	usage
fi

binary=$1
evidence_dir=$2

if [ -L "$binary" ] || [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
	printf '%s\n' "linux-bsd-client-smoke: target binary is not a regular executable file" >&2
	exit 2
fi
if [ -L "$evidence_dir" ] || { [ -e "$evidence_dir" ] && [ ! -d "$evidence_dir" ]; }; then
	printf '%s\n' "linux-bsd-client-smoke: evidence path is not a real directory" >&2
	exit 1
fi
mkdir -p "$evidence_dir"
if [ -L "$evidence_dir" ] || [ ! -d "$evidence_dir" ]; then
	printf '%s\n' "linux-bsd-client-smoke: evidence path changed into a non-directory after creation" >&2
	exit 1
fi
for output in \
	kernel.txt \
	version.json \
	status.json \
	readiness.json \
	manifest-verify.json \
	doctor.json \
	play-plan.json \
	result.txt; do
	if [ -e "$evidence_dir/$output" ] || [ -L "$evidence_dir/$output" ]; then
		printf '%s\n' "linux-bsd-client-smoke: refusing to overwrite existing evidence output: $evidence_dir/$output" >&2
		exit 1
	fi
done

case "$(uname -s)" in
	Linux) expected_goos=linux ;;
	FreeBSD) expected_goos=freebsd ;;
	OpenBSD) expected_goos=openbsd ;;
	NetBSD) expected_goos=netbsd ;;
	DragonFly) expected_goos=dragonfly ;;
	*)
		printf '%s\n' "linux-bsd-client-smoke: unsupported kernel; run this only on Linux or a supported BSD" >&2
		exit 1
		;;
esac
runtime_machine=$(uname -m)
case "$runtime_machine" in
	x86_64|amd64) expected_goarch=amd64 ;;
	aarch64|arm64) expected_goarch=arm64 ;;
	*)
		runtime_machine_arch=
		if command -v sysctl >/dev/null 2>&1; then
			runtime_machine_arch=$(sysctl -n hw.machine_arch 2>/dev/null || :)
		fi
		if [ -z "$runtime_machine_arch" ] || [ "$runtime_machine_arch" = "$runtime_machine" ]; then
			runtime_machine_arch=$(uname -p 2>/dev/null || :)
		fi
		case "$runtime_machine_arch" in
			x86_64|amd64) expected_goarch=amd64 ;;
			aarch64|arm64) expected_goarch=arm64 ;;
			*)
				printf '%s\n' "linux-bsd-client-smoke: unsupported machine architecture: uname -m=$runtime_machine uname -p=$runtime_machine_arch" >&2
				exit 1
				;;
		esac
		;;
esac

"$binary" version --json > "$evidence_dir/version.json"
"$binary" status --json > "$evidence_dir/status.json"
"$binary" readiness --json > "$evidence_dir/readiness.json"
"$binary" manifest verify --json > "$evidence_dir/manifest-verify.json"
{
	printf 'sysname=%s\n' "$(uname -s)"
	printf 'release=%s\n' "$(uname -r)"
	printf 'machine=%s\n' "$runtime_machine"
	printf 'machine_arch=%s\n' "$expected_goarch"
} > "$evidence_dir/kernel.txt"

doctor_exit=0
if "$binary" doctor --profile client --json > "$evidence_dir/doctor.json"; then
	doctor_exit=0
else
	doctor_exit=$?
fi
if [ "$doctor_exit" -ne 0 ]; then
	printf '%s\n' "linux-bsd-client-smoke: client preflight did not pass; inspect doctor.json" >&2
	exit 1
fi

require_fixed() {
	file=$1
	value=$2
	description=$3
	if ! grep -F -- "$value" "$file" >/dev/null; then
		printf '%s\n' "linux-bsd-client-smoke: $description was not found in $file" >&2
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
require_fixed "$evidence_dir/readiness.json" '"repository_evidence_verified": true' "verified repository evidence"
require_json_success "$evidence_dir/manifest-verify.json" "manifest verify"
require_json_success "$evidence_dir/doctor.json" doctor
require_fixed "$evidence_dir/doctor.json" "\"os\": \"$expected_goos\"" "runtime GOOS $expected_goos"
require_fixed "$evidence_dir/doctor.json" "\"architecture\": \"$expected_goarch\"" "runtime architecture $expected_goarch"

require_check_pass() {
	check_id=$1
	if ! awk -v wanted="$check_id" '
		index($0, "\"id\": \"" wanted "\"") > 0 { in_check = 1; seen = 1; next }
		in_check && /"status": "pass"/ { passed = 1 }
		in_check && /^[[:space:]]*}[,]?[[:space:]]*$/ { in_check = 0 }
		END { if (!(seen && passed)) exit 1 }
	' "$evidence_dir/doctor.json"; then
		printf '%s\n' "linux-bsd-client-smoke: $check_id did not PASS" >&2
		exit 1
	fi
}

for check_id in client.platform client.graphical-session client.input client.moonlight; do
	require_check_pass "$check_id"
done

# Use a reserved documentation-only host name. --dry-run never contacts it;
# this validates the same route-bound client selection and League defaults that
# the live command will use after pairing with a real physical host.
if "$binary" remote play \
	--host example.invalid \
	--confirm-physical-host \
	--acknowledge-unverified-handoff \
	--dry-run --json > "$evidence_dir/play-plan.json"; then
	play_exit=0
else
	play_exit=$?
fi
if [ "$play_exit" -ne 0 ]; then
	printf '%s\n' "linux-bsd-client-smoke: remote play dry run failed; inspect play-plan.json" >&2
	exit 1
fi
require_json_success "$evidence_dir/play-plan.json" "remote play"
require_fixed "$evidence_dir/play-plan.json" '"route": "physical-' "physical remote route"
require_fixed "$evidence_dir/play-plan.json" '"-1080"' "1080p stream option"
require_fixed "$evidence_dir/play-plan.json" '"-fps"' "FPS stream option"
require_fixed "$evidence_dir/play-plan.json" '"60"' "60 FPS value"
require_fixed "$evidence_dir/play-plan.json" '"-bitrate"' "bitrate stream option"
require_fixed "$evidence_dir/play-plan.json" '"20000"' "20 Mbps bitrate value"
require_fixed "$evidence_dir/play-plan.json" '"1392"' "1392-byte packet-size option"

{
	printf 'goos=%s\n' "$expected_goos"
	printf 'goarch=%s\n' "$expected_goarch"
	printf 'kernel_release=%s\n' "$(uname -r)"
	printf 'doctor_exit=%s\n' "$doctor_exit"
	printf 'client_preflight=pass\n'
	printf 'remote_play_dry_run_exit=%s\n' "$play_exit"
	printf 'network=not-used\n'
	printf 'gameplay=not-tested\n'
} > "$evidence_dir/result.txt"

printf '%s\n' "Linux/BSD client smoke passed for $expected_goos/$expected_goarch (host not contacted; gameplay not tested)"
