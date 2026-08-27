#!/bin/sh
set -eu
set -f

export LC_ALL=C
umask 077

usage() {
  echo "usage: linux-runtime-smoke.sh BINARY EVIDENCE_DIR" >&2
  exit 2
}

if [ "$#" -ne 2 ]; then
  usage
fi

binary=$1
evidence_dir=$2

if [ -L "$binary" ] || [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
  echo "linux-runtime-smoke: target binary is not a regular executable file" >&2
  exit 2
fi

mkdir -p "$evidence_dir"

actual_uname=$(uname -s)
if [ "$actual_uname" != Linux ]; then
  echo "linux-runtime-smoke: uname is $actual_uname; expected Linux" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) actual_arch=amd64 ;;
  *)
    echo "linux-runtime-smoke: machine architecture is not amd64" >&2
    exit 1
    ;;
esac

{
  printf 'sysname=%s\n' "$actual_uname"
  printf 'release=%s\n' "$(uname -r)"
  printf 'machine=%s\n' "$(uname -m)"
} > "$evidence_dir/kernel.txt"

"$binary" version --json > "$evidence_dir/version.json"
"$binary" status --json > "$evidence_dir/status.json"
"$binary" readiness --json > "$evidence_dir/readiness.json"
"$binary" manifest verify --json > "$evidence_dir/manifest-verify.json"

doctor_exit=0
if "$binary" doctor --profile client --json > "$evidence_dir/doctor.json"; then
  doctor_exit=0
else
  doctor_exit=$?
fi

# Hosted Linux runners are intentionally headless and do not prove a usable
# Moonlight desktop. A blocked client doctor result is the expected, honest
# outcome until a real Linux/BSD client session is tested separately.
if [ "$doctor_exit" -ne 3 ]; then
  echo "linux-runtime-smoke: client doctor exited $doctor_exit; expected 3" >&2
  exit 1
fi

require_fixed() {
  file=$1
  value=$2
  description=$3
  if ! grep -F "$value" "$file" >/dev/null; then
    echo "linux-runtime-smoke: $description was not found in $file" >&2
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
require_fixed "$evidence_dir/doctor.json" '"os": "linux"' "runtime GOOS linux"
require_fixed "$evidence_dir/doctor.json" '"architecture": "amd64"' "runtime architecture amd64"

if ! awk '
  /"id": "client.platform"/ {
    in_platform = 1
    seen = 1
    next
  }
  in_platform && /"status": "pass"/ {
    passed = 1
  }
  in_platform && /^[[:space:]]*}[,]?[[:space:]]*$/ {
    in_platform = 0
  }
  END {
    if (!(seen && passed)) {
      exit 1
    }
  }
' "$evidence_dir/doctor.json"; then
  echo "linux-runtime-smoke: client.platform did not PASS" >&2
  exit 1
fi

{
  printf 'goos=linux\n'
  printf 'goarch=%s\n' "$actual_arch"
  printf 'doctor_exit=%s\n' "$doctor_exit"
  printf 'client.platform=pass\n'
  printf 'gameplay=not-tested\n'
} > "$evidence_dir/result.txt"

echo "Linux runtime smoke passed for Linux/$actual_arch (client preflight remains blocked as expected)"
