#!/bin/sh
set -eu
set -f

export LC_ALL=C
umask 077

usage() {
  echo "usage: bsd-runtime-smoke.sh BINARY GOOS GOARCH UNAME EVIDENCE_DIR" >&2
  exit 2
}

if [ "$#" -ne 5 ]; then
  usage
fi

binary=$1
expected_goos=$2
expected_goarch=$3
expected_uname=$4
evidence_dir=$5

case "$expected_goos:$expected_goarch:$expected_uname" in
  freebsd:amd64:FreeBSD | freebsd:arm64:FreeBSD \
    | openbsd:amd64:OpenBSD | openbsd:arm64:OpenBSD \
    | netbsd:amd64:NetBSD | netbsd:arm64:NetBSD \
    | dragonfly:amd64:DragonFly)
    ;;
  *)
    echo "bsd-runtime-smoke: unsupported GOOS/GOARCH/uname combination" >&2
    exit 2
    ;;
esac

if [ -L "$binary" ] || [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
  echo "bsd-runtime-smoke: target binary is not a regular executable file" >&2
  exit 2
fi

mkdir -p "$evidence_dir"

actual_uname=$(uname -s)
if [ "$actual_uname" != "$expected_uname" ]; then
  echo "bsd-runtime-smoke: uname is $actual_uname; expected $expected_uname" >&2
  exit 1
fi

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

if [ "$doctor_exit" -ne 3 ]; then
  echo "bsd-runtime-smoke: client doctor exited $doctor_exit; expected 3" >&2
  exit 1
fi

require_fixed() {
  file=$1
  value=$2
  description=$3
  if ! grep -F "$value" "$file" >/dev/null; then
    echo "bsd-runtime-smoke: $description was not found in $file" >&2
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
require_fixed "$evidence_dir/doctor.json" "\"architecture\": \"$expected_goarch\"" "runtime architecture $expected_goarch"

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
  echo "bsd-runtime-smoke: client.platform did not PASS" >&2
  exit 1
fi

{
  printf 'goos=%s\n' "$expected_goos"
  printf 'goarch=%s\n' "$expected_goarch"
  printf 'doctor_exit=%s\n' "$doctor_exit"
  printf 'client.platform=pass\n'
  printf 'gameplay=not-tested\n'
} > "$evidence_dir/result.txt"

echo "BSD runtime smoke passed for $expected_uname/$expected_goos $expected_goarch"
