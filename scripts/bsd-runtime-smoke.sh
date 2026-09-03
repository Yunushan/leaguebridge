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

if [ -L "$evidence_dir" ] || { [ -e "$evidence_dir" ] && [ ! -d "$evidence_dir" ]; }; then
  echo "bsd-runtime-smoke: evidence path is not a real directory" >&2
  exit 1
fi
mkdir -p "$evidence_dir"
if [ -L "$evidence_dir" ] || [ ! -d "$evidence_dir" ]; then
  echo "bsd-runtime-smoke: evidence path changed into a non-directory after creation" >&2
  exit 1
fi
for output in \
  kernel.txt \
  version.json \
  status.json \
  readiness.json \
  manifest-verify.json \
  doctor.json \
  result.txt; do
  if [ -e "$evidence_dir/$output" ] || [ -L "$evidence_dir/$output" ]; then
    echo "bsd-runtime-smoke: refusing to overwrite existing evidence output: $evidence_dir/$output" >&2
    exit 1
  fi
done

actual_uname=$(uname -s)
if [ "$actual_uname" != "$expected_uname" ]; then
  echo "bsd-runtime-smoke: uname is $actual_uname; expected $expected_uname" >&2
  exit 1
fi

runtime_machine=$(uname -m)
case "$runtime_machine" in
  x86_64|amd64) actual_goarch=amd64 ;;
  aarch64|arm64) actual_goarch=arm64 ;;
  *)
    runtime_machine_arch=
    if command -v sysctl >/dev/null 2>&1; then
      runtime_machine_arch=$(sysctl -n hw.machine_arch 2>/dev/null || :)
    fi
    if [ -z "$runtime_machine_arch" ] || [ "$runtime_machine_arch" = "$runtime_machine" ]; then
      runtime_machine_arch=$(uname -p 2>/dev/null || :)
    fi
    case "$runtime_machine_arch" in
      x86_64|amd64) actual_goarch=amd64 ;;
      aarch64|arm64) actual_goarch=arm64 ;;
      *)
        echo "bsd-runtime-smoke: machine architecture is not amd64 or arm64: uname -m=$runtime_machine uname -p=$runtime_machine_arch" >&2
        exit 1
        ;;
    esac
    ;;
esac
if [ "$actual_goarch" != "$expected_goarch" ]; then
  echo "bsd-runtime-smoke: machine architecture is $actual_goarch; expected $expected_goarch" >&2
  exit 1
fi

{
  printf 'sysname=%s\n' "$actual_uname"
  printf 'release=%s\n' "$(uname -r)"
  printf 'machine=%s\n' "$runtime_machine"
  printf 'machine_arch=%s\n' "$actual_goarch"
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

# A headless BSD runner can return the blocked exit code, while a real desktop
# can return success with only optional diagnostic warnings. Accept both states
# and record which one occurred; neither state is gameplay evidence.
case "$doctor_exit" in
  0) client_preflight=pass ;;
  3) client_preflight=blocked ;;
  *)
    echo "bsd-runtime-smoke: client doctor exited $doctor_exit; expected 0 or 3" >&2
    exit 1
    ;;
esac

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
require_fixed "$evidence_dir/readiness.json" '"repository_evidence_verified": true' "verified repository evidence"
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
  printf 'client_preflight=%s\n' "$client_preflight"
  printf 'client.platform=pass\n'
  printf 'gameplay=not-tested\n'
} > "$evidence_dir/result.txt"

if [ "$client_preflight" = pass ]; then
  echo "BSD runtime smoke passed for $expected_uname/$expected_goos $expected_goarch (client preflight passed; gameplay not tested)"
else
  echo "BSD runtime smoke passed for $expected_uname/$expected_goos $expected_goarch (client preflight remains blocked as expected)"
fi
