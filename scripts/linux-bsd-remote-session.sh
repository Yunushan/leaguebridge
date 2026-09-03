#!/bin/sh
set -eu
set -f

export LC_ALL=C
umask 077

usage() {
	printf '%s\n' 'usage: linux-bsd-remote-session.sh BINARY CONFIG --start [WAKE_MAC [WAKE_WAIT [WAKE_BROADCAST [WAKE_PORT [WAKE_RETRIES [WAKE_RETRY_DELAY]]]]]]' >&2
	exit 2
}

if [ "$#" -lt 3 ] || [ "$#" -gt 9 ]; then
	usage
fi

binary=$1
config=$2
start_flag=$3
if [ "$start_flag" != "--start" ]; then
	usage
fi
shift 3

wake_requested=0
wake_mac=
wake_wait=15
wake_broadcast=255.255.255.255
wake_port=9
wake_retries=3
wake_retry_delay=5

if [ "$#" -gt 0 ]; then
	wake_requested=1
	wake_mac=$1
	[ -n "$wake_mac" ] || usage
	shift
fi
if [ "$#" -gt 0 ]; then
	wake_wait=$1
	[ -n "$wake_wait" ] || usage
	shift
fi
if [ "$#" -gt 0 ]; then
	wake_broadcast=$1
	[ -n "$wake_broadcast" ] || usage
	shift
fi
if [ "$#" -gt 0 ]; then
	wake_port=$1
	[ -n "$wake_port" ] || usage
	shift
fi
if [ "$#" -gt 0 ]; then
	wake_retries=$1
	[ -n "$wake_retries" ] || usage
	shift
fi
if [ "$#" -gt 0 ]; then
	wake_retry_delay=$1
	[ -n "$wake_retry_delay" ] || usage
	shift
fi
[ "$#" -eq 0 ] || usage

fail() {
	printf '%s\n' "linux-bsd-remote-session: $*" >&2
	exit 1
}

if [ -L "$binary" ] || [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
	fail "target binary is not a regular executable file"
fi
if [ -L "$config" ] || [ ! -f "$config" ]; then
	fail "configuration must be a regular, non-symlink file"
fi

case "$(uname -s)" in
	Linux|FreeBSD|OpenBSD|NetBSD|DragonFly) ;;
	*) fail "unsupported kernel; run this only on Linux or a supported BSD" ;;
esac

if ! "$binary" config validate --file "$config" >/dev/null; then
	fail "configuration validation failed; no host operation was started"
fi
if ! "$binary" remote play \
	--config "$config" \
	--dry-run --json --acknowledge-unverified-handoff >/dev/null; then
	fail "stream plan/client preflight failed; no host operation was started"
fi

printf '%s\n' "Checking that the configured physical host advertises League of Legends..."
list_exit=0
if [ "$wake_requested" -eq 1 ]; then
	if "$binary" remote list \
		--config "$config" \
		--require-configured-app --require-app "League of Legends" \
		--acknowledge-unverified-handoff \
		--wake-mac "$wake_mac" --wake-wait "$wake_wait" \
		--wake-broadcast "$wake_broadcast" --wake-port "$wake_port" \
		--wake-retries "$wake_retries" --wake-retry-delay "$wake_retry_delay"; then
		list_exit=0
	else
		list_exit=$?
	fi
else
	if "$binary" remote list \
		--config "$config" \
		--require-configured-app --require-app "League of Legends"; then
		list_exit=0
	else
		list_exit=$?
	fi
fi
if [ "$list_exit" -ne 0 ]; then
	fail "physical-host application preflight failed; no stream was started"
fi

printf '%s\n' "Physical-host preflight passed. Starting the live League session."
printf '%s\n' "League and Vanguard remain on the physical host; stop if Riot or Vanguard reports an error."
printf '%s\n' "The session's exit status is not gameplay evidence; verify Practice Tool input and ordinary play manually."

stream_exit=0
if "$binary" remote play \
	--config "$config" \
	--require-configured-app --require-app "League of Legends" \
	--acknowledge-unverified-handoff; then
	stream_exit=0
else
	stream_exit=$?
fi

if [ "$stream_exit" -eq 0 ]; then
	printf '%s\n' "Moonlight ended normally; League/Vanguard gameplay remains unverified." >&2
else
	printf '%s\n' "Moonlight ended with status $stream_exit; inspect the live client output." >&2
fi
exit "$stream_exit"
