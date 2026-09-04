#!/bin/sh
set -eu
set -f

export LC_ALL=C
umask 077

fail() {
	printf '%s\n' "verify-install.sh: $*" >&2
	exit 1
}

if [ "$#" -ne 4 ]; then
	fail "usage: scripts/verify-install.sh ARCHIVE EXPECTED_VERSION EXPECTED_GOOS EXPECTED_GOARCH"
fi

archive=$1
expected_version=$2
expected_goos=$3
expected_goarch=$4
if [ -L "$archive" ] || [ ! -f "$archive" ]; then
	fail "archive must be a regular, non-symlink file"
fi
case "$expected_goos/$expected_goarch" in
	linux/amd64|linux/arm64|freebsd/amd64|freebsd/arm64|openbsd/amd64|openbsd/arm64|netbsd/amd64|netbsd/arm64|dragonfly/amd64) ;;
	*) fail "expected target is not an installable production artifact" ;;
esac
case "$(basename "$archive")" in
	leaguebridge_*_"$expected_goos"_"$expected_goarch".tar.gz) ;;
	*) fail "archive filename does not match the expected GOOS/GOARCH target" ;;
esac
# Release tooling performs the complete Semantic Version validation before it
# creates an archive. Keep this portable installer smoke check limited to the
# required prefix so valid prerelease and build-metadata forms are not rejected
# by a second, incomplete shell grammar.
case "$expected_version" in
	v*) ;;
	*) fail "expected version must be v-prefixed" ;;
esac

case "$(uname -s)" in
	Linux) runtime_goos=linux ;;
	FreeBSD) runtime_goos=freebsd ;;
	OpenBSD) runtime_goos=openbsd ;;
	NetBSD) runtime_goos=netbsd ;;
	DragonFly) runtime_goos=dragonfly ;;
	*) fail "install smoke requires a supported Linux or BSD kernel" ;;
esac
[ "$runtime_goos" = "$expected_goos" ] || fail "runtime kernel does not match the expected archive GOOS"
runtime_machine=$(uname -m)
case "$runtime_machine" in
	x86_64|amd64) runtime_goarch=amd64 ;;
	aarch64|arm64) runtime_goarch=arm64 ;;
	*)
		runtime_machine_arch=
		if command -v sysctl >/dev/null 2>&1; then
			runtime_machine_arch=$(sysctl -n hw.machine_arch 2>/dev/null || :)
		fi
		if [ -z "$runtime_machine_arch" ] || [ "$runtime_machine_arch" = "$runtime_machine" ]; then
			runtime_machine_arch=$(uname -p 2>/dev/null || :)
		fi
		case "$runtime_machine_arch" in
			x86_64|amd64) runtime_goarch=amd64 ;;
			aarch64|arm64) runtime_goarch=arm64 ;;
			*) fail "install smoke is running on an unsupported machine architecture: uname -m=$runtime_machine uname -p=$runtime_machine_arch" ;;
		esac
		;;
esac
[ "$runtime_goarch" = "$expected_goarch" ] || fail "runtime machine architecture does not match the expected archive GOARCH"

archive_directory=$(CDPATH= cd -P "$(dirname "$archive")" 2>/dev/null && pwd -P) || fail "cannot resolve the archive directory"
archive_path=$archive_directory/$(basename "$archive")

temporary_base=${TMPDIR:-/tmp}
case "$temporary_base" in
	/*) ;;
	*) fail "TMPDIR must be absolute" ;;
esac
case "$temporary_base" in
	/|*/|*//*|*/./*|*/../*|*/.|*/..|*[!A-Za-z0-9_./+-]*)
		fail "TMPDIR must be a normalized, non-root path using conservative characters"
		;;
esac

scratch=
scratch_attempt=0
while [ "$scratch_attempt" -lt 100 ]; do
	scratch=$temporary_base/leaguebridge-install-smoke.$$.${scratch_attempt}
	if mkdir "$scratch" 2>/dev/null; then
		break
	fi
	scratch=
	scratch_attempt=$((scratch_attempt + 1))
done
[ -n "$scratch" ] || fail "cannot create a private scratch directory"

payload=$scratch/payload
stage_root=$scratch/root
sentinel=$scratch/user-data
redirect_root=$scratch/redirect-root

cleanup() {
	# Every cleanup target is fixed beneath the scratch directory. Deliberately
	# avoid recursive deletion so an unexpected object is left for inspection.
	rm -f "$stage_root/usr/local/bin/leaguebridge" 2>/dev/null || :
	rm -f "$stage_root/usr/local/libexec/leaguebridge/linux-bsd-client-smoke.sh" 2>/dev/null || :
	rm -f "$stage_root/usr/local/libexec/leaguebridge/linux-bsd-remote-session.sh" 2>/dev/null || :
	rm -f "$stage_root/usr/local/libexec/leaguebridge/uninstall.sh" 2>/dev/null || :
	rm -f "$stage_root/usr/local/share/doc/leaguebridge/README.md" 2>/dev/null || :
	rm -f "$stage_root/usr/local/share/doc/leaguebridge/LICENSE" 2>/dev/null || :
	rm -f "$stage_root/usr/local/share/doc/leaguebridge/SBOM.spdx.json" 2>/dev/null || :
	rm -f "$stage_root/usr/local/share/doc/leaguebridge/PACKAGE-MANIFEST.json" 2>/dev/null || :
	rm -f "$payload/LICENSE" "$payload/PACKAGE-MANIFEST.json" "$payload/README.md" "$payload/SBOM.spdx.json" 2>/dev/null || :
	rm -f "$payload/install.sh" "$payload/linux-bsd-client-smoke.sh" "$payload/linux-bsd-remote-session.sh" "$payload/uninstall.sh" "$payload/leaguebridge" 2>/dev/null || :
	rm -f "$sentinel" 2>/dev/null || :
	rm -f "$redirect_root" 2>/dev/null || :
	rm -f "$stage_root/usr/local/bin/user-owned" 2>/dev/null || :
	rm -f "$stage_root/usr/local/share/doc/user-owned" 2>/dev/null || :
	rmdir "$stage_root/usr/local/share/doc/leaguebridge" 2>/dev/null || :
	rmdir "$stage_root/usr/local/libexec/leaguebridge" 2>/dev/null || :
	rmdir "$stage_root/usr/local/share/doc" 2>/dev/null || :
	rmdir "$stage_root/usr/local/share" 2>/dev/null || :
	rmdir "$stage_root/usr/local/libexec" 2>/dev/null || :
	rmdir "$stage_root/usr/local/bin" 2>/dev/null || :
	rmdir "$stage_root/usr/local" 2>/dev/null || :
	rmdir "$stage_root/usr" 2>/dev/null || :
	rmdir "$stage_root" 2>/dev/null || :
	rmdir "$payload" 2>/dev/null || :
	rmdir "$scratch" 2>/dev/null || :
}

trap cleanup 0
trap 'exit 1' 1 2 3 15

mkdir "$payload" "$stage_root"

extract_archive_members() {
	if [ "$runtime_goos" != linux ] && command -v pax >/dev/null 2>&1; then
		# pax is part of the BSD base systems and handles the gzip-compressed
		# tar archive without relying on GNU tar extensions.
		(cd "$payload" && pax -r -z -f "$archive_path" "$@")
	else
		tar -xzf "$archive" -C "$payload" "$@"
	fi
}

extract_archive_members \
	LICENSE PACKAGE-MANIFEST.json README.md SBOM.spdx.json install.sh linux-bsd-client-smoke.sh linux-bsd-remote-session.sh uninstall.sh leaguebridge || fail "cannot extract canonical archive members"

for payload_member in LICENSE PACKAGE-MANIFEST.json README.md SBOM.spdx.json install.sh linux-bsd-client-smoke.sh linux-bsd-remote-session.sh uninstall.sh leaguebridge; do
	payload_path=$payload/$payload_member
	if [ -L "$payload_path" ] || [ ! -f "$payload_path" ]; then
		fail "extracted member is not a regular, non-symlink file: $payload_member"
	fi
done

# Validation must fail before touching the destination for unsafe roots.
for invalid_prefix in '' relative / /usr/local/ /usr//local /usr/./local /usr/../local '/usr/local path'; do
	if PREFIX=$invalid_prefix DESTDIR="$stage_root" "$payload/install.sh" >/dev/null 2>&1; then
		fail "installer accepted unsafe PREFIX: $invalid_prefix"
	fi
done
for invalid_destdir in relative / /tmp/ /tmp//root /tmp/./root /tmp/../root '/tmp/package root'; do
	if PREFIX=/usr/local DESTDIR=$invalid_destdir "$payload/install.sh" >/dev/null 2>&1; then
		fail "installer accepted unsafe DESTDIR: $invalid_destdir"
	fi
done
if PREFIX=/usr/local DESTDIR="$stage_root" "$payload/install.sh" unexpected-argument >/dev/null 2>&1; then
	fail "installer accepted a positional argument"
fi
[ ! -e "$stage_root/usr" ] || fail "path validation touched the destination"

# Refuse a redirected destination component before creating anything below it.
ln -s "$stage_root" "$redirect_root"
if PREFIX=/usr/local DESTDIR="$redirect_root" "$payload/install.sh" >/dev/null 2>&1; then
	fail "installer followed a destination directory symlink"
fi
[ ! -e "$stage_root/usr" ] || fail "installer wrote through a destination directory symlink"
rm -f "$redirect_root"

PREFIX=/usr/local DESTDIR="$stage_root" "$payload/install.sh" >/dev/null

installed_binary=$stage_root/usr/local/bin/leaguebridge
installed_client_smoke=$stage_root/usr/local/libexec/leaguebridge/linux-bsd-client-smoke.sh
installed_remote_session=$stage_root/usr/local/libexec/leaguebridge/linux-bsd-remote-session.sh
installed_uninstaller=$stage_root/usr/local/libexec/leaguebridge/uninstall.sh
installed_readme=$stage_root/usr/local/share/doc/leaguebridge/README.md
installed_license=$stage_root/usr/local/share/doc/leaguebridge/LICENSE
installed_sbom=$stage_root/usr/local/share/doc/leaguebridge/SBOM.spdx.json
installed_package_manifest=$stage_root/usr/local/share/doc/leaguebridge/PACKAGE-MANIFEST.json

# Damage regular files, then reinstall to prove deterministic upgrade/repair.
printf '%s\n' stale-binary > "$installed_binary"
printf '%s\n' stale-document > "$installed_readme"
chmod 0600 "$installed_binary" "$installed_readme"
PREFIX=/usr/local DESTDIR="$stage_root" "$payload/install.sh" >/dev/null

cmp "$payload/leaguebridge" "$installed_binary" >/dev/null || fail "upgrade did not restore the binary"
cmp "$payload/README.md" "$installed_readme" >/dev/null || fail "upgrade did not restore README.md"
cmp "$payload/LICENSE" "$installed_license" >/dev/null || fail "installed LICENSE differs from the archive"
cmp "$payload/SBOM.spdx.json" "$installed_sbom" >/dev/null || fail "installed SBOM differs from the archive"
cmp "$payload/PACKAGE-MANIFEST.json" "$installed_package_manifest" >/dev/null || fail "installed package manifest differs from the archive"
cmp "$payload/linux-bsd-client-smoke.sh" "$installed_client_smoke" >/dev/null || fail "installed client smoke helper differs from the archive"
cmp "$payload/linux-bsd-remote-session.sh" "$installed_remote_session" >/dev/null || fail "installed remote session helper differs from the archive"
cmp "$payload/uninstall.sh" "$installed_uninstaller" >/dev/null || fail "installed uninstaller differs from the archive"

file_mode() {
	mode_path=$1
	if mode_value=$(stat -c '%a' "$mode_path" 2>/dev/null); then
		printf '%s\n' "$mode_value"
		return 0
	fi
	if mode_value=$(stat -f '%Lp' "$mode_path" 2>/dev/null); then
		printf '%s\n' "$mode_value"
		return 0
	fi
	return 1
}

[ "$(file_mode "$installed_binary")" = 755 ] || fail "installed binary mode is not 0755"
[ "$(file_mode "$installed_client_smoke")" = 755 ] || fail "installed client smoke helper mode is not 0755"
[ "$(file_mode "$installed_remote_session")" = 755 ] || fail "installed remote session helper mode is not 0755"
[ "$(file_mode "$installed_uninstaller")" = 755 ] || fail "installed uninstaller mode is not 0755"
[ "$(file_mode "$installed_readme")" = 644 ] || fail "installed README.md mode is not 0644"
[ "$(file_mode "$installed_license")" = 644 ] || fail "installed LICENSE mode is not 0644"
[ "$(file_mode "$installed_sbom")" = 644 ] || fail "installed SBOM mode is not 0644"
[ "$(file_mode "$installed_package_manifest")" = 644 ] || fail "installed package manifest mode is not 0644"

"$installed_binary" status >/dev/null
"$installed_binary" manifest verify >/dev/null
version_output=$("$installed_binary" version)
version_line=$(printf '%s\n' "$version_output" | sed -n '1p')
[ "$version_line" = "LeagueBridge $expected_version" ] || fail "installed binary reports an unexpected version"

# Unknown positional arguments must fail before the uninstaller removes any
# owned path. PREFIX and DESTDIR are environment-only interfaces.
if PREFIX=/usr/local DESTDIR="$stage_root" "$installed_uninstaller" unexpected-argument >/dev/null 2>&1; then
	fail "uninstaller accepted a positional argument"
fi
if (unset PREFIX; DESTDIR="$stage_root" "$installed_uninstaller" >/dev/null 2>&1); then
	fail "uninstaller accepted an omitted PREFIX"
fi
if (unset DESTDIR; PREFIX=/usr/local "$installed_uninstaller" >/dev/null 2>&1); then
	fail "uninstaller accepted an omitted DESTDIR"
fi
for retained_path in \
	"$installed_binary" \
	"$installed_remote_session" \
	"$installed_uninstaller" \
	"$installed_readme" \
	"$installed_license" \
	"$installed_sbom" \
	"$installed_package_manifest"; do
	if [ ! -f "$retained_path" ] || [ -L "$retained_path" ]; then
		fail "uninstaller changed an installed path after rejecting an argument: $retained_path"
	fi
done

# An explicitly present empty DESTDIR remains valid. Use a non-existent prefix
# beneath the private scratch directory so this check cannot affect host paths.
empty_destdir_prefix=$scratch/empty-destdir-prefix
DESTDIR= PREFIX="$empty_destdir_prefix" "$installed_uninstaller" >/dev/null
[ ! -e "$empty_destdir_prefix" ] || fail "empty DESTDIR validation created a destination path"

# A final destination symlink must be rejected without changing its target.
mv "$installed_binary" "$sentinel"
ln -s "$sentinel" "$installed_binary"
if PREFIX=/usr/local DESTDIR="$stage_root" "$payload/install.sh" >/dev/null 2>&1; then
	fail "installer replaced a destination symlink"
fi
[ -L "$installed_binary" ] || fail "installer changed the destination symlink"
cmp "$payload/leaguebridge" "$sentinel" >/dev/null || fail "installer changed the symlink target"
rm -f "$installed_binary"
mv "$sentinel" "$installed_binary"

# Uninstalling a replaced final file removes only that link, never its target.
printf '%s\n' user-data > "$sentinel"
rm -f "$installed_readme"
ln -s "$sentinel" "$installed_readme"
printf '%s\n' user-owned > "$stage_root/usr/local/bin/user-owned"
printf '%s\n' user-owned > "$stage_root/usr/local/share/doc/user-owned"
PREFIX=/usr/local DESTDIR="$stage_root" "$installed_uninstaller" >/dev/null
[ -f "$sentinel" ] && [ ! -L "$sentinel" ] || fail "uninstaller followed a replaced final symlink"
[ "$(sed -n '1p' "$sentinel")" = user-data ] || fail "uninstaller changed external user data"
[ "$(sed -n '1p' "$stage_root/usr/local/bin/user-owned")" = user-owned ] || fail "uninstaller changed an unrelated binary"
[ "$(sed -n '1p' "$stage_root/usr/local/share/doc/user-owned")" = user-owned ] || fail "uninstaller changed unrelated documentation"

for removed_path in \
	"$installed_binary" \
	"$installed_remote_session" \
	"$installed_uninstaller" \
	"$installed_readme" \
	"$installed_license" \
	"$installed_sbom" \
	"$installed_package_manifest"; do
	if [ -e "$removed_path" ] || [ -L "$removed_path" ]; then
		fail "installed path remains after uninstall: $removed_path"
	fi
done
[ ! -d "$stage_root/usr/local/share/doc/leaguebridge" ] || fail "documentation directory remains after uninstall"
[ ! -d "$stage_root/usr/local/libexec/leaguebridge" ] || fail "helper directory remains after uninstall"

printf '%s\n' "install, upgrade, command, target, explicit-root, symlink safety, and uninstall smoke passed for $archive"
