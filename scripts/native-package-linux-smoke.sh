#!/usr/bin/env bash
set -euo pipefail
set -f

export LC_ALL=C
umask 022

usage() {
  echo "usage: native-package-linux-smoke.sh VERSION RELEASE_ARCHIVE" >&2
  exit 2
}

fail() {
  echo "native-package-linux-smoke: $*" >&2
  exit 1
}

if [[ "$#" -ne 2 ]]; then
  usage
fi

version=$1
archive=$2
# Keep the shell guard to the required prefix only. The repository's Go
# semantic-version checker below is authoritative; duplicating SemVer grammar
# in a shell glob can reject valid prerelease forms before that checker runs.
case "$version" in
  v*) ;;
  *) fail "VERSION must be a v-prefixed semantic version" ;;
esac
if [[ "$archive" == /* || "$archive" == *$'\n'* || "$archive" == *$'\r'* ]]; then
  fail "release archive must be a safe workspace-relative path"
fi
if [[ -L "$archive" || ! -f "$archive" ]]; then
  fail "release archive must be a regular, non-symlink file"
fi
for command_name in go dpkg-deb dpkg rpm rpmbuild sudo sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is unavailable: $command_name"
done
if ! go run -mod=vendor ./tools/versioncheck "$version" >/dev/null 2>&1; then
  fail "VERSION is not accepted by the repository semantic-version checker"
fi
sudo -n true >/dev/null 2>&1 || fail "passwordless sudo is required for private package-manager smoke tests"

ensure_directory() {
  local directory=$1
  if [[ -L "$directory" || ( -e "$directory" && ! -d "$directory" ) ]]; then
    fail "path is not a real directory: $directory"
  fi
  mkdir -p "$directory"
  if [[ -L "$directory" || ! -d "$directory" ]]; then
    fail "path changed into a non-directory after creation: $directory"
  fi
}

ensure_directory native-package-staging
ensure_directory native-package-output
ensure_directory native-package-evidence

go run -mod=vendor ./tools/nativepackagestage \
  -archive "$archive" -family debian \
  -output native-package-staging/debian
go run -mod=vendor ./tools/nativepackagecheck \
  -staging native-package-staging/debian
go run -mod=vendor ./tools/nativepackagestage \
  -archive "$archive" -family rpm \
  -output native-package-staging/rpm
go run -mod=vendor ./tools/nativepackagecheck \
  -staging native-package-staging/rpm

package_version=${version#v}
package_version=${package_version%%+*}
deb_version=$(printf '%s' "$package_version" | tr '-' '~')
rpm_version=${package_version%%-*}
rpm_release=1
if [[ "$package_version" == *-* ]]; then
  rpm_release="1.${package_version#*-}"
fi
rpm_release=${rpm_release//-/.}
rpm_release=${rpm_release//+/.}

ensure_directory native-package-output/debian
ensure_directory native-package-output/rpm
ensure_directory native-package-evidence/debian
ensure_directory native-package-evidence/rpm

debian_package="native-package-output/debian/leaguebridge_${deb_version}_amd64.deb"
rpm_package="native-package-output/rpm/leaguebridge-${rpm_version}-${rpm_release}.x86_64.rpm"
debian_evidence="native-package-evidence/debian/install.txt"
rpm_evidence="native-package-evidence/rpm/install.txt"
for output in "$debian_package" "$rpm_package"; do
  if [[ -e "$output" || -L "$output" ]]; then
    fail "package output already exists: $output"
  fi
done
for evidence in "$debian_evidence" "$rpm_evidence"; do
  if [[ -e "$evidence" || -L "$evidence" ]]; then
    fail "evidence output already exists: $evidence"
  fi
done

temporary_root=$(mktemp -d)
debian_root=$temporary_root/debian-root
rpm_top=$temporary_root/rpm-top
rpm_payload=$temporary_root/rpm-payload
debian_scratch=$temporary_root/debian-install
rpm_scratch=$temporary_root/rpm-install
cleanup() {
  set +e
  sudo dpkg --root="$debian_scratch" --admindir="$debian_scratch/var/lib/dpkg" \
    --instdir="$debian_scratch" --purge leaguebridge >/dev/null 2>&1
  sudo rpm --root "$rpm_scratch" --erase leaguebridge >/dev/null 2>&1
  if [[ -n "${temporary_root:-}" && -e "$temporary_root" && ! -L "$temporary_root" ]]; then
    rm -rf -- "$temporary_root"
  fi
}
trap cleanup EXIT

mkdir -p "$debian_root" "$rpm_top" "$rpm_payload"
cp -a native-package-staging/debian/root/. "$debian_root/"
mkdir -p "$debian_root/DEBIAN"
printf '%s\n' \
  'Package: leaguebridge' \
  "Version: $deb_version" \
  'Architecture: amd64' \
  'Maintainer: LeagueBridge contributors <maintainers@leaguebridge.invalid>' \
  'Section: net' \
  'Priority: optional' \
  'Description: LeagueBridge remote handoff controller' \
  ' A bounded, read-only compatibility and remote handoff controller.' \
  > "$debian_root/DEBIAN/control"
chmod 0644 "$debian_root/DEBIAN/control"
dpkg-deb --build --root-owner-group "$debian_root" "$debian_package" >/dev/null

cp -a native-package-staging/rpm/root/. "$rpm_payload/"
mkdir -p "$rpm_top/BUILD" "$rpm_top/BUILDROOT" "$rpm_top/RPMS" "$rpm_top/SOURCES" \
  "$rpm_top/SPECS" "$rpm_top/SRPMS"
rpm_spec=$rpm_top/SPECS/leaguebridge.spec
printf '%s\n' \
  'Name: leaguebridge' \
  "Version: $rpm_version" \
  "Release: $rpm_release" \
  'Summary: LeagueBridge remote handoff controller' \
  'License: 0BSD' \
  'BuildArch: x86_64' \
  'AutoReqProv: no' \
  '%description' \
  'A bounded, read-only compatibility and remote handoff controller.' \
  '%install' \
  'rm -rf %{buildroot}' \
  'mkdir -p %{buildroot}' \
  'cp -a %{_leaguebridge_payload}/. %{buildroot}/' \
  '%files' \
  '%attr(0755,root,root) /usr/bin/leaguebridge' \
  '%attr(0644,root,root) /usr/share/doc/leaguebridge/LICENSE' \
  '%attr(0644,root,root) /usr/share/doc/leaguebridge/README.md' \
  '%attr(0644,root,root) /usr/share/doc/leaguebridge/SBOM.spdx.json' \
  '%attr(0644,root,root) /usr/share/doc/leaguebridge/PACKAGE-MANIFEST.json' \
  > "$rpm_spec"
rpmbuild \
  --define "_topdir $rpm_top" \
  --define "_leaguebridge_payload $rpm_payload" \
  --define '_build_id_links none' \
  --define '_binary_payload w9.gzdio' \
  -bb "$rpm_spec" >/dev/null
generated_rpm="$rpm_top/RPMS/x86_64/leaguebridge-${rpm_version}-${rpm_release}.x86_64.rpm"
if [[ -L "$generated_rpm" || ! -f "$generated_rpm" ]]; then
  fail "rpmbuild did not create the expected package"
fi
cp "$generated_rpm" "$rpm_package"

mkdir -p "$debian_scratch/var/lib/dpkg" "$rpm_scratch"
sudo dpkg --root="$debian_scratch" --admindir="$debian_scratch/var/lib/dpkg" \
  --instdir="$debian_scratch" --unpack "$debian_package"
{
  echo 'package=debian'
  echo "version=$version"
  echo "filename=$(basename "$debian_package")"
  echo 'target=linux/amd64'
  dpkg-deb --info "$debian_package"
  sudo dpkg-query --admindir="$debian_scratch/var/lib/dpkg" -W leaguebridge
  "$debian_scratch/usr/bin/leaguebridge" status
  "$debian_scratch/usr/bin/leaguebridge" manifest verify
  sudo dpkg --root="$debian_scratch" --admindir="$debian_scratch/var/lib/dpkg" \
    --instdir="$debian_scratch" --purge leaguebridge
  test ! -e "$debian_scratch/usr/bin/leaguebridge"
  echo 'install=pass'
  echo 'uninstall=pass'
  sha256sum "$debian_package"
} > "$debian_evidence" 2>&1

sudo rpm --root "$rpm_scratch" --initdb
sudo rpm --root "$rpm_scratch" --install "$rpm_package"
{
  echo 'package=rpm'
  echo "version=$version"
  echo "filename=$(basename "$rpm_package")"
  echo 'target=linux/amd64'
  rpm --version
  rpm -qip "$rpm_package"
  sudo rpm --root "$rpm_scratch" -q leaguebridge
  "$rpm_scratch/usr/bin/leaguebridge" status
  "$rpm_scratch/usr/bin/leaguebridge" manifest verify
  sudo rpm --root "$rpm_scratch" --erase leaguebridge
  test ! -e "$rpm_scratch/usr/bin/leaguebridge"
  echo 'install=pass'
  echo 'uninstall=pass'
  sha256sum "$rpm_package"
} > "$rpm_evidence" 2>&1

echo "native Linux package smoke passed for $version"
