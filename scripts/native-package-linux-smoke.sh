#!/usr/bin/env bash
set -euo pipefail
set -f

export LC_ALL=C
umask 022

usage() {
  echo "usage: native-package-linux-smoke.sh VERSION RELEASE_ARCHIVE [OUTPUT_ROOT]" >&2
  exit 2
}

fail() {
  echo "native-package-linux-smoke: $*" >&2
  exit 1
}

if [[ "$#" -lt 2 || "$#" -gt 3 ]]; then
  usage
fi

version=$1
archive=$2
output_root=${3:-.}
output_prefix=
if [[ "$output_root" != "." ]]; then
  if [[ "$output_root" == /* || "$output_root" == */ || "$output_root" == *$'\n'* || "$output_root" == *$'\r'* || "$output_root" == *[^A-Za-z0-9._/-]* ]]; then
    fail "OUTPUT_ROOT must be a safe workspace-relative path"
  fi
  IFS=/ read -r -a output_parts <<< "$output_root"
  output_current=
  for output_part in "${output_parts[@]}"; do
    if [[ -z "$output_part" || "$output_part" == "." || "$output_part" == ".." ]]; then
      fail "OUTPUT_ROOT must not contain empty or traversing path components"
    fi
    if [[ -n "$output_current" ]]; then
      output_current="$output_current/$output_part"
    else
      output_current=$output_part
    fi
    if [[ -L "$output_current" ]]; then
      fail "OUTPUT_ROOT contains a symlinked path component: $output_current"
    fi
  done
  output_prefix="$output_root/"
fi
staging_root="${output_prefix}native-package-staging"
package_root="${output_prefix}native-package-output"
evidence_root="${output_prefix}native-package-evidence"
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
for command_name in go dpkg-deb dpkg rpm rpmbuild file sudo sha256sum cmp stat uname; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is unavailable: $command_name"
done
if ! go run -mod=vendor ./tools/versioncheck "$version" >/dev/null 2>&1; then
  fail "VERSION is not accepted by the repository semantic-version checker"
fi

case "$(uname -m)" in
  x86_64|amd64) target_goarch=amd64; debian_arch=amd64; rpm_arch=x86_64 ;;
  aarch64|arm64) target_goarch=arm64; debian_arch=arm64; rpm_arch=aarch64 ;;
  *) fail "native Linux package smoke requires an amd64 or arm64 host" ;;
esac
if [[ "${archive##*/}" != "leaguebridge_${version#v}_linux_${target_goarch}.tar.gz" ]]; then
  fail "release archive does not match the native Linux host and version"
fi
if [[ "$(dpkg --print-architecture)" != "$debian_arch" || "$(rpm --eval '%{_arch}')" != "$rpm_arch" ]]; then
  fail "package managers do not match the native Linux host architecture"
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

verify_installed_payload() {
  local staging_root=$1 installed_root=$2 relative expected_mode
  for relative in \
    usr/bin/leaguebridge \
    usr/libexec/leaguebridge/linux-bsd-client-smoke.sh \
    usr/libexec/leaguebridge/linux-bsd-remote-session.sh \
    usr/share/doc/leaguebridge/LICENSE \
    usr/share/doc/leaguebridge/README.md \
    usr/share/doc/leaguebridge/SBOM.spdx.json \
    usr/share/doc/leaguebridge/PACKAGE-MANIFEST.json; do
    if [[ -L "$installed_root/$relative" || ! -f "$installed_root/$relative" ]]; then
      fail "installed payload is not a regular file: $relative"
    fi
    cmp -s "$staging_root/$relative" "$installed_root/$relative" || \
      fail "installed payload differs from verified staging: $relative"
    expected_mode=$(stat -c '%a' "$staging_root/$relative")
    [[ $(stat -c '%a:%u:%g' "$installed_root/$relative") == "$expected_mode:0:0" ]] || \
      fail "installed payload mode or root ownership differs: $relative"
  done
  echo 'payload=pass'
}

ensure_directory "$output_root"
staging_debian="$staging_root/debian/$target_goarch"
staging_rpm="$staging_root/rpm/$target_goarch"
packages_debian="$package_root/debian/$target_goarch"
packages_rpm="$package_root/rpm/$target_goarch"
evidence_debian="$evidence_root/debian/$target_goarch"
evidence_rpm="$evidence_root/rpm/$target_goarch"
ensure_directory "$staging_root/debian"
ensure_directory "$staging_root/rpm"
ensure_directory "$packages_debian"
ensure_directory "$packages_rpm"
ensure_directory "$evidence_debian"
ensure_directory "$evidence_rpm"

go run -mod=vendor ./tools/nativepackagestage \
  -archive "$archive" -family debian \
  -output "$staging_debian"
go run -mod=vendor ./tools/nativepackagecheck \
  -staging "$staging_debian"
go run -mod=vendor ./tools/nativepackagestage \
  -archive "$archive" -family rpm \
  -output "$staging_rpm"
go run -mod=vendor ./tools/nativepackagecheck \
  -staging "$staging_rpm"

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

debian_package="$packages_debian/leaguebridge_${deb_version}_${debian_arch}.deb"
rpm_package="$packages_rpm/leaguebridge-${rpm_version}-${rpm_release}.${rpm_arch}.rpm"
debian_evidence="$evidence_debian/install.txt"
rpm_evidence="$evidence_rpm/install.txt"
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
  cleanup_status=$?
  set +e
  sudo dpkg --root="$debian_scratch" --admindir="$debian_scratch/var/lib/dpkg" \
    --instdir="$debian_scratch" --purge leaguebridge >/dev/null 2>&1
  sudo rpm --root "$rpm_scratch" --erase leaguebridge >/dev/null 2>&1
  if [[ -n "${temporary_root:-}" && -e "$temporary_root" && ! -L "$temporary_root" ]]; then
    # Package managers create root-owned databases and directories even when
    # the caller owns the private parent. Remove those roots with the same
    # privilege used to create them, and do not hide a cleanup failure.
    if ! sudo rm -rf -- "$temporary_root"; then
      echo "native-package-linux-smoke: could not remove private package roots" >&2
      if [[ "$cleanup_status" -eq 0 ]]; then
        cleanup_status=1
      fi
    fi
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT

mkdir -p "$debian_root" "$rpm_top" "$rpm_payload"
cp -a "$staging_debian/root/." "$debian_root/"
mkdir -p "$debian_root/DEBIAN"
printf '%s\n' \
  'Package: leaguebridge' \
  "Version: $deb_version" \
  "Architecture: $debian_arch" \
  'Maintainer: LeagueBridge contributors <maintainers@leaguebridge.invalid>' \
  'Section: net' \
  'Priority: optional' \
  'Description: LeagueBridge remote handoff controller' \
  ' A bounded, read-only compatibility and remote handoff controller.' \
  > "$debian_root/DEBIAN/control"
chmod 0644 "$debian_root/DEBIAN/control"
dpkg-deb --build --root-owner-group "$debian_root" "$debian_package" >/dev/null

cp -a "$staging_rpm/root/." "$rpm_payload/"
mkdir -p "$rpm_top/BUILD" "$rpm_top/BUILDROOT" "$rpm_top/RPMS" "$rpm_top/SOURCES" \
  "$rpm_top/SPECS" "$rpm_top/SRPMS"
rpm_spec=$rpm_top/SPECS/leaguebridge.spec
printf '%s\n' \
  'Name: leaguebridge' \
  "Version: $rpm_version" \
  "Release: $rpm_release" \
  'Summary: LeagueBridge remote handoff controller' \
  'License: 0BSD' \
  "BuildArch: $rpm_arch" \
  'AutoReqProv: no' \
  '%description' \
  'A bounded, read-only compatibility and remote handoff controller.' \
  '%install' \
  'rm -rf %{buildroot}' \
  'mkdir -p %{buildroot}' \
  'cp -a %{_leaguebridge_payload}/. %{buildroot}/' \
  '%files' \
  '%attr(0755,root,root) /usr/bin/leaguebridge' \
  '%attr(0755,root,root) /usr/libexec/leaguebridge/linux-bsd-client-smoke.sh' \
  '%attr(0755,root,root) /usr/libexec/leaguebridge/linux-bsd-remote-session.sh' \
  '%attr(0644,root,root) /usr/share/doc/leaguebridge/LICENSE' \
  '%attr(0644,root,root) /usr/share/doc/leaguebridge/README.md' \
  '%attr(0644,root,root) /usr/share/doc/leaguebridge/SBOM.spdx.json' \
  '%attr(0644,root,root) /usr/share/doc/leaguebridge/PACKAGE-MANIFEST.json' \
  > "$rpm_spec"
# These are already verified release payloads. Distribution postprocessing
# (including stripping ELF comments/notes) would invalidate their bound hashes.
rpmbuild \
  --define "_topdir $rpm_top" \
  --define "_leaguebridge_payload $rpm_payload" \
  --define '_build_id_links none' \
  --define '_binary_payload w9.gzdio' \
  --define '__os_install_post %{nil}' \
  -bb "$rpm_spec" >/dev/null
generated_rpm="$rpm_top/RPMS/$rpm_arch/leaguebridge-${rpm_version}-${rpm_release}.${rpm_arch}.rpm"
if [[ -L "$generated_rpm" || ! -f "$generated_rpm" ]]; then
  fail "rpmbuild did not create the expected package"
fi
cp "$generated_rpm" "$rpm_package"

mkdir -p "$debian_scratch/var/lib/dpkg" "$rpm_scratch"
# Minimal images can globally exclude documentation. This private install
# must exercise every verified payload member, regardless of those filters.
sudo dpkg --root="$debian_scratch" --admindir="$debian_scratch/var/lib/dpkg" \
  --instdir="$debian_scratch" --path-include='/*' --unpack "$debian_package"
{
  echo 'package=debian'
  echo "version=$version"
  echo "filename=$(basename "$debian_package")"
  echo "target=linux/$target_goarch"
  dpkg-deb --info "$debian_package"
  sudo dpkg-query --admindir="$debian_scratch/var/lib/dpkg" -W leaguebridge
  verify_installed_payload "$staging_debian/root" "$debian_scratch"
  test -x "$debian_scratch/usr/libexec/leaguebridge/linux-bsd-client-smoke.sh"
  test -x "$debian_scratch/usr/libexec/leaguebridge/linux-bsd-remote-session.sh"
  "$debian_scratch/usr/bin/leaguebridge" status
  "$debian_scratch/usr/bin/leaguebridge" manifest verify
  sudo dpkg --root="$debian_scratch" --admindir="$debian_scratch/var/lib/dpkg" \
    --instdir="$debian_scratch" --purge leaguebridge
  test ! -e "$debian_scratch/usr/bin/leaguebridge"
  test ! -e "$debian_scratch/usr/libexec/leaguebridge/linux-bsd-client-smoke.sh"
  test ! -e "$debian_scratch/usr/libexec/leaguebridge/linux-bsd-remote-session.sh"
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
  echo "target=linux/$target_goarch"
  rpm --version
  rpm -qip "$rpm_package"
  sudo rpm --root "$rpm_scratch" -q leaguebridge
  verify_installed_payload "$staging_rpm/root" "$rpm_scratch"
  test -x "$rpm_scratch/usr/libexec/leaguebridge/linux-bsd-client-smoke.sh"
  test -x "$rpm_scratch/usr/libexec/leaguebridge/linux-bsd-remote-session.sh"
  "$rpm_scratch/usr/bin/leaguebridge" status
  "$rpm_scratch/usr/bin/leaguebridge" manifest verify
  sudo rpm --root "$rpm_scratch" --erase leaguebridge
  test ! -e "$rpm_scratch/usr/bin/leaguebridge"
  test ! -e "$rpm_scratch/usr/libexec/leaguebridge/linux-bsd-client-smoke.sh"
  test ! -e "$rpm_scratch/usr/libexec/leaguebridge/linux-bsd-remote-session.sh"
  echo 'install=pass'
  echo 'uninstall=pass'
  sha256sum "$rpm_package"
} > "$rpm_evidence" 2>&1

echo "native Linux package smoke passed for $version"
