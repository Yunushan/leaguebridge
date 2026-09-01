#!/bin/sh
set -eu
set -f

export LC_ALL=C
umask 022

usage() {
  echo "usage: native-package-bsd-smoke.sh VERSION GOOS FAMILY [VERSION_CHECKER]" >&2
  exit 2
}

fail() {
  echo "native-package-bsd-smoke: $*" >&2
  exit 1
}

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  usage
fi

version=$1
expected_goos=$2
family=$3
version_checker=${4:-}
# Keep the shell guard to the required prefix only. The repository's Go
# semantic-version checker below (or the shipped checker binary) is
# authoritative; duplicating SemVer grammar in a shell glob can reject valid
# prerelease forms before that checker runs.
case "$version" in
  v*) ;;
  *) fail "VERSION must be a v-prefixed semantic version" ;;
esac
case "$expected_goos:$family" in
  freebsd:freebsd-pkg|openbsd:openbsd-pkg|netbsd:pkgsrc|dragonfly:dports) ;;
  *) fail "GOOS and native package family do not match" ;;
esac

case "$(uname -s):$expected_goos" in
  FreeBSD:freebsd|OpenBSD:openbsd|NetBSD:netbsd|DragonFly:dragonfly) ;;
  *) fail "package smoke is running on the wrong BSD kernel" ;;
esac
case "$(uname -m)" in
  amd64|x86_64) ;;
  *) fail "package smoke requires an amd64 guest" ;;
esac
if [ -n "$version_checker" ]; then
  if [ -L "$version_checker" ] || [ ! -f "$version_checker" ]; then
    fail "VERSION_CHECKER must be a regular, non-symlink file"
  fi
  if ! "$version_checker" "$version" >/dev/null 2>&1; then
    fail "VERSION is not accepted by the repository semantic-version checker"
  fi
elif command -v go >/dev/null 2>&1; then
  if ! go run -mod=vendor ./tools/versioncheck "$version" >/dev/null 2>&1; then
    fail "VERSION is not accepted by the repository semantic-version checker"
  fi
else
  fail "go is unavailable in the BSD guest and no VERSION_CHECKER was supplied"
fi

package_version=${version#v}
package_name="leaguebridge-$package_version"
staging="native-package-staging/$family"
package_dir="native-package-output/$family"
evidence_dir="native-package-evidence/$family"

ensure_directory() {
  directory=$1
  if [ -L "$directory" ] || { [ -e "$directory" ] && [ ! -d "$directory" ]; }; then
    fail "path is not a real directory: $directory"
  fi
  mkdir -p "$directory"
  if [ -L "$directory" ] || [ ! -d "$directory" ]; then
    fail "path changed into a non-directory after creation: $directory"
  fi
}

ensure_directory native-package-staging
ensure_directory native-package-output
ensure_directory native-package-evidence
ensure_directory "$package_dir"
ensure_directory "$evidence_dir"
if [ -L "$staging" ] || [ ! -d "$staging" ]; then
  fail "staging directory is not a real directory: $staging"
fi

case "$expected_goos" in
  freebsd|dragonfly)
    package="$package_dir/$package_name-$expected_goos.pkg"
    ;;
  openbsd|netbsd)
    package="$package_dir/$package_name-$expected_goos.tgz"
    ;;
esac
evidence="$evidence_dir/install.txt"
if [ -e "$package" ] || [ -L "$package" ]; then
  fail "package output already exists: $package"
fi
if [ -e "$evidence" ] || [ -L "$evidence" ]; then
  fail "evidence output already exists: $evidence"
fi

if [ "$(id -u)" -eq 0 ]; then
  root_command=
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  root_command=sudo
elif command -v doas >/dev/null 2>&1 && doas -n true >/dev/null 2>&1; then
  root_command=doas
else
  fail "root or a non-interactive doas/sudo command is required"
fi

as_root() {
  if [ -n "$root_command" ]; then
    "$root_command" "$@"
  else
    "$@"
  fi
}

package_installed=0
netbsd_payload_staged=0

assert_clean_install_paths() {
  for install_path in \
    /usr/local/bin/leaguebridge \
    /usr/local/share/doc/leaguebridge \
    /usr/local/share/doc/leaguebridge/LICENSE \
    /usr/local/share/doc/leaguebridge/README.md \
    /usr/local/share/doc/leaguebridge/SBOM.spdx.json \
    /usr/local/share/doc/leaguebridge/PACKAGE-MANIFEST.json; do
    if [ -e "$install_path" ] || [ -L "$install_path" ]; then
      fail "guest has a pre-existing LeagueBridge path; refusing to overwrite: $install_path"
    fi
  done
}

assert_uninstalled() {
  for installed_path in \
    /usr/local/bin/leaguebridge \
    /usr/local/share/doc/leaguebridge \
    /usr/local/share/doc/leaguebridge/LICENSE \
    /usr/local/share/doc/leaguebridge/README.md \
    /usr/local/share/doc/leaguebridge/SBOM.spdx.json \
    /usr/local/share/doc/leaguebridge/PACKAGE-MANIFEST.json; do
    if [ -e "$installed_path" ] || [ -L "$installed_path" ]; then
      fail "package uninstall left $installed_path behind"
    fi
  done
}

remove_owned_doc_directory() {
  as_root rmdir /usr/local/share/doc/leaguebridge 2>/dev/null || :
}

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/leaguebridge-native-package.XXXXXXXX")
cleanup() {
  set +e
  case "$expected_goos" in
    freebsd|dragonfly)
      if [ "$package_installed" -eq 1 ]; then
        as_root pkg delete -y "$package_name" >/dev/null 2>&1
      fi
      ;;
    openbsd)
      if [ "$package_installed" -eq 1 ]; then
        as_root pkg_delete -I "$package_name" >/dev/null 2>&1
      fi
      ;;
    netbsd)
      if [ "$package_installed" -eq 1 ]; then
        as_root pkg_delete -f "$package_name" >/dev/null 2>&1
      fi
      ;;
  esac
  if [ "$netbsd_payload_staged" -eq 1 ] || [ "$package_installed" -eq 1 ]; then
    as_root rm -f \
      /usr/local/bin/leaguebridge \
      /usr/local/share/doc/leaguebridge/LICENSE \
      /usr/local/share/doc/leaguebridge/README.md \
      /usr/local/share/doc/leaguebridge/SBOM.spdx.json \
      /usr/local/share/doc/leaguebridge/PACKAGE-MANIFEST.json
    remove_owned_doc_directory
  fi
  if [ -n "${temporary_root:-}" ] && [ -e "$temporary_root" ] && [ ! -L "$temporary_root" ]; then
    rm -rf -- "$temporary_root"
  fi
}
trap cleanup EXIT HUP INT TERM

case "$expected_goos" in
  freebsd|dragonfly)
    command -v pkg >/dev/null 2>&1 || fail "pkg is unavailable in the BSD guest"
    if pkg info -e "$package_name" >/dev/null 2>&1; then
      fail "guest already has package $package_name installed"
    fi
    assert_clean_install_paths
    metadata="$temporary_root/metadata"
    mkdir "$metadata"
    printf '%s\n' \
      '{' \
      '  name: "leaguebridge",' \
      "  version: \"$package_version\"," \
      '  origin: "sysutils/leaguebridge",' \
      '  comment: "LeagueBridge remote handoff controller",' \
      '  maintainer: "LeagueBridge contributors <maintainers@leaguebridge.invalid>",' \
      '  prefix: "/usr/local",' \
      '  desc: "A bounded, read-only compatibility and remote handoff controller."' \
      '}' > "$metadata/+MANIFEST"
    generated="$temporary_root/generated"
    mkdir "$generated"
    pkg create -m "$metadata" -r "$staging/root" -o "$generated" -f txz -n
    generated_package=
    set +f
    for candidate in "$generated"/*.pkg; do
      if [ ! -f "$candidate" ]; then
        continue
      fi
      if [ -n "$generated_package" ]; then
        fail "pkg create produced more than one .pkg file"
      fi
      generated_package=$candidate
    done
    set -f
    [ -n "$generated_package" ] || fail "pkg create did not produce a .pkg file"
    mv "$generated_package" "$package"
    ;;
  openbsd)
    command -v pkg_create >/dev/null 2>&1 || fail "pkg_create is unavailable in the OpenBSD guest"
    command -v pkg_add >/dev/null 2>&1 || fail "pkg_add is unavailable in the OpenBSD guest"
    command -v pkg_delete >/dev/null 2>&1 || fail "pkg_delete is unavailable in the OpenBSD guest"
    command -v pkg_info >/dev/null 2>&1 || fail "pkg_info is unavailable in the OpenBSD guest"
    if pkg_info -e "$package_name" >/dev/null 2>&1; then
      fail "guest already has package $package_name installed"
    fi
    assert_clean_install_paths
    packlist="$temporary_root/packing-list"
    description="$temporary_root/description"
    printf '%s\n' \
      "@name $package_name" \
      '@arch amd64' \
      '@cwd /usr/local' \
      '@mode 0755' \
      'bin/leaguebridge' \
      '@mode 0644' \
      'share/doc/leaguebridge/LICENSE' \
      'share/doc/leaguebridge/README.md' \
      'share/doc/leaguebridge/SBOM.spdx.json' \
      'share/doc/leaguebridge/PACKAGE-MANIFEST.json' > "$packlist"
    printf '%s\n' 'A bounded, read-only compatibility and remote handoff controller.' > "$description"
    pkg_create -A amd64 -B "$staging/root" -p /usr/local \
      -f "$packlist" -d "$description" \
      -D COMMENT='LeagueBridge remote handoff controller' \
      -D FULLPKGPATH=sysutils/leaguebridge "$package"
    ;;
  netbsd)
    command -v pkg_create >/dev/null 2>&1 || fail "pkg_create is unavailable in the NetBSD guest"
    command -v pkg_add >/dev/null 2>&1 || fail "pkg_add is unavailable in the NetBSD guest"
    command -v pkg_delete >/dev/null 2>&1 || fail "pkg_delete is unavailable in the NetBSD guest"
    command -v pkg_info >/dev/null 2>&1 || fail "pkg_info is unavailable in the NetBSD guest"
    if pkg_info -e "$package_name" >/dev/null 2>&1; then
      fail "guest already has package $package_name installed"
    fi
    assert_clean_install_paths
    packlist="$temporary_root/packing-list"
    comment="$temporary_root/comment"
    description="$temporary_root/description"
    printf '%s\n' \
      "@name $package_name" \
      '@cwd /usr/local' \
      '@mode 0755' \
      'bin/leaguebridge' \
      '@mode 0644' \
      'share/doc/leaguebridge/LICENSE' \
      'share/doc/leaguebridge/README.md' \
      'share/doc/leaguebridge/SBOM.spdx.json' \
      'share/doc/leaguebridge/PACKAGE-MANIFEST.json' > "$packlist"
    printf '%s\n' 'LeagueBridge remote handoff controller' > "$comment"
    printf '%s\n' 'A bounded, read-only compatibility and remote handoff controller.' > "$description"
    as_root mkdir -p /usr/local/bin /usr/local/share/doc/leaguebridge
    netbsd_payload_staged=1
    as_root cp -p \
      "$staging/root/usr/local/bin/leaguebridge" \
      /usr/local/bin/leaguebridge
    as_root cp -p \
      "$staging/root/usr/local/share/doc/leaguebridge/LICENSE" \
      "$staging/root/usr/local/share/doc/leaguebridge/README.md" \
      "$staging/root/usr/local/share/doc/leaguebridge/SBOM.spdx.json" \
      "$staging/root/usr/local/share/doc/leaguebridge/PACKAGE-MANIFEST.json" \
      /usr/local/share/doc/leaguebridge/
    as_root chmod 0755 /usr/local/bin/leaguebridge
    as_root chmod 0644 /usr/local/share/doc/leaguebridge/LICENSE \
      /usr/local/share/doc/leaguebridge/README.md \
      /usr/local/share/doc/leaguebridge/SBOM.spdx.json \
      /usr/local/share/doc/leaguebridge/PACKAGE-MANIFEST.json
    root_abs=$(cd "$staging/root" && pwd -P)
    pkg_create \
      -I /usr/local -p "$root_abs/usr/local" -F gzip \
      -c "$comment" -d "$description" -f "$packlist" "$package"
    as_root rm -f /usr/local/bin/leaguebridge \
      /usr/local/share/doc/leaguebridge/LICENSE \
      /usr/local/share/doc/leaguebridge/README.md \
      /usr/local/share/doc/leaguebridge/SBOM.spdx.json \
      /usr/local/share/doc/leaguebridge/PACKAGE-MANIFEST.json
    as_root rmdir /usr/local/share/doc/leaguebridge 2>/dev/null || :
    assert_clean_install_paths
    netbsd_payload_staged=0
    ;;
esac

if [ -L "$package" ] || [ ! -f "$package" ]; then
  fail "native package builder did not create a regular package: $package"
fi

case "$expected_goos" in
  freebsd|dragonfly)
    {
      echo "package=$family"
      echo "version=$version"
      echo "filename=$(basename "$package")"
      echo "target=$expected_goos/amd64"
      uname -a
      pkg -v
      pkg info -e "$package_name" || :
      package_installed=1
      as_root pkg add -f "$package"
      as_root pkg info -e "$package_name"
      /usr/local/bin/leaguebridge status
      /usr/local/bin/leaguebridge manifest verify
      as_root pkg delete -y "$package_name"
      remove_owned_doc_directory
      assert_uninstalled
      package_installed=0
      echo 'install=pass'
      echo 'uninstall=pass'
      sha256 "$package"
    } > "$evidence" 2>&1
    ;;
  openbsd)
    {
      echo "package=$family"
      echo "version=$version"
      echo "filename=$(basename "$package")"
      echo "target=$expected_goos/amd64"
      uname -a
      pkg_add -V
      package_installed=1
      as_root pkg_add -D unsigned -I "$package"
      as_root pkg_info -e "$package_name"
      /usr/local/bin/leaguebridge status
      /usr/local/bin/leaguebridge manifest verify
      as_root pkg_delete -I "$package_name"
      remove_owned_doc_directory
      assert_uninstalled
      package_installed=0
      echo 'package-signature=unsigned-ci-only'
      echo 'install=pass'
      echo 'uninstall=pass'
      sha256 "$package"
    } > "$evidence" 2>&1
    ;;
  netbsd)
    {
      echo "package=$family"
      echo "version=$version"
      echo "filename=$(basename "$package")"
      echo "target=$expected_goos/amd64"
      uname -a
      pkg_add -V
      package_installed=1
      as_root pkg_add "$package"
      as_root pkg_info -e "$package_name"
      /usr/local/bin/leaguebridge status
      /usr/local/bin/leaguebridge manifest verify
      as_root pkg_delete -f "$package_name"
      remove_owned_doc_directory
      assert_uninstalled
      package_installed=0
      echo 'install=pass'
      echo 'uninstall=pass'
      sha256 "$package"
    } > "$evidence" 2>&1
    ;;
esac

echo "native BSD package smoke passed for $expected_goos/$family $version"
