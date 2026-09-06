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
runtime_machine=$(uname -m)
case "$runtime_machine" in
  amd64|x86_64) expected_goarch=amd64 ;;
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
      amd64|x86_64) expected_goarch=amd64 ;;
      aarch64|arm64) expected_goarch=arm64 ;;
      *) fail "machine architecture is not amd64 or arm64: uname -m=$runtime_machine uname -p=$runtime_machine_arch" ;;
    esac
    ;;
esac
case "$expected_goos:$expected_goarch" in
  freebsd:amd64|openbsd:amd64|netbsd:amd64|dragonfly:amd64) package_architecture=amd64 ;;
  freebsd:arm64|netbsd:arm64) package_architecture=aarch64 ;;
  openbsd:arm64) package_architecture=arm64 ;;
  *) fail "native package smoke does not support $expected_goos/$expected_goarch" ;;
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
installed_package_name=$package_name
staging_parent="native-package-staging/$family"
package_parent="native-package-output/$family"
evidence_parent="native-package-evidence/$family"
staging="$staging_parent/$expected_goarch"
package_dir="$package_parent/$expected_goarch"
evidence_dir="$evidence_parent/$expected_goarch"

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
ensure_directory "$package_parent"
ensure_directory "$evidence_parent"
ensure_directory "$package_dir"
ensure_directory "$evidence_dir"
if [ -L "$staging_parent" ] || [ ! -d "$staging_parent" ]; then
  fail "staging directory is not a real directory: $staging_parent"
fi
if [ -L "$staging" ] || [ ! -d "$staging" ]; then
  fail "staging directory is not a real directory: $staging"
fi

case "$expected_goos" in
  freebsd|dragonfly)
    package="$package_dir/$package_name-$expected_goos-$expected_goarch.pkg"
    ;;
  openbsd|netbsd)
    package="$package_dir/$package_name-$expected_goos-$expected_goarch.tgz"
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
pkg_command=

assert_clean_install_paths() {
  for install_path in \
    /usr/local/bin/leaguebridge \
    /usr/local/libexec/leaguebridge/linux-bsd-client-smoke.sh \
    /usr/local/libexec/leaguebridge/linux-bsd-remote-session.sh \
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
    /usr/local/libexec/leaguebridge/linux-bsd-client-smoke.sh \
    /usr/local/libexec/leaguebridge/linux-bsd-remote-session.sh \
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

hash_package() {
  package_path=$1
  package_hash=
  if command -v sha256sum >/dev/null 2>&1; then
    package_hash=$(sha256sum "$package_path" | awk '{print $1}')
  elif command -v sha256 >/dev/null 2>&1; then
    package_hash=$(sha256 -q "$package_path" 2>/dev/null || :)
    if [ -z "$package_hash" ]; then
      package_hash=$(sha256 "$package_path" | awk '{print $NF}')
    fi
  elif command -v openssl >/dev/null 2>&1; then
    package_hash=$(openssl dgst -sha256 -r "$package_path" 2>/dev/null | awk '{print $1}' || :)
    if [ -z "$package_hash" ]; then
      package_hash=$(openssl dgst -sha256 "$package_path" | awk '{print $NF}')
    fi
  else
    fail "no SHA-256 utility is available in the BSD guest"
  fi
  case "$package_hash" in
    ''|*[!0-9A-Fa-f]*) fail "SHA-256 utility returned an invalid package digest" ;;
  esac
  if [ "${#package_hash}" -ne 64 ]; then
    fail "SHA-256 utility returned a digest with an unexpected length"
  fi
  printf '%s  %s\n' "$(printf '%s' "$package_hash" | tr 'A-F' 'a-f')" "$package_path"
}

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/leaguebridge-native-package.XXXXXXXX")
cleanup() {
  cleanup_status=$?
  set +e
  if [ "$cleanup_status" -ne 0 ] && [ -f "${evidence:-}" ]; then
    echo "native-package-bsd-smoke: command output before failure:" >&2
    cat "$evidence" >&2
  fi
  case "$expected_goos" in
    freebsd|dragonfly)
      if [ "$package_installed" -eq 1 ] && [ -n "${pkg_command:-}" ]; then
        as_root "$pkg_command" delete -y "$package_name" >/dev/null 2>&1
      fi
      ;;
    openbsd)
      if [ "$package_installed" -eq 1 ]; then
        as_root pkg_delete -I "$installed_package_name" >/dev/null 2>&1
      fi
      ;;
    netbsd)
      if [ "$package_installed" -eq 1 ]; then
        as_root pkg_delete -f "$package_name" >/dev/null 2>&1
      fi
      ;;
  esac
  if [ "$package_installed" -eq 1 ]; then
    as_root rm -f \
      /usr/local/bin/leaguebridge \
      /usr/local/libexec/leaguebridge/linux-bsd-client-smoke.sh \
      /usr/local/libexec/leaguebridge/linux-bsd-remote-session.sh \
      /usr/local/share/doc/leaguebridge/LICENSE \
      /usr/local/share/doc/leaguebridge/README.md \
      /usr/local/share/doc/leaguebridge/SBOM.spdx.json \
      /usr/local/share/doc/leaguebridge/PACKAGE-MANIFEST.json
    remove_owned_doc_directory
  fi
  if [ -n "${temporary_root:-}" ] && [ -e "$temporary_root" ] && [ ! -L "$temporary_root" ]; then
    rm -rf -- "$temporary_root"
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT HUP INT TERM

case "$expected_goos" in
  openbsd)
    # OpenBSD derives the installed package name from the output filename when
    # the packing list does not contain @name. Keep the name used by pkg_info
    # and pkg_delete bound to that derived identity.
    installed_package_name="$package_name-$expected_goos-$expected_goarch"
    ;;
esac

case "$expected_goos" in
  freebsd|dragonfly)
    # Prefer the static client. On FreeBSD-family guests, pkg can be a
    # bootstrap wrapper whose interpreter or downloaded client is absent even
    # though the static package tool is already available.
    if command -v pkg-static >/dev/null 2>&1; then
      pkg_command=$(command -v pkg-static)
    elif command -v pkg >/dev/null 2>&1; then
      pkg_command=$(command -v pkg)
    else
      fail "pkg and pkg-static are unavailable in the BSD guest"
    fi
    case "$pkg_command" in
      /*) ;;
      *) fail "BSD package tool did not resolve to an absolute path" ;;
    esac
    if "$pkg_command" info -e "$installed_package_name" >/dev/null 2>&1; then
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
    # pkg create only includes files named by metadata or a packing list;
    # -r supplies their source root and does not enumerate that directory.
    packlist="$temporary_root/packing-list"
    printf '%s\n' \
      '@cwd /usr/local' \
      '@mode 0755' \
      'bin/leaguebridge' \
      'libexec/leaguebridge/linux-bsd-client-smoke.sh' \
      'libexec/leaguebridge/linux-bsd-remote-session.sh' \
      '@mode 0644' \
      'share/doc/leaguebridge/LICENSE' \
      'share/doc/leaguebridge/README.md' \
      'share/doc/leaguebridge/SBOM.spdx.json' \
      'share/doc/leaguebridge/PACKAGE-MANIFEST.json' \
      '@mode 0755' \
      '@dir libexec/leaguebridge' \
      '@dir share/doc/leaguebridge' > "$packlist"
    "$pkg_command" create -m "$metadata" -p "$packlist" -r "$staging/root" -o "$generated" -f txz -n
    generated_package=
    set +f
    for candidate in "$generated"/*.pkg "$generated"/*.txz; do
      if [ ! -f "$candidate" ]; then
        continue
      fi
      if [ -n "$generated_package" ]; then
        fail "pkg create produced more than one package file"
      fi
      generated_package=$candidate
    done
    set -f
    [ -n "$generated_package" ] || fail "pkg create did not produce a .pkg or .txz file"
    mv "$generated_package" "$package"
    ;;
  openbsd)
    command -v pkg_create >/dev/null 2>&1 || fail "pkg_create is unavailable in the OpenBSD guest"
    command -v pkg_add >/dev/null 2>&1 || fail "pkg_add is unavailable in the OpenBSD guest"
    command -v pkg_delete >/dev/null 2>&1 || fail "pkg_delete is unavailable in the OpenBSD guest"
    command -v pkg_info >/dev/null 2>&1 || fail "pkg_info is unavailable in the OpenBSD guest"
    if pkg_info -e "$installed_package_name" >/dev/null 2>&1; then
      fail "guest already has package $package_name installed"
    fi
    assert_clean_install_paths
    packlist="$temporary_root/packing-list"
    description="$temporary_root/description"
    printf '%s\n' \
      '@cwd /usr/local' \
      '@mode 0755' \
      'bin/leaguebridge' \
      'libexec/leaguebridge/linux-bsd-client-smoke.sh' \
      'libexec/leaguebridge/linux-bsd-remote-session.sh' \
      '@mode 0644' \
      'share/doc/leaguebridge/LICENSE' \
      'share/doc/leaguebridge/README.md' \
      'share/doc/leaguebridge/SBOM.spdx.json' \
      'share/doc/leaguebridge/PACKAGE-MANIFEST.json' > "$packlist"
    printf '%s\n' 'A bounded, read-only compatibility and remote handoff controller.' > "$description"
    pkg_create -A "$package_architecture" -B "$staging/root" -p /usr/local \
      -f "$packlist" -d "$description" \
      -D COMMENT='LeagueBridge remote handoff controller' \
      -D FULLPKGPATH=sysutils/leaguebridge "$package"
    ;;
  netbsd)
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
      'libexec/leaguebridge/linux-bsd-client-smoke.sh' \
      'libexec/leaguebridge/linux-bsd-remote-session.sh' \
      '@mode 0644' \
      'share/doc/leaguebridge/LICENSE' \
      'share/doc/leaguebridge/README.md' \
      'share/doc/leaguebridge/SBOM.spdx.json' \
      'share/doc/leaguebridge/PACKAGE-MANIFEST.json' > "$packlist"
    printf '%s\n' 'LeagueBridge remote handoff controller' > "$comment"
    printf '%s\n' 'A bounded, read-only compatibility and remote handoff controller.' > "$description"
    if command -v pkg_create >/dev/null 2>&1; then
      root_abs=$(cd "$staging/root" && pwd -P)
      pkg_create \
        -I /usr/local -p "$root_abs/usr/local" -F gzip \
        -c "$comment" -d "$description" -f "$packlist" "$package"
    else
      package_archiver=
      if command -v tar >/dev/null 2>&1 && command -v gzip >/dev/null 2>&1; then
        package_archiver=tar
      elif command -v pax >/dev/null 2>&1; then
        # NetBSD ships pax in the base system; it can write gzip-compressed
        # tar archives even when the optional pkg_create utility is absent.
        package_archiver=pax
      else
        fail "pkg_create is unavailable and neither tar/gzip nor pax is available in the NetBSD guest"
      fi
      package_root="$temporary_root/netbsd-package-root"
      package_path_absolute=$(pwd -P)/$package
      mkdir -p "$package_root/bin" "$package_root/libexec/leaguebridge" "$package_root/share/doc/leaguebridge"
      cp -p "$staging/root/usr/local/bin/leaguebridge" "$package_root/bin/leaguebridge"
      cp -p "$staging/root/usr/local/libexec/leaguebridge/linux-bsd-client-smoke.sh" "$package_root/libexec/leaguebridge/linux-bsd-client-smoke.sh"
      cp -p "$staging/root/usr/local/libexec/leaguebridge/linux-bsd-remote-session.sh" "$package_root/libexec/leaguebridge/linux-bsd-remote-session.sh"
      cp -p \
        "$staging/root/usr/local/share/doc/leaguebridge/LICENSE" \
        "$staging/root/usr/local/share/doc/leaguebridge/README.md" \
        "$staging/root/usr/local/share/doc/leaguebridge/SBOM.spdx.json" \
        "$staging/root/usr/local/share/doc/leaguebridge/PACKAGE-MANIFEST.json" \
        "$package_root/share/doc/leaguebridge/"
      cp "$packlist" "$package_root/+CONTENTS"
      cp "$comment" "$package_root/+COMMENT"
      cp "$description" "$package_root/+DESC"
      # NetBSD's pkg_install format treats +CONTENTS as the package table of
      # contents. Put it first so the tar fallback remains consumable by
      # pkg_add implementations that stream metadata instead of seeking.
      if [ "$package_archiver" = tar ]; then
        (cd "$package_root" && tar -czf "$package_path_absolute" \
          +CONTENTS +COMMENT +DESC \
          bin/leaguebridge \
          libexec/leaguebridge/linux-bsd-client-smoke.sh \
          libexec/leaguebridge/linux-bsd-remote-session.sh \
          share/doc/leaguebridge/LICENSE \
          share/doc/leaguebridge/README.md \
          share/doc/leaguebridge/SBOM.spdx.json \
          share/doc/leaguebridge/PACKAGE-MANIFEST.json)
      else
        (cd "$package_root" && pax -w -z -f "$package_path_absolute" \
          +CONTENTS +COMMENT +DESC \
          bin/leaguebridge \
          libexec/leaguebridge/linux-bsd-client-smoke.sh \
          libexec/leaguebridge/linux-bsd-remote-session.sh \
          share/doc/leaguebridge/LICENSE \
          share/doc/leaguebridge/README.md \
          share/doc/leaguebridge/SBOM.spdx.json \
          share/doc/leaguebridge/PACKAGE-MANIFEST.json)
      fi
    fi
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
      echo "target=$expected_goos/$expected_goarch"
      uname -a
      "$pkg_command" -v
      "$pkg_command" info -e "$package_name" || :
      package_installed=1
      as_root "$pkg_command" add -f "$package"
      as_root "$pkg_command" info -e "$package_name"
      /usr/local/bin/leaguebridge status
      test -x /usr/local/libexec/leaguebridge/linux-bsd-client-smoke.sh
      test -x /usr/local/libexec/leaguebridge/linux-bsd-remote-session.sh
      /usr/local/bin/leaguebridge manifest verify
      as_root "$pkg_command" delete -y "$package_name"
      remove_owned_doc_directory
      assert_uninstalled
      package_installed=0
      echo 'install=pass'
      echo 'uninstall=pass'
      hash_package "$package"
    } > "$evidence" 2>&1
    ;;
  openbsd)
    {
      echo "package=$family"
      echo "version=$version"
      echo "filename=$(basename "$package")"
      echo "target=$expected_goos/$expected_goarch"
      uname -a
      pkg_add -V
      package_installed=1
      as_root pkg_add -D unsigned -I "$package"
      as_root pkg_info -e "$installed_package_name"
      /usr/local/bin/leaguebridge status
      test -x /usr/local/libexec/leaguebridge/linux-bsd-client-smoke.sh
      test -x /usr/local/libexec/leaguebridge/linux-bsd-remote-session.sh
      /usr/local/bin/leaguebridge manifest verify
      as_root pkg_delete -I "$installed_package_name"
      remove_owned_doc_directory
      assert_uninstalled
      package_installed=0
      echo 'package-signature=unsigned-ci-only'
      echo 'install=pass'
      echo 'uninstall=pass'
      hash_package "$package"
    } > "$evidence" 2>&1
    ;;
  netbsd)
    {
      echo "package=$family"
      echo "version=$version"
      echo "filename=$(basename "$package")"
      echo "target=$expected_goos/$expected_goarch"
      uname -a
      pkg_add -V
      package_installed=1
      as_root pkg_add "$package"
      as_root pkg_info -e "$package_name"
      /usr/local/bin/leaguebridge status
      test -x /usr/local/libexec/leaguebridge/linux-bsd-client-smoke.sh
      test -x /usr/local/libexec/leaguebridge/linux-bsd-remote-session.sh
      /usr/local/bin/leaguebridge manifest verify
      as_root pkg_delete -f "$package_name"
      remove_owned_doc_directory
      assert_uninstalled
      package_installed=0
      echo 'install=pass'
      echo 'uninstall=pass'
      hash_package "$package"
    } > "$evidence" 2>&1
    ;;
esac

echo "native BSD package smoke passed for $expected_goos/$family $version"
