#!/bin/sh
set -eu
set -f

export LC_ALL=C
umask 022

program=leaguebridge
if [ "${PREFIX+x}" = x ]; then
	prefix=$PREFIX
else
	prefix=/usr/local
fi
destdir=${DESTDIR-}
install_temporary=

fail() {
	printf '%s\n' "install.sh: $*" >&2
	exit 1
}

if [ "$#" -ne 0 ]; then
	fail "positional arguments are not accepted; set PREFIX and DESTDIR in the environment"
fi

cleanup() {
	if [ -n "$install_temporary" ]; then
		if [ -L "$install_temporary" ] || [ -f "$install_temporary" ]; then
			rm -f "$install_temporary" 2>/dev/null || :
		fi
	fi
}

trap cleanup 0
trap 'exit 1' 1 2 3 15

validate_absolute_path() {
	path_label=$1
	path_value=$2
	case "$path_value" in
	/*) ;;
	*) fail "$path_label must be an absolute path" ;;
	esac
	case "$path_value" in
	/|*/|*//*|*/./*|*/../*|*/.|*/..)
		fail "$path_label must be normalized, non-root, and contain no dot components"
		;;
	esac
	case "$path_value" in
	*[!A-Za-z0-9_./+-]*)
		fail "$path_label contains unsupported characters"
		;;
	esac
	if [ "${#path_value}" -gt 1024 ]; then
		fail "$path_label exceeds 1024 bytes"
	fi
}

validate_absolute_path PREFIX "$prefix"
if [ -n "$destdir" ]; then
	validate_absolute_path DESTDIR "$destdir"
fi

script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || fail "cannot resolve the archive directory"
source_binary=$script_dir/$program
source_readme=$script_dir/README.md
source_license=$script_dir/LICENSE
source_sbom=$script_dir/SBOM.spdx.json
source_package_manifest=$script_dir/PACKAGE-MANIFEST.json
source_uninstaller=$script_dir/uninstall.sh

require_regular_source() {
	source_path=$1
	if [ -L "$source_path" ] || [ ! -f "$source_path" ]; then
		fail "required archive member is not a regular, non-symlink file: $source_path"
	fi
}

require_regular_source "$source_binary"
require_regular_source "$source_readme"
require_regular_source "$source_license"
require_regular_source "$source_sbom"
require_regular_source "$source_package_manifest"
require_regular_source "$source_uninstaller"

install_root=$destdir$prefix
binary_dir=$install_root/bin
documentation_dir=$install_root/share/doc/$program
helper_dir=$install_root/libexec/$program

# Create one exact directory component at a time and refuse every symlink or
# non-directory in the destination path. This avoids mkdir -p following a
# pre-existing redirected component during a privileged install.
ensure_directory_tree() {
	tree_path=$1
	tree_rest=${tree_path#/}
	tree_current=
	tree_old_ifs=$IFS
	IFS=/
	set -- $tree_rest
	IFS=$tree_old_ifs
	for tree_component do
		[ -n "$tree_component" ] || fail "invalid empty directory component in $tree_path"
		tree_current=$tree_current/$tree_component
		if [ -L "$tree_current" ]; then
			fail "destination directory component is a symlink: $tree_current"
		fi
		if [ -e "$tree_current" ]; then
			[ -d "$tree_current" ] || fail "destination component is not a directory: $tree_current"
		else
			mkdir "$tree_current" || fail "cannot create directory: $tree_current"
		fi
	done
}

ensure_directory_tree "$binary_dir"
ensure_directory_tree "$documentation_dir"
ensure_directory_tree "$helper_dir"

new_temporary() {
	temporary_destination=$1
	temporary_attempt=0
	while [ "$temporary_attempt" -lt 100 ]; do
		install_temporary=$temporary_destination.leaguebridge-new.$$.${temporary_attempt}
		if [ ! -e "$install_temporary" ] && [ ! -L "$install_temporary" ]; then
			if (umask 077; set -C; : > "$install_temporary") 2>/dev/null; then
				return 0
			fi
		fi
		temporary_attempt=$((temporary_attempt + 1))
	done
	fail "cannot allocate a temporary file beside $temporary_destination"
}

install_file() {
	install_source=$1
	install_destination=$2
	install_mode=$3

	if [ -L "$install_destination" ]; then
		fail "refusing to replace destination symlink: $install_destination"
	fi
	if [ -e "$install_destination" ] && [ ! -f "$install_destination" ]; then
		fail "refusing to replace non-regular destination: $install_destination"
	fi

	new_temporary "$install_destination"
	cp "$install_source" "$install_temporary" || fail "cannot copy $install_source"
	chmod "$install_mode" "$install_temporary" || fail "cannot set mode on $install_temporary"

	# Recheck the final object immediately before rename. mv replaces a regular
	# file atomically on the same filesystem, which provides deterministic
	# install and upgrade behavior without following a final symlink.
	if [ -L "$install_destination" ]; then
		fail "destination became a symlink during install: $install_destination"
	fi
	if [ -e "$install_destination" ] && [ ! -f "$install_destination" ]; then
		fail "destination became non-regular during install: $install_destination"
	fi
	mv -f "$install_temporary" "$install_destination" || fail "cannot publish $install_destination"
	install_temporary=
}

install_file "$source_binary" "$binary_dir/$program" 0755
install_file "$source_uninstaller" "$helper_dir/uninstall.sh" 0755
install_file "$source_readme" "$documentation_dir/README.md" 0644
install_file "$source_license" "$documentation_dir/LICENSE" 0644
install_file "$source_sbom" "$documentation_dir/SBOM.spdx.json" 0644
install_file "$source_package_manifest" "$documentation_dir/PACKAGE-MANIFEST.json" 0644

printf '%s\n' "Installed LeagueBridge under $install_root"
printf '%s\n' "Binary: $binary_dir/$program"
printf '%s\n' "Uninstall: DESTDIR=$destdir PREFIX=$prefix $helper_dir/uninstall.sh"
