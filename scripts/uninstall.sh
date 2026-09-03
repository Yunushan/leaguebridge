#!/bin/sh
set -eu
set -f

export LC_ALL=C

program=leaguebridge

fail() {
	printf '%s\n' "uninstall.sh: $*" >&2
	exit 1
}

if [ "$#" -ne 0 ]; then
	fail "positional arguments are not accepted; set PREFIX and DESTDIR in the environment"
fi
if [ "${PREFIX+x}" != x ]; then
	fail "PREFIX must be explicitly set in the environment"
fi
if [ "${DESTDIR+x}" != x ]; then
	fail "DESTDIR must be explicitly set in the environment (it may be empty)"
fi
prefix=$PREFIX
destdir=$DESTDIR

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

install_root=$destdir$prefix
binary_dir=$install_root/bin
documentation_dir=$install_root/share/doc/$program
helper_dir=$install_root/libexec/$program

# Inspect existing parents one component at a time. If an installed directory
# was replaced with a symlink, abort before touching a path below it.
check_directory_tree() {
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
			fail "installed directory component is a symlink: $tree_current"
		fi
		if [ -e "$tree_current" ]; then
			[ -d "$tree_current" ] || fail "installed path component is not a directory: $tree_current"
		else
			return 0
		fi
	done
}

check_directory_tree "$binary_dir"
check_directory_tree "$documentation_dir"
check_directory_tree "$helper_dir"

remove_file() {
	remove_path=$1
	if [ -L "$remove_path" ] || [ -f "$remove_path" ]; then
		rm -f "$remove_path" || fail "cannot remove $remove_path"
		if [ -L "$remove_path" ] || [ -e "$remove_path" ]; then
			fail "installed path remains after removal: $remove_path"
		fi
		return 0
	fi
	if [ -e "$remove_path" ]; then
		fail "refusing to remove non-file installed path: $remove_path"
	fi
}

# Remove only the exact files owned by LeagueBridge. A replaced final symlink
# is unlinked directly; it is never followed. No recursive deletion is used.
remove_file "$binary_dir/$program"
remove_file "$documentation_dir/README.md"
remove_file "$documentation_dir/LICENSE"
remove_file "$documentation_dir/SBOM.spdx.json"
remove_file "$documentation_dir/PACKAGE-MANIFEST.json"
remove_file "$helper_dir/linux-bsd-client-smoke.sh"
remove_file "$helper_dir/linux-bsd-remote-session.sh"
remove_file "$helper_dir/uninstall.sh"

# Remove only LeagueBridge-specific directories and only when they are empty.
# Shared prefix, bin, libexec, share, and share/doc directories are preserved.
if [ -d "$documentation_dir" ] && [ ! -L "$documentation_dir" ]; then
	rmdir "$documentation_dir" 2>/dev/null || :
fi
if [ -d "$helper_dir" ] && [ ! -L "$helper_dir" ]; then
	rmdir "$helper_dir" 2>/dev/null || :
fi

printf '%s\n' "Removed LeagueBridge files from $install_root"
