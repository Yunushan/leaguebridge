#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C
export GIT_NO_REPLACE_OBJECTS=1
export GIT_CONFIG_NOSYSTEM=1
export GIT_ATTR_NOSYSTEM=1
export GIT_CONFIG_COUNT=0
unset GIT_ATTR_SOURCE GIT_CONFIG_PARAMETERS
export GOENV=off
export GOWORK=off
export GOFLAGS=
export GOEXPERIMENT=
export GOFIPS140=off
export GOCACHEPROG=
export GO_EXTLINK_ENABLED=0
export GOTOOLCHAIN=local
export GO111MODULE=on
export GOPROXY=off
export GONOPROXY=
export GOSUMDB=off
export GONOSUMDB=
export GOVCS='*:off'
export GOPRIVATE=
export CGO_ENABLED=0
export GOAMD64=v1

scratch="$(mktemp -d)"
cleanup() {
  if [[ -n "${scratch:-}" && -e "$scratch" && ! -L "$scratch" ]]; then
    rm -rf -- "$scratch"
  fi
}
trap cleanup EXIT
export GOPATH="$scratch/gopath"
export GOMODCACHE="$GOPATH/pkg/mod"
export GOCACHE="$scratch/gocache"
export GOTMPDIR="$scratch/go-tmp"
mkdir -p "$GOMODCACHE" "$GOCACHE" "$GOTMPDIR"

# Establish the same Git boundary as release.sh before deriving the default
# epoch, commit, or tree used to verify the two builds.
release_git_config="$scratch/empty-git-config"
release_git_attributes="$scratch/empty-git-attributes"
: >"$release_git_config"
: >"$release_git_attributes"
export GIT_CONFIG_SYSTEM="$release_git_config"
export GIT_CONFIG_GLOBAL="$release_git_config"
release_git() {
  command git --no-replace-objects -c core.attributesFile="$release_git_attributes" "$@"
}

repository_root="$(cd "$(release_git rev-parse --show-toplevel)" && pwd -P)"
cd "$repository_root"
info_attributes="$(release_git rev-parse --git-path info/attributes)"
if [[ -e "$info_attributes" || -L "$info_attributes" ]]; then
  echo "reproducibility checks refuse out-of-tree Git attributes at $info_attributes" >&2
  exit 2
fi

version="${VERSION:-v0.0.0-test}"
if [[ -z "${SOURCE_DATE_EPOCH:-}" || ! "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]]; then
  SOURCE_DATE_EPOCH="$(release_git show -s --format=%ct HEAD)"
fi
export VERSION="$version" SOURCE_DATE_EPOCH
commit="$(release_git rev-parse HEAD)"
if [[ -n "${GITHUB_SHA:-}" ]]; then
  commit="$(release_git rev-parse --verify "${GITHUB_SHA}^{commit}")"
fi
tree="$(release_git rev-parse "${commit}^{tree}")"
builder_go_version="$(go env GOVERSION)"

bash scripts/release.sh
go run -mod=vendor ./tools/releasecheck -dir dist -version "$version" -source-date-epoch "$SOURCE_DATE_EPOCH" -commit "$commit" -tree "$tree" -builder-go-version "$builder_go_version"
(cd dist && sha256sum --check checksums.txt)
sh scripts/verify-install.sh "dist/leaguebridge_${version#v}_linux_amd64.tar.gz" "$version" linux amd64
cp dist/checksums.txt "$scratch/first-checksums.txt"
first_manifest="$(sha256sum dist/checksums.txt)"

bash scripts/release.sh
go run -mod=vendor ./tools/releasecheck -dir dist -version "$version" -source-date-epoch "$SOURCE_DATE_EPOCH" -commit "$commit" -tree "$tree" -builder-go-version "$builder_go_version"
(cd dist && sha256sum --check checksums.txt)
sh scripts/verify-install.sh "dist/leaguebridge_${version#v}_linux_amd64.tar.gz" "$version" linux amd64
if ! cmp --silent "$scratch/first-checksums.txt" dist/checksums.txt; then
  echo "release checksum manifest changed between identical builds" >&2
  exit 1
fi
second_manifest="$(sha256sum dist/checksums.txt)"

if [[ "$first_manifest" != "$second_manifest" ]]; then
  echo "release checksum manifest changed between identical builds" >&2
  exit 1
fi

echo "release archives are reproducible for $VERSION at epoch $SOURCE_DATE_EPOCH"
