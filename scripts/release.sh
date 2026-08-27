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
export GOARM64=v8.0
unset GODEBUG
umask 022

work_root="$(mktemp -d)"
cleanup() {
  rm -rf -- "$work_root"
}
trap cleanup EXIT

# Git has attribute and configuration layers outside the committed tree. Keep
# those layers empty, force replacement objects off for every command, and
# override any repository-local core.attributesFile setting.
release_git_config="$work_root/empty-git-config"
release_git_attributes="$work_root/empty-git-attributes"
: >"$release_git_config"
: >"$release_git_attributes"
export GIT_CONFIG_SYSTEM="$release_git_config"
export GIT_CONFIG_GLOBAL="$release_git_config"
release_git() {
  command git --no-replace-objects -c core.attributesFile="$release_git_attributes" "$@"
}

repository_root="$(cd "$(release_git rev-parse --show-toplevel)" && pwd -P)"
cd "$repository_root"

# There is no Git switch that disables $GIT_DIR/info/attributes. Refuse the
# layer entirely so only attributes committed in the bound tree can affect the
# archive. The symlink check also catches a dangling attributes path.
info_attributes="$(release_git rev-parse --git-path info/attributes)"
if [[ -e "$info_attributes" || -L "$info_attributes" ]]; then
  echo "release builds refuse out-of-tree Git attributes at $info_attributes" >&2
  exit 2
fi

required_builder_go_version=go1.27.0
builder_go_version="$(go env GOVERSION)"
if [[ "$builder_go_version" != "$required_builder_go_version" ]]; then
  echo "release builds require Go $required_builder_go_version exactly; found $builder_go_version" >&2
  exit 2
fi

export GOPATH="$work_root/gopath"
export GOMODCACHE="$GOPATH/pkg/mod"
export GOCACHE="$work_root/gocache"
mkdir -p "$GOMODCACHE" "$GOCACHE"

if [[ -z "${SOURCE_DATE_EPOCH:-}" || ! "$SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$ ]]; then
  echo "SOURCE_DATE_EPOCH must be provided as positive canonical decimal seconds without leading zeros" >&2
  exit 2
fi
if ! build_date="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"; then
  echo "SOURCE_DATE_EPOCH is outside the range supported by the release tooling" >&2
  exit 2
fi
build_year="${build_date%%-*}"
if (( 10#$build_year < 1980 || 10#$build_year > 2107 )); then
  echo "SOURCE_DATE_EPOCH must be representable by the release formats (years 1980 through 2107)" >&2
  exit 2
fi
export SOURCE_DATE_EPOCH

head_commit="$(release_git rev-parse --verify HEAD)"
commit="$head_commit"
if [[ -n "${GITHUB_SHA:-}" ]]; then
  if ! commit="$(release_git rev-parse --verify "${GITHUB_SHA}^{commit}")"; then
    echo "GITHUB_SHA does not peel to a commit" >&2
    exit 2
  fi
fi
if [[ ! "$commit" =~ ^[0-9a-f]{40}$ && ! "$commit" =~ ^[0-9a-f]{64}$ ]]; then
  echo "release commit must be a 40- or 64-character lowercase hexadecimal object ID" >&2
  exit 2
fi
if [[ "$commit" != "$head_commit" ]]; then
  echo "release commit does not match the checked-out HEAD" >&2
  exit 2
fi
tree="$(release_git rev-parse --verify "${commit}^{tree}")"
if [[ ! "$tree" =~ ^[0-9a-f]{40}$ && ! "$tree" =~ ^[0-9a-f]{64}$ ]]; then
  echo "release tree must be a 40- or 64-character lowercase hexadecimal object ID" >&2
  exit 2
fi
if [[ -n "$(release_git status --porcelain --untracked-files=normal)" ]]; then
  echo "release builds require a clean Git worktree" >&2
  exit 2
fi

# Keep the exported-tree contract auditable. Gitlinks are not materialized by
# git archive, symlinks can escape the private snapshot, and export attributes
# can omit or rewrite bytes relative to the bound tree object.
while IFS= read -r -d '' tree_entry; do
  tree_metadata="${tree_entry%%$'\t'*}"
  tree_path="${tree_entry#*$'\t'}"
  tree_mode="${tree_metadata%% *}"
  case "$tree_mode" in
    120000)
      echo "release source tree contains a symbolic link: $tree_path" >&2
      exit 2
      ;;
    160000)
      echo "release source tree contains a gitlink/submodule: $tree_path" >&2
      exit 2
      ;;
  esac
  case "$tree_path" in
    vendor/github.com/santhosh-tekuri/jsonschema/v6/.gitmodules)
      # Go 1.27 vendors this inert upstream metadata file. The snapshot-local
      # vendorcheck below binds its exact path and bytes before any build.
      ;;
    .gitmodules|*/.gitmodules)
      echo "release source tree contains .gitmodules: $tree_path" >&2
      exit 2
      ;;
    .gitattributes|*/.gitattributes)
      attribute_data="$(release_git cat-file blob "$commit:$tree_path")"
      if grep -Eq '(^|[[:space:]])[-!]?export-(ignore|subst)(=[^[:space:]]+)?([[:space:]]|$)' <<<"$attribute_data"; then
        echo "release source tree contains archive-affecting export-ignore/export-subst attributes: $tree_path" >&2
        exit 2
      fi
      ;;
  esac
done < <(release_git ls-tree -r -z "$commit")

snapshot_archive="$work_root/source.tar"
snapshot_root="$work_root/source"
mkdir -p "$snapshot_root"
release_git archive --format=tar --output="$snapshot_archive" "$commit"
tar -xf "$snapshot_archive" -C "$snapshot_root"

(cd "$snapshot_root" && go run -mod=vendor ./tools/vendorcheck -root .)
if [[ -z "${VERSION:-}" ]] || ! (cd "$snapshot_root" && go run -mod=vendor ./tools/versioncheck "$VERSION"); then
  echo "VERSION must be a valid Semantic Version beginning with v" >&2
  exit 2
fi
(cd "$snapshot_root" && go run -mod=vendor ./tools/readinesscheck -root .)
readiness_scorecard_sha256="$(sha256sum "$snapshot_root/readiness/scorecard.json")"
readiness_scorecard_sha256="${readiness_scorecard_sha256%% *}"
if [[ ! "$readiness_scorecard_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "verified readiness scorecard did not produce a canonical SHA-256 digest" >&2
  exit 2
fi
repository_evidence_verification="leaguebridge-repository-evidence-v1:$readiness_scorecard_sha256"

release_output_dir="$repository_root/dist"
if [[ -L "$release_output_dir" ]] || [[ -e "$release_output_dir" && ! -d "$release_output_dir" ]]; then
  echo "dist must be absent or a non-symlink directory" >&2
  exit 2
fi
rm -rf -- "$release_output_dir"
mkdir -p "$release_output_dir"

targets=(
  linux/amd64
  freebsd/amd64
  openbsd/amd64
  netbsd/amd64
  dragonfly/amd64
  windows/amd64
  darwin/amd64
  darwin/arm64
)

for target in "${targets[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  name="leaguebridge_${VERSION#v}_${goos}_${goarch}"
  pack_stage="$work_root/package-$goos-$goarch"
  mkdir -p "$pack_stage"
  binary_name=leaguebridge
  if [[ "$goos" == windows ]]; then
    binary_name=leaguebridge.exe
  fi
  binary="$pack_stage/$binary_name"

  target_tuning=goamd64=v1
  if [[ "$goarch" == arm64 ]]; then
    target_tuning=goarm64=v8.0
  fi
  release_identity="leaguebridge-release:$VERSION:$goos:$goarch"
  release_contract="leaguebridge-release-contract-v4|$VERSION|$goos|$goarch|$SOURCE_DATE_EPOCH|$commit|$tree|$builder_go_version|$target_tuning|filippo.io/edwards25519@v1.2.0#h1:crnVqOiS4jqYleHd9vaKZ+HKtHfllngJIiOpNpoJsjo="
  contract_hash="$(printf '%s' "$release_contract" | sha256sum)"
  contract_hash="${contract_hash%% *}"
  build_id="leaguebridge-build-v4-$contract_hash"
  ldflags="-s -w -buildid=$build_id -X github.com/Yunushan/leaguebridge/internal/version.Version=$VERSION -X github.com/Yunushan/leaguebridge/internal/version.Commit=$commit -X github.com/Yunushan/leaguebridge/internal/version.BuildDate=$build_date -X github.com/Yunushan/leaguebridge/internal/version.ReleaseIdentity=$release_identity -X github.com/Yunushan/leaguebridge/internal/version.RepositoryEvidenceVerification=$repository_evidence_verification"

  (
    cd "$snapshot_root"
    GOOS="$goos" GOARCH="$goarch" go build -mod=vendor -trimpath -buildvcs=false -ldflags "$ldflags" -o "$binary" ./cmd/leaguebridge
    go run -mod=vendor ./tools/sbom -binary "$binary" -version "$VERSION" -os "$goos" -arch "$goarch" -output "$pack_stage/SBOM.spdx.json"
  )
  cp "$snapshot_root/LICENSE" "$snapshot_root/README.md" "$pack_stage/"
  chmod 0755 "$binary"
  chmod 0644 "$pack_stage/SBOM.spdx.json" "$pack_stage/LICENSE" "$pack_stage/README.md"

  if [[ "$goos" != windows ]]; then
    cp "$snapshot_root/scripts/install.sh" "$snapshot_root/scripts/uninstall.sh" "$pack_stage/"
    chmod 0755 "$pack_stage/install.sh" "$pack_stage/uninstall.sh"
  fi

  (
    cd "$snapshot_root"
    go run -mod=vendor ./tools/packagemanifest \
      -version "$VERSION" \
      -os "$goos" \
      -arch "$goarch" \
      -source-date-epoch "$SOURCE_DATE_EPOCH" \
      -commit "$commit" \
      -tree "$tree" \
      -builder-go-version "$builder_go_version" \
      -root "$pack_stage" \
      -output "$pack_stage/PACKAGE-MANIFEST.json"
  )
  chmod 0644 "$pack_stage/PACKAGE-MANIFEST.json"

  if [[ "$goos" == windows ]]; then
    (cd "$snapshot_root" && go run -mod=vendor ./tools/canonicalzip -root "$pack_stage" -output "$release_output_dir/$name.zip" -source-date-epoch "$SOURCE_DATE_EPOCH")
  else
    (cd "$snapshot_root" && go run -mod=vendor ./tools/canonicaltar -root "$pack_stage" -output "$release_output_dir/$name.tar.gz" -source-date-epoch "$SOURCE_DATE_EPOCH")
  fi
done

(cd "$release_output_dir" && sha256sum --binary ./*.tar.gz ./*.zip > checksums.txt)
(cd "$snapshot_root" && go run -mod=vendor ./tools/releasecheck -dir "$release_output_dir" -version "$VERSION" -source-date-epoch "$SOURCE_DATE_EPOCH" -commit "$commit" -tree "$tree" -builder-go-version "$builder_go_version")

printf '%s\n' "created and verified eight release archives for $VERSION from commit $commit tree $tree"
