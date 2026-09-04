// Package packageinfo defines the canonical inventory embedded in every
// LeagueBridge release archive. The inventory describes artifact integrity;
// it is deliberately not runtime-support evidence.
package packageinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/releaseversion"
	"github.com/Yunushan/leaguebridge/internal/target"
)

const (
	// ManifestName is the exact archive member used for the package inventory.
	ManifestName               = "PACKAGE-MANIFEST.json"
	SchemaID                   = "https://github.com/Yunushan/leaguebridge/schemas/package-manifest.schema.json"
	SchemaVersion              = 3
	ValidationScope            = "artifact-integrity-only"
	MinimumSupportedGoVersion  = "go1.25.12"
	ProductionBuilderGoVersion = "go1.27.0"
	// ProductionDependency* is the sole compiled third-party module admitted
	// by the production release contract. Vendored builds may omit the module
	// sum from Go build information; release verification restores this pinned
	// sum only after the path, version, and absence of a replacement match.
	ProductionDependencyPath           = "filippo.io/edwards25519"
	ProductionDependencyVersion        = "v1.2.0"
	ProductionDependencySum            = "h1:crnVqOiS4jqYleHd9vaKZ+HKtHfllngJIiOpNpoJsjo="
	ProductionDependencyLicense        = "BSD-3-Clause"
	ProductionDependencyIdentity       = ProductionDependencyPath + "@" + ProductionDependencyVersion + "#" + ProductionDependencySum
	ProductionDependencyLicenseComment = "BSD-3-Clause is the pinned upstream module license; license conclusion and copyright were not independently analyzed."
	minimumEpoch                       = int64(315532800)
	maximumEpoch                       = int64(4354819199)
)

// Manifest is a reproducible, target-bound inventory for a release archive.
type Manifest struct {
	Schema          string        `json:"$schema"`
	SchemaVersion   int           `json:"schema_version"`
	Name            string        `json:"name"`
	Version         string        `json:"version"`
	Target          Target        `json:"target"`
	Artifact        Artifact      `json:"artifact"`
	Provenance      Provenance    `json:"provenance"`
	ValidationScope string        `json:"validation_scope"`
	DefaultPrefix   string        `json:"default_prefix"`
	MetadataPath    string        `json:"metadata_install_path"`
	Payload         []PayloadFile `json:"payload"`
}

type Target struct {
	GOOS           string `json:"goos"`
	GOARCH         string `json:"goarch"`
	RequiredKernel string `json:"required_kernel"`
}

type Artifact struct {
	Filename string `json:"filename"`
	Format   string `json:"format"`
}

type Provenance struct {
	SourceCommit     string           `json:"source_commit"`
	SourceTree       string           `json:"source_tree"`
	SourceDateEpoch  int64            `json:"source_date_epoch"`
	BuilderGoVersion string           `json:"builder_go_version"`
	BuildEnvironment BuildEnvironment `json:"build_environment"`
}

// BuildEnvironment records the release-affecting Go environment which is
// fixed by scripts/release.sh. Architecture-specific tuning is explicit: only
// the setting applicable to the target is populated.
type BuildEnvironment struct {
	CGOEnabled   string `json:"cgo_enabled"`
	GOENV        string `json:"goenv"`
	GOFLAGS      string `json:"goflags"`
	GOEXPERIMENT string `json:"goexperiment"`
	GOFIPS140    string `json:"gofips140"`
	GOCACHEPROG  string `json:"gocacheprog"`
	GOExtlink    string `json:"go_extlink_enabled"`
	GOTOOLCHAIN  string `json:"gotoolchain"`
	GOWORK       string `json:"gowork"`
	GOAMD64      string `json:"goamd64"`
	GOARM64      string `json:"goarm64"`
	GO111MODULE  string `json:"go111module"`
	GOPROXY      string `json:"goproxy"`
	GONOPROXY    string `json:"gonoproxy"`
	GOSUMDB      string `json:"gosumdb"`
	GONOSUMDB    string `json:"gonosumdb"`
	GOVCS        string `json:"govcs"`
	GOPRIVATE    string `json:"goprivate"`
}

type PayloadFile struct {
	ArchivePath string `json:"archive_path"`
	InstallPath string `json:"install_path"`
	Role        string `json:"role"`
	Mode        string `json:"mode"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
}

// Build creates the exact manifest for the supplied archive payload. The map
// must contain every expected non-manifest member and no additional member.
func Build(version, goos, goarch string, epoch int64, commit, tree, builderGoVersion string, bodies map[string][]byte) (Manifest, error) {
	spec, err := targetSpecFor(version, goos, goarch)
	if err != nil {
		return Manifest{}, err
	}
	if epoch < minimumEpoch || epoch > maximumEpoch {
		return Manifest{}, errors.New("source date epoch must be representable by release archive timestamps (1980 through 2107)")
	}
	if !validCommit(commit) {
		return Manifest{}, errors.New("source commit must be a 40- or 64-character lowercase hexadecimal object ID")
	}
	if !validCommit(tree) {
		return Manifest{}, errors.New("source tree must be a 40- or 64-character lowercase hexadecimal object ID")
	}
	if !validGoVersion(builderGoVersion) {
		return Manifest{}, errors.New("builder Go version must use canonical go1.x.y form")
	}
	if len(bodies) != len(spec.files) {
		return Manifest{}, fmt.Errorf("payload has %d files; want %d", len(bodies), len(spec.files))
	}

	payload := make([]PayloadFile, 0, len(spec.files))
	for _, file := range spec.files {
		body, ok := bodies[file.archivePath]
		if !ok {
			return Manifest{}, fmt.Errorf("payload is missing %q", file.archivePath)
		}
		digest := sha256.Sum256(body)
		payload = append(payload, PayloadFile{
			ArchivePath: file.archivePath,
			InstallPath: file.installPath,
			Role:        file.role,
			Mode:        file.mode,
			Size:        int64(len(body)),
			SHA256:      hex.EncodeToString(digest[:]),
		})
	}

	return Manifest{
		Schema:        SchemaID,
		SchemaVersion: SchemaVersion,
		Name:          "leaguebridge",
		Version:       version,
		Target:        Target{GOOS: goos, GOARCH: goarch, RequiredKernel: spec.nativeKernel},
		Artifact:      Artifact{Filename: spec.filename, Format: spec.format},
		Provenance: Provenance{
			SourceCommit:     commit,
			SourceTree:       tree,
			SourceDateEpoch:  epoch,
			BuilderGoVersion: builderGoVersion,
			BuildEnvironment: buildEnvironmentFor(goarch),
		},
		ValidationScope: ValidationScope,
		DefaultPrefix:   spec.defaultPrefix,
		MetadataPath:    spec.metadataPath,
		Payload:         payload,
	}, nil
}

// Marshal returns the canonical bytes stored in the release archive.
func Marshal(manifest Manifest) ([]byte, error) {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ExpectedPayloadNames returns the exact ordered non-manifest members for a
// target. The order is lexical so it also matches canonical archive order.
func ExpectedPayloadNames(goos, goarch string) ([]string, error) {
	spec, err := targetSpecFor("v0.0.0", goos, goarch)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(spec.files))
	for _, file := range spec.files {
		names = append(names, file.archivePath)
	}
	return names, nil
}

type fileSpec struct {
	archivePath string
	installPath string
	role        string
	mode        string
}

type targetSpec struct {
	filename      string
	format        string
	nativeKernel  string
	defaultPrefix string
	metadataPath  string
	files         []fileSpec
}

func targetSpecFor(version, goos, goarch string) (targetSpec, error) {
	if !releaseversion.Valid(version) {
		return targetSpec{}, errors.New("version must be a valid v-prefixed Semantic Version")
	}
	kernels := map[string]string{
		"linux":     "Linux",
		"freebsd":   "FreeBSD",
		"openbsd":   "OpenBSD",
		"netbsd":    "NetBSD",
		"dragonfly": "DragonFly",
	}
	if !target.IsSupported(goos, goarch) {
		if _, ok := kernels[goos]; !ok {
			return targetSpec{}, fmt.Errorf("unsupported operating system %q", goos)
		}
		return targetSpec{}, fmt.Errorf("unsupported target %s/%s", goos, goarch)
	}
	kernel, ok := kernels[goos]
	if !ok {
		return targetSpec{}, fmt.Errorf("unsupported operating system %q", goos)
	}

	base := "leaguebridge_" + strings.TrimPrefix(version, "v") + "_" + goos + "_" + goarch
	prefix := "/usr/local"
	doc := prefix + "/share/doc/leaguebridge/"
	files := []fileSpec{
		{archivePath: "LICENSE", installPath: doc + "LICENSE", role: "license", mode: "0644"},
		{archivePath: "README.md", installPath: doc + "README.md", role: "documentation", mode: "0644"},
		{archivePath: "SBOM.spdx.json", installPath: doc + "SBOM.spdx.json", role: "sbom", mode: "0644"},
		{archivePath: "install.sh", role: "installer", mode: "0755"},
		{archivePath: "leaguebridge", installPath: prefix + "/bin/leaguebridge", role: "executable", mode: "0755"},
		{archivePath: "linux-bsd-client-smoke.sh", installPath: prefix + "/libexec/leaguebridge/linux-bsd-client-smoke.sh", role: "client-smoke-helper", mode: "0755"},
		{archivePath: "linux-bsd-remote-session.sh", installPath: prefix + "/libexec/leaguebridge/linux-bsd-remote-session.sh", role: "remote-session-helper", mode: "0755"},
		{archivePath: "uninstall.sh", installPath: prefix + "/libexec/leaguebridge/uninstall.sh", role: "uninstaller", mode: "0755"},
	}
	sort.Slice(files, func(i, j int) bool { return files[i].archivePath < files[j].archivePath })
	return targetSpec{
		filename:      base + ".tar.gz",
		format:        "tar.gz",
		nativeKernel:  kernel,
		defaultPrefix: prefix,
		metadataPath:  doc + ManifestName,
		files:         files,
	}, nil
}

func buildEnvironmentFor(goarch string) BuildEnvironment {
	environment := BuildEnvironment{
		CGOEnabled:   "0",
		GOENV:        "off",
		GOFLAGS:      "",
		GOEXPERIMENT: "",
		GOFIPS140:    "off",
		GOCACHEPROG:  "",
		GOExtlink:    "0",
		GOTOOLCHAIN:  "local",
		GOWORK:       "off",
		GO111MODULE:  "on",
		GOPROXY:      "off",
		GONOPROXY:    "",
		GOSUMDB:      "off",
		GONOSUMDB:    "",
		GOVCS:        "*:off",
		GOPRIVATE:    "",
	}
	if goarch == "amd64" {
		environment.GOAMD64 = "v1"
	} else if goarch == "arm64" {
		environment.GOARM64 = "v8.0"
	}
	return environment
}

func validCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for index := range value {
		if !strings.ContainsRune("0123456789abcdef", rune(value[index])) {
			return false
		}
	}
	return true
}

func validGoVersion(value string) bool {
	if len(value) < len("go1.0.0") || len(value) > 32 || !strings.HasPrefix(value, "go1.") {
		return false
	}
	for index := len("go1."); index < len(value); index++ {
		character := value[index]
		if (character < '0' || character > '9') && character != '.' {
			return false
		}
	}
	parts := strings.Split(strings.TrimPrefix(value, "go"), ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
	}
	return true
}
