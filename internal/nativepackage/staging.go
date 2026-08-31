// Package nativepackage prepares a portable LeagueBridge release archive for
// an optional operating-system package builder. It deliberately stops at a
// content-addressed staging tree; package-manager output and native runtime
// evidence are separate concerns.
package nativepackage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/exactjson"
	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
	"github.com/Yunushan/leaguebridge/internal/releaseversion"
)

const (
	SchemaID            = "https://github.com/Yunushan/leaguebridge/schemas/native-package-staging.schema.json"
	SchemaVersion       = 1
	ValidationScope     = "staging-integrity-only"
	PackageName         = "leaguebridge"
	StagingManifestName = "NATIVE-PACKAGE-MANIFEST.json"
	MaximumManifestSize = int64(1 << 20)
	MaximumPayloadSize  = int64(128 << 20)
	manifestFilename    = "PACKAGE-MANIFEST.json"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Family identifies the native packaging ecosystem for which a staging tree
// may be handed to a separately governed builder.
type Family string

const (
	FamilyDebian  Family = "debian"
	FamilyRPM     Family = "rpm"
	FamilyFreeBSD Family = "freebsd-pkg"
	FamilyOpenBSD Family = "openbsd-pkg"
	FamilyPkgsrc  Family = "pkgsrc"
	FamilyDPorts  Family = "dports"
)

// SupportedFamilies returns the stable family order used by tooling and
// documentation.
func SupportedFamilies() []Family {
	return []Family{
		FamilyDebian,
		FamilyRPM,
		FamilyFreeBSD,
		FamilyOpenBSD,
		FamilyPkgsrc,
		FamilyDPorts,
	}
}

// Target is the native target copied from the portable package manifest.
type Target struct {
	GOOS           string `json:"goos"`
	GOARCH         string `json:"goarch"`
	RequiredKernel string `json:"required_kernel"`
}

type SourceArtifact struct {
	Filename string `json:"filename"`
	Format   string `json:"format"`
	SHA256   string `json:"sha256"`
}

type Package struct {
	Family       Family `json:"family"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	InstallRoot  string `json:"install_root"`
}

type PayloadFile struct {
	SourcePath  string `json:"source_path"`
	InstallPath string `json:"install_path"`
	Role        string `json:"role"`
	Mode        string `json:"mode"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
}

// Manifest is the exact inventory emitted beside a native package staging
// tree. It never asserts that a package was built, installed, or executed.
type Manifest struct {
	Schema          string         `json:"$schema"`
	SchemaVersion   int            `json:"schema_version"`
	Name            string         `json:"name"`
	Version         string         `json:"version"`
	Target          Target         `json:"target"`
	SourceArtifact  SourceArtifact `json:"source_artifact"`
	Package         Package        `json:"package"`
	ValidationScope string         `json:"validation_scope"`
	Payload         []PayloadFile  `json:"payload"`
}

type familySpec struct {
	family       Family
	goos         string
	goarch       string
	architecture string
	installRoot  string
}

// Build derives a native-package staging manifest from a previously verified
// portable Unix release manifest. sourceManifest must be the exact canonical
// bytes stored in that archive, and archiveSHA256 must cover the complete
// archive bytes.
func Build(source packageinfo.Manifest, sourceManifest []byte, archiveSHA256 string, family Family) (Manifest, error) {
	if len(sourceManifest) == 0 {
		return Manifest{}, errors.New("source package manifest is empty")
	}
	canonicalSource, err := packageinfo.Marshal(source)
	if err != nil {
		return Manifest{}, fmt.Errorf("marshal source package manifest: %w", err)
	}
	if !bytes.Equal(sourceManifest, canonicalSource) {
		return Manifest{}, errors.New("source package manifest is not canonical")
	}
	if !digestPattern.MatchString(archiveSHA256) {
		return Manifest{}, errors.New("source archive digest must be 64 lowercase hexadecimal characters")
	}
	if source.Artifact.Format != "tar.gz" {
		return Manifest{}, errors.New("native package staging accepts Unix tar.gz release archives only")
	}
	spec, err := familySpecFor(family, source.Target.GOOS, source.Target.GOARCH)
	if err != nil {
		return Manifest{}, err
	}
	if err := validateSourcePayload(source); err != nil {
		return Manifest{}, err
	}

	entries := make(map[string]packageinfo.PayloadFile, len(source.Payload))
	for _, entry := range source.Payload {
		entries[entry.ArchivePath] = entry
	}
	staged := make([]PayloadFile, 0, 5)
	for _, path := range []string{"LICENSE", manifestFilename, "README.md", "SBOM.spdx.json", "leaguebridge"} {
		entry := PayloadFile{SourcePath: path, Mode: "0644"}
		switch path {
		case "LICENSE":
			sourceEntry := entries[path]
			entry.Role = "license"
			entry.Size = sourceEntry.Size
			entry.SHA256 = sourceEntry.SHA256
		case manifestFilename:
			entry.Role = "documentation"
			entry.Size = int64(len(sourceManifest))
			digest := sha256.Sum256(sourceManifest)
			entry.SHA256 = hex.EncodeToString(digest[:])
		case "README.md":
			sourceEntry := entries[path]
			entry.Role = "documentation"
			entry.Size = sourceEntry.Size
			entry.SHA256 = sourceEntry.SHA256
		case "SBOM.spdx.json":
			sourceEntry := entries[path]
			entry.Role = "sbom"
			entry.Size = sourceEntry.Size
			entry.SHA256 = sourceEntry.SHA256
		case "leaguebridge":
			sourceEntry := entries[path]
			entry.Role = "executable"
			entry.Mode = "0755"
			entry.Size = sourceEntry.Size
			entry.SHA256 = sourceEntry.SHA256
		}
		entry.InstallPath = stagedInstallPath(path, spec.installRoot)
		staged = append(staged, entry)
	}

	manifest := Manifest{
		Schema:        SchemaID,
		SchemaVersion: SchemaVersion,
		Name:          PackageName,
		Version:       source.Version,
		Target: Target{
			GOOS:           source.Target.GOOS,
			GOARCH:         source.Target.GOARCH,
			RequiredKernel: source.Target.RequiredKernel,
		},
		SourceArtifact: SourceArtifact{
			Filename: source.Artifact.Filename,
			Format:   source.Artifact.Format,
			SHA256:   archiveSHA256,
		},
		Package: Package{
			Family:       spec.family,
			Name:         PackageName,
			Version:      source.Version,
			Architecture: spec.architecture,
			InstallRoot:  spec.installRoot,
		},
		ValidationScope: ValidationScope,
		Payload:         staged,
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Marshal returns the canonical LF-terminated JSON representation.
func Marshal(manifest Manifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Unmarshal strictly decodes the canonical staging manifest. Standard
// encoding/json accepts duplicate and case-insensitive fields; a staging
// verifier must not let either representation hide a different inventory.
func Unmarshal(data []byte) (Manifest, error) {
	if len(data) == 0 || int64(len(data)) > MaximumManifestSize {
		return Manifest{}, fmt.Errorf("native package staging manifest size is outside 1..%d bytes", MaximumManifestSize)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return Manifest{}, fmt.Errorf("decode native package staging manifest: %w", err)
	}
	if err := exactjson.ValidateKeys(data, Manifest{}); err != nil {
		return Manifest{}, fmt.Errorf("native package staging manifest fields are invalid: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode native package staging manifest: %w", err)
	}
	canonical, err := Marshal(manifest)
	if err != nil {
		return Manifest{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Manifest{}, errors.New("native package staging manifest is not canonical")
	}
	return manifest, nil
}

// Validate checks the cross-field invariants which are intentionally kept in
// Go as well as in the public JSON Schema.
func (manifest Manifest) Validate() error {
	if manifest.Schema != SchemaID || manifest.SchemaVersion != SchemaVersion || manifest.Name != PackageName || manifest.ValidationScope != ValidationScope {
		return errors.New("native package staging manifest identity is invalid")
	}
	if !releaseversion.Valid(manifest.Version) {
		return errors.New("native package staging version must be a valid v-prefixed Semantic Version")
	}
	if manifest.SourceArtifact.Format != "tar.gz" || !digestPattern.MatchString(manifest.SourceArtifact.SHA256) || manifest.SourceArtifact.Filename != sourceFilename(manifest.Version, manifest.Target.GOOS, manifest.Target.GOARCH) {
		return errors.New("native package source artifact is invalid")
	}
	if manifest.Target.RequiredKernel != requiredKernel(manifest.Target.GOOS) {
		return errors.New("native package target kernel is not bound to its GOOS")
	}
	if manifest.Package.Name != PackageName || manifest.Package.Version != manifest.Version {
		return errors.New("native package identity is not bound to the source version")
	}
	spec, err := familySpecFor(manifest.Package.Family, manifest.Target.GOOS, manifest.Target.GOARCH)
	if err != nil {
		return err
	}
	if manifest.Package.Architecture != spec.architecture || manifest.Package.InstallRoot != spec.installRoot {
		return errors.New("native package architecture or install root is not target-bound")
	}
	if len(manifest.Payload) != 5 {
		return fmt.Errorf("native package payload has %d files; want 5", len(manifest.Payload))
	}
	for index, path := range []string{"LICENSE", manifestFilename, "README.md", "SBOM.spdx.json", "leaguebridge"} {
		entry := manifest.Payload[index]
		if entry.SourcePath != path || entry.Size < 0 || entry.Size > MaximumPayloadSize || !digestPattern.MatchString(entry.SHA256) {
			return fmt.Errorf("native package payload[%d] is invalid", index)
		}
		if entry.InstallPath != stagedInstallPath(path, spec.installRoot) {
			return fmt.Errorf("native package payload %q has an unexpected install path", path)
		}
		expectedRole, expectedMode := stagedPayloadMetadata(path)
		if entry.Role != expectedRole || entry.Mode != expectedMode {
			return fmt.Errorf("native package payload %q has unexpected role or mode", path)
		}
	}
	return nil
}

func stagedPayloadMetadata(sourcePath string) (role, mode string) {
	switch sourcePath {
	case "LICENSE":
		return "license", "0644"
	case "leaguebridge":
		return "executable", "0755"
	case manifestFilename, "README.md":
		return "documentation", "0644"
	case "SBOM.spdx.json":
		return "sbom", "0644"
	default:
		return "", ""
	}
}

// VerifyStagingRoot verifies the manifest and every byte in a staging tree.
// It is intentionally limited to staging integrity: the returned manifest is
// not evidence that a target package was built, installed, or executed.
func VerifyStagingRoot(root *os.Root) (Manifest, error) {
	if root == nil {
		return Manifest{}, errors.New("native package staging root is nil")
	}
	manifestData, err := fileinput.ReadRegularBoundedFromRoot(root, StagingManifestName, MaximumManifestSize)
	if err != nil {
		return Manifest{}, fmt.Errorf("read %s: %w", StagingManifestName, err)
	}
	manifest, err := Unmarshal(manifestData)
	if err != nil {
		return Manifest{}, err
	}

	expectedFiles := map[string]PayloadFile{}
	expectedDirectories := map[string]struct{}{".": {}}
	for _, entry := range manifest.Payload {
		relative, err := stagingRelativePath(entry.InstallPath)
		if err != nil {
			return Manifest{}, fmt.Errorf("payload %q: %w", entry.SourcePath, err)
		}
		stagedPath := path.Join("root", relative)
		if _, duplicate := expectedFiles[stagedPath]; duplicate {
			return Manifest{}, fmt.Errorf("staging manifest maps multiple payloads to %q", stagedPath)
		}
		expectedFiles[stagedPath] = entry
		for directory := path.Dir(stagedPath); ; directory = path.Dir(directory) {
			expectedDirectories[directory] = struct{}{}
			if directory == "." {
				break
			}
		}
	}
	expectedFiles[StagingManifestName] = PayloadFile{SourcePath: StagingManifestName, InstallPath: "/" + StagingManifestName, Role: "staging-manifest", Mode: "0644", Size: int64(len(manifestData)), SHA256: digest(manifestData)}

	for relative, entry := range expectedFiles {
		data, info, err := readStagedFile(root, relative, MaximumPayloadSize)
		if err != nil {
			return Manifest{}, fmt.Errorf("verify staged file %q: %w", relative, err)
		}
		if int64(len(data)) != entry.Size || info.Size() != entry.Size {
			return Manifest{}, fmt.Errorf("staged file %q size = %d, want %d", relative, len(data), entry.Size)
		}
		// Windows filesystems do not expose the requested POSIX permission bits
		// through os.FileInfo; the manifest still carries the mode for the Unix
		// package builder to apply.
		if entry.Mode != "" && runtime.GOOS != "windows" {
			mode, err := parseStagingMode(entry.Mode)
			if err != nil {
				return Manifest{}, fmt.Errorf("staged file %q: %w", relative, err)
			}
			if info.Mode().Perm() != mode.Perm() {
				return Manifest{}, fmt.Errorf("staged file %q mode = %04o, want %04o", relative, info.Mode().Perm(), mode.Perm())
			}
		}
		if got := digest(data); got != entry.SHA256 {
			return Manifest{}, fmt.Errorf("staged file %q SHA-256 = %s, want %s", relative, got, entry.SHA256)
		}
	}

	if err := verifyStagingTree(root, expectedFiles, expectedDirectories); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func stagingRelativePath(installPath string) (string, error) {
	if !strings.HasPrefix(installPath, "/") || strings.ContainsAny(installPath, "\\\x00\r\n") {
		return "", errors.New("install path must be an absolute slash-separated path")
	}
	relative := strings.TrimPrefix(installPath, "/")
	clean := path.Clean(relative)
	if relative == "" || clean != relative || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", errors.New("install path contains unsafe components")
	}
	return clean, nil
}

func parseStagingMode(raw string) (os.FileMode, error) {
	if raw != "0644" && raw != "0755" {
		return 0, fmt.Errorf("mode %q is not 0644 or 0755", raw)
	}
	if raw == "0755" {
		return 0o755, nil
	}
	return 0o644, nil
}

func readStagedFile(root *os.Root, name string, maximum int64) ([]byte, os.FileInfo, error) {
	if root == nil {
		return nil, nil, errors.New("native package staging root is nil")
	}
	if name == "" || path.IsAbs(name) || path.Clean(name) != name || strings.ContainsAny(name, "\\\x00\r\n") {
		return nil, nil, fmt.Errorf("staging path %q is unsafe", name)
	}
	components := strings.Split(name, "/")
	current := ""
	var before os.FileInfo
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, nil, fmt.Errorf("staging path %q is unsafe", name)
		}
		if current == "" {
			current = component
		} else {
			current += "/" + component
		}
		info, err := root.Lstat(filepath.FromSlash(current))
		if err != nil {
			return nil, nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("staging path %q traverses a symlink", name)
		}
		if index < len(components)-1 {
			if !info.IsDir() {
				return nil, nil, fmt.Errorf("staging path %q has a non-directory ancestor", name)
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("staging path %q is not a regular non-symlink file", name)
		}
		if info.Size() > maximum {
			return nil, nil, fmt.Errorf("staging path %q exceeds %d bytes", name, maximum)
		}
		before = info
	}

	file, err := root.Open(filepath.FromSlash(name))
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, nil, errors.New("staging file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > maximum {
		return nil, nil, fmt.Errorf("staging file exceeds %d bytes", maximum)
	}
	final, err := root.Lstat(filepath.FromSlash(name))
	if err != nil {
		return nil, nil, err
	}
	if !final.Mode().IsRegular() || final.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, final) || final.Size() != int64(len(data)) {
		return nil, nil, errors.New("staging file changed while reading")
	}
	return data, final, nil
}

func verifyStagingTree(root *os.Root, expectedFiles map[string]PayloadFile, expectedDirectories map[string]struct{}) error {
	return fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk staging tree at %q: %w", name, walkErr)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("staging tree contains symlink %q", name)
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect staging tree entry %q: %w", name, err)
		}
		if entry.IsDir() {
			if _, ok := expectedDirectories[name]; !ok {
				return fmt.Errorf("staging tree contains unexpected directory %q", name)
			}
			if !info.IsDir() {
				return fmt.Errorf("staging tree directory %q is not a directory", name)
			}
			return nil
		}
		if _, ok := expectedFiles[name]; !ok {
			return fmt.Errorf("staging tree contains unexpected file %q", name)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("staging tree entry %q is not a regular file", name)
		}
		return nil
	})
}

func digest(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSON(decoder, "$", 0); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return fmt.Errorf("decode trailing JSON data: %w", err)
	}
	return nil
}

func walkJSON(decoder *json.Decoder, location string, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds 64 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("%s object key is not a string", location)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("%s has duplicate key %q", location, key)
			}
			seen[key] = struct{}{}
			if err := walkJSON(decoder, location+"."+key, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("%s has malformed object", location)
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := walkJSON(decoder, fmt.Sprintf("%s[%d]", location, index), depth+1); err != nil {
				return err
			}
			index++
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("%s has malformed array", location)
		}
	default:
		return fmt.Errorf("%s has unexpected delimiter %q", location, delimiter)
	}
	return nil
}

func validateSourcePayload(source packageinfo.Manifest) error {
	if source.Schema != packageinfo.SchemaID || source.SchemaVersion != packageinfo.SchemaVersion || source.Name != PackageName || source.ValidationScope != packageinfo.ValidationScope {
		return errors.New("source package manifest identity is invalid")
	}
	if !releaseversion.Valid(source.Version) || source.Artifact.Filename != sourceFilename(source.Version, source.Target.GOOS, source.Target.GOARCH) || source.DefaultPrefix != "/usr/local" || source.MetadataPath != "/usr/local/share/doc/leaguebridge/"+manifestFilename {
		return errors.New("source package manifest is not a Unix release manifest")
	}
	if source.Target.RequiredKernel != requiredKernel(source.Target.GOOS) {
		return errors.New("source package target kernel is not bound to its GOOS")
	}
	names, err := packageinfo.ExpectedPayloadNames(source.Target.GOOS, source.Target.GOARCH)
	if err != nil {
		return err
	}
	if len(source.Payload) != len(names) {
		return fmt.Errorf("source package payload has %d files; want %d", len(source.Payload), len(names))
	}
	seen := make(map[string]struct{}, len(source.Payload))
	for index, entry := range source.Payload {
		if entry.ArchivePath != names[index] {
			return fmt.Errorf("source package payload[%d] is out of canonical order", index)
		}
		if entry.Size < 0 || !digestPattern.MatchString(entry.SHA256) {
			return fmt.Errorf("source package payload %q is not content-addressed", entry.ArchivePath)
		}
		installPath, role, mode := sourcePayloadSpec(entry.ArchivePath)
		if entry.InstallPath != installPath || entry.Role != role || entry.Mode != mode {
			return fmt.Errorf("source package payload %q has non-canonical install metadata", entry.ArchivePath)
		}
		if _, ok := seen[entry.ArchivePath]; ok {
			return fmt.Errorf("source package payload contains duplicate %q", entry.ArchivePath)
		}
		seen[entry.ArchivePath] = struct{}{}
	}
	return nil
}

func familySpecFor(family Family, goos, goarch string) (familySpec, error) {
	specs := map[Family]familySpec{
		FamilyDebian:  {family: FamilyDebian, goos: "linux", goarch: "amd64", architecture: "amd64", installRoot: "/"},
		FamilyRPM:     {family: FamilyRPM, goos: "linux", goarch: "amd64", architecture: "x86_64", installRoot: "/"},
		FamilyFreeBSD: {family: FamilyFreeBSD, goos: "freebsd", goarch: "amd64", architecture: "amd64", installRoot: "/usr/local"},
		FamilyOpenBSD: {family: FamilyOpenBSD, goos: "openbsd", goarch: "amd64", architecture: "amd64", installRoot: "/usr/local"},
		FamilyPkgsrc:  {family: FamilyPkgsrc, goos: "netbsd", goarch: "amd64", architecture: "amd64", installRoot: "/usr/local"},
		FamilyDPorts:  {family: FamilyDPorts, goos: "dragonfly", goarch: "amd64", architecture: "amd64", installRoot: "/usr/local"},
	}
	spec, ok := specs[family]
	if !ok {
		return familySpec{}, fmt.Errorf("unsupported native package family %q", family)
	}
	if goos != spec.goos || (spec.goarch != "" && goarch != spec.goarch) {
		return familySpec{}, fmt.Errorf("native package family %q does not support %s/%s", family, goos, goarch)
	}
	return spec, nil
}

func sourceFilename(version, goos, goarch string) string {
	return "leaguebridge_" + strings.TrimPrefix(version, "v") + "_" + goos + "_" + goarch + ".tar.gz"
}

func requiredKernel(goos string) string {
	return map[string]string{
		"linux":     "Linux",
		"freebsd":   "FreeBSD",
		"openbsd":   "OpenBSD",
		"netbsd":    "NetBSD",
		"dragonfly": "DragonFly",
	}[goos]
}

func sourcePayloadSpec(path string) (installPath, role, mode string) {
	const documentation = "/usr/local/share/doc/leaguebridge/"
	switch path {
	case "LICENSE":
		return documentation + "LICENSE", "license", "0644"
	case "README.md":
		return documentation + "README.md", "documentation", "0644"
	case "SBOM.spdx.json":
		return documentation + "SBOM.spdx.json", "sbom", "0644"
	case "install.sh":
		return "", "installer", "0755"
	case "leaguebridge":
		return "/usr/local/bin/leaguebridge", "executable", "0755"
	case "uninstall.sh":
		return "/usr/local/libexec/leaguebridge/uninstall.sh", "uninstaller", "0755"
	default:
		return "", "", ""
	}
}

func stagedInstallPath(sourcePath, installRoot string) string {
	if sourcePath == "leaguebridge" {
		if installRoot == "/" {
			return "/usr/bin/leaguebridge"
		}
		return "/usr/local/bin/leaguebridge"
	}
	if installRoot == "/" {
		return "/usr/share/doc/leaguebridge/" + sourcePath
	}
	return "/usr/local/share/doc/leaguebridge/" + sourcePath
}

// SourcePayloadNames returns the stable order of source files copied into the
// staging root. It is kept exported for the staging command and its tests.
func SourcePayloadNames() []string {
	result := []string{"LICENSE", manifestFilename, "README.md", "SBOM.spdx.json", "leaguebridge"}
	return append([]string(nil), result...)
}

// PackageFamiliesForTarget returns families which can consume one target.
func PackageFamiliesForTarget(goos, goarch string) []Family {
	var result []Family
	for _, family := range SupportedFamilies() {
		if _, err := familySpecFor(family, goos, goarch); err == nil {
			result = append(result, family)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
