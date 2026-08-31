// Command sbom generates a canonical SPDX 2.3 component inventory from one
// LeagueBridge release binary and the Go build information embedded in it.
package main

import (
	"crypto/sha256"
	debugbuildinfo "debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
)

const (
	expectedMainModule = "github.com/Yunushan/leaguebridge"
	maxBinarySize      = int64(512 * 1024 * 1024)
	maxBuildInfoValue  = 4096
	maxDependencies    = 16384

	artifactPackageID  = "SPDXRef-Package-LeagueBridge"
	toolchainPackageID = "SPDXRef-Package-GoToolchain"
	mainModuleID       = "SPDXRef-Package-GoModule-Main"

	licenseExplanation = "License data was not analyzed from source files; NOASSERTION is intentional."
)

var (
	safeValue       = regexp.MustCompile(`^[A-Za-z0-9._+\-]+$`)
	lowerHexSHA256  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	purlPathSegment = regexp.MustCompile(`^[a-z0-9][a-z0-9._~+\-]*$`)
	purlVersion     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~\-]*$`)
)

type document struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	DocumentDescribes []string       `json:"documentDescribes"`
	CreationInfo      creationInfo   `json:"creationInfo"`
	Packages          []spdxPackage  `json:"packages"`
	Relationships     []relationship `json:"relationships"`
}

type creationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	Name                  string        `json:"name"`
	SPDXID                string        `json:"SPDXID"`
	VersionInfo           string        `json:"versionInfo,omitempty"`
	PackageFileName       string        `json:"packageFileName,omitempty"`
	DownloadLocation      string        `json:"downloadLocation"`
	FilesAnalyzed         bool          `json:"filesAnalyzed"`
	PrimaryPackagePurpose string        `json:"primaryPackagePurpose,omitempty"`
	BuiltDate             string        `json:"builtDate,omitempty"`
	LicenseConcluded      string        `json:"licenseConcluded"`
	LicenseDeclared       string        `json:"licenseDeclared"`
	LicenseComments       string        `json:"licenseComments"`
	CopyrightText         string        `json:"copyrightText"`
	Checksums             []checksum    `json:"checksums,omitempty"`
	ExternalRefs          []externalRef `json:"externalRefs,omitempty"`
	Comment               string        `json:"comment,omitempty"`
}

type checksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type externalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	Comment            string `json:"comment,omitempty"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("sbom", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	binary := flags.String("binary", "", "release binary to inspect and hash")
	version := flags.String("version", "", "release version")
	goos := flags.String("os", "", "target operating system")
	goarch := flags.String("arch", "", "target architecture")
	output := flags.String("output", "", "output SPDX JSON path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *binary == "" || *version == "" || *goos == "" || *goarch == "" || *output == "" {
		return errors.New("binary, version, os, arch, and output are required")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "version", value: *version},
		{name: "os", value: *goos},
		{name: "arch", value: *goarch},
	} {
		if !safeValue.MatchString(field.value) {
			return fmt.Errorf("%s contains unsafe characters", field.name)
		}
	}

	hash, info, err := inspectBinary(*binary)
	if err != nil {
		return fmt.Errorf("inspect binary: %w", err)
	}
	created, err := sourceTime()
	if err != nil {
		return err
	}
	doc, err := newDocument(*version, *goos, *goarch, filepath.Base(*binary), hash, created, info)
	if err != nil {
		return fmt.Errorf("build SPDX inventory: %w", err)
	}
	data, err := marshalDocument(doc)
	if err != nil {
		return err
	}
	if err := fileinput.RejectSymlinkedParents(*output); err != nil {
		return fmt.Errorf("inspect output parents: %w", err)
	}
	if err := writeExclusive(*output, data); err != nil {
		return fmt.Errorf("write SPDX: %w", err)
	}
	return nil
}

func newDocument(version, goos, goarch, binaryName, hash string, created time.Time, info *debug.BuildInfo) (document, error) {
	if !safeValue.MatchString(version) || !safeValue.MatchString(goos) || !safeValue.MatchString(goarch) {
		return document{}, errors.New("release version or target contains unsafe characters")
	}
	switch goos {
	case "linux", "freebsd", "openbsd", "netbsd", "dragonfly":
	default:
		return document{}, fmt.Errorf("unsupported release operating system %q", goos)
	}
	if goarch != "amd64" {
		return document{}, fmt.Errorf("unsupported release architecture %q", goarch)
	}
	if binaryName != "leaguebridge" {
		return document{}, fmt.Errorf("binary name is %q; want %q for Linux/BSD amd64 releases", binaryName, "leaguebridge")
	}
	if !lowerHexSHA256.MatchString(hash) {
		return document{}, errors.New("binary SHA-256 must be 64 lowercase hexadecimal characters")
	}
	dependencies, err := validateBuildInfo(info, goos, goarch)
	if err != nil {
		return document{}, err
	}

	createdText := created.UTC().Format(time.RFC3339)
	name := strings.Join([]string{"leaguebridge", version, goos, goarch}, "-")
	doc := document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              name,
		DocumentNamespace: "https://github.com/Yunushan/leaguebridge/sbom/" + version + "/" + goos + "/" + goarch + "/" + hash,
		DocumentDescribes: []string{artifactPackageID},
		CreationInfo: creationInfo{
			Created:  createdText,
			Creators: []string{"Tool: leaguebridge/tools/sbom"},
		},
		Packages: []spdxPackage{
			newPackage("leaguebridge", artifactPackageID, version, "APPLICATION", "Release binary package; the SHA-256 checksum covers the exact executable bytes."),
			newPackage("Go toolchain", toolchainPackageID, info.GoVersion, "APPLICATION", "Exact Go toolchain recorded in the release binary's embedded build information."),
			modulePackage(info.Main, mainModuleID, "SOURCE", "Main Go module recorded in the release binary's embedded build information."),
		},
		Relationships: []relationship{
			{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: artifactPackageID},
			{SPDXElementID: toolchainPackageID, RelationshipType: "BUILD_TOOL_OF", RelatedSPDXElement: artifactPackageID},
			{SPDXElementID: artifactPackageID, RelationshipType: "GENERATED_FROM", RelatedSPDXElement: mainModuleID},
		},
	}
	doc.Packages[0].PackageFileName = binaryName
	doc.Packages[0].BuiltDate = createdText
	doc.Packages[0].Checksums = []checksum{{Algorithm: "SHA256", ChecksumValue: hash}}
	doc.Packages[0].ExternalRefs = []externalRef{{
		ReferenceCategory: "PACKAGE-MANAGER",
		ReferenceType:     "purl",
		ReferenceLocator:  "pkg:generic/leaguebridge@" + escapePURL(version),
	}}

	for _, dependency := range dependencies {
		if dependency.Replace == nil {
			id := dependencyID("dependency", dependency, nil)
			doc.Packages = append(doc.Packages, modulePackage(*dependency, id, "LIBRARY", "Compiled Go dependency module recorded in the release binary's embedded build information."))
			doc.Relationships = append(doc.Relationships, relationship{
				SPDXElementID:      mainModuleID,
				RelationshipType:   "DEPENDS_ON",
				RelatedSPDXElement: id,
			})
			continue
		}

		requestedID := dependencyID("requested", dependency, nil)
		replacementID := dependencyID("replacement", dependency, dependency.Replace)
		doc.Packages = append(doc.Packages,
			modulePackage(*dependency, requestedID, "LIBRARY", "Requested Go dependency module; Go build information records an effective replacement."),
			modulePackage(*dependency.Replace, replacementID, "LIBRARY", "Effective replacement module selected by the release binary's Go build information."),
		)
		doc.Relationships = append(doc.Relationships,
			relationship{
				SPDXElementID:      mainModuleID,
				RelationshipType:   "DEPENDS_ON",
				RelatedSPDXElement: replacementID,
			},
			relationship{
				SPDXElementID:      requestedID,
				RelationshipType:   "OTHER",
				RelatedSPDXElement: replacementID,
				Comment:            "Go build information states that the related package replaced this requested module.",
			},
		)
	}
	return doc, nil
}

func newPackage(name, id, version, purpose, comment string) spdxPackage {
	return spdxPackage{
		Name:                  name,
		SPDXID:                id,
		VersionInfo:           version,
		DownloadLocation:      "NOASSERTION",
		FilesAnalyzed:         false,
		PrimaryPackagePurpose: purpose,
		LicenseConcluded:      "NOASSERTION",
		LicenseDeclared:       "NOASSERTION",
		LicenseComments:       licenseExplanation,
		CopyrightText:         "NOASSERTION",
		Comment:               comment,
	}
}

func modulePackage(module debug.Module, id, purpose, comment string) spdxPackage {
	pkg := newPackage(module.Path, id, module.Version, purpose, comment)
	if module.Path == packageinfo.ProductionDependencyPath &&
		module.Version == packageinfo.ProductionDependencyVersion &&
		module.Sum == packageinfo.ProductionDependencySum &&
		module.Replace == nil {
		pkg.LicenseDeclared = packageinfo.ProductionDependencyLicense
		pkg.LicenseComments = packageinfo.ProductionDependencyLicenseComment
	}
	if purl, ok := goModulePURL(module.Path, module.Version); ok {
		pkg.ExternalRefs = append(pkg.ExternalRefs, externalRef{
			ReferenceCategory: "PACKAGE-MANAGER",
			ReferenceType:     "purl",
			ReferenceLocator:  purl,
		})
	}
	if module.Sum != "" {
		pkg.ExternalRefs = append(pkg.ExternalRefs, externalRef{
			ReferenceCategory: "OTHER",
			ReferenceType:     "go-module-sum",
			ReferenceLocator:  module.Sum,
		})
	}
	return pkg
}

func validateBuildInfo(info *debug.BuildInfo, goos, goarch string) ([]*debug.Module, error) {
	if info == nil {
		return nil, errors.New("Go build information is missing")
	}
	if err := validateBuildValue("Go toolchain version", info.GoVersion, true); err != nil {
		return nil, err
	}
	if err := validateBuildValue("main package path", info.Path, true); err != nil {
		return nil, err
	}
	if info.Main.Path != expectedMainModule {
		return nil, fmt.Errorf("main module is %q; want %q", info.Main.Path, expectedMainModule)
	}
	if info.Path != expectedMainModule && !strings.HasPrefix(info.Path, expectedMainModule+"/") {
		return nil, fmt.Errorf("main package %q is outside module %q", info.Path, expectedMainModule)
	}
	if info.Main.Replace != nil {
		return nil, errors.New("main module unexpectedly contains replacement metadata")
	}
	if err := validateModule("main module", &info.Main); err != nil {
		return nil, err
	}
	if len(info.Deps) > maxDependencies {
		return nil, fmt.Errorf("build information contains %d dependencies; maximum is %d", len(info.Deps), maxDependencies)
	}

	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		if _, exists := settings[setting.Key]; exists {
			return nil, fmt.Errorf("duplicate Go build setting %q", setting.Key)
		}
		settings[setting.Key] = setting.Value
	}
	for _, target := range []struct {
		key  string
		want string
	}{
		{key: "GOOS", want: goos},
		{key: "GOARCH", want: goarch},
	} {
		got, ok := settings[target.key]
		if !ok {
			return nil, fmt.Errorf("Go build setting %s is missing", target.key)
		}
		if got != target.want {
			return nil, fmt.Errorf("Go build setting %s is %q; want %q", target.key, got, target.want)
		}
	}

	dependencies := append([]*debug.Module(nil), info.Deps...)
	seenPaths := make(map[string]struct{}, len(dependencies))
	for index, dependency := range dependencies {
		if dependency == nil {
			return nil, fmt.Errorf("dependency %d is nil", index)
		}
		if err := validateModule(fmt.Sprintf("dependency %d", index), dependency); err != nil {
			return nil, err
		}
		if _, exists := seenPaths[dependency.Path]; exists {
			return nil, fmt.Errorf("duplicate dependency module path %q", dependency.Path)
		}
		seenPaths[dependency.Path] = struct{}{}
		if dependency.Replace != nil {
			if dependency.Replace.Replace != nil {
				return nil, fmt.Errorf("dependency %q has nested replacement metadata", dependency.Path)
			}
			if err := validateModule("replacement for "+dependency.Path, dependency.Replace); err != nil {
				return nil, err
			}
		}
	}
	sort.Slice(dependencies, func(i, j int) bool {
		return moduleSortKey(dependencies[i]) < moduleSortKey(dependencies[j])
	})
	for index, dependency := range dependencies {
		if dependency.Path == packageinfo.ProductionDependencyPath &&
			dependency.Version == packageinfo.ProductionDependencyVersion &&
			dependency.Sum == "" &&
			dependency.Replace == nil {
			canonical := *dependency
			canonical.Sum = packageinfo.ProductionDependencySum
			dependencies[index] = &canonical
		}
	}
	return dependencies, nil
}

func validateModule(label string, module *debug.Module) error {
	if module == nil {
		return fmt.Errorf("%s is nil", label)
	}
	if err := validateBuildValue(label+" path", module.Path, true); err != nil {
		return err
	}
	if err := validateBuildValue(label+" version", module.Version, false); err != nil {
		return err
	}
	if err := validateBuildValue(label+" sum", module.Sum, false); err != nil {
		return err
	}
	if module.Sum != "" {
		if !strings.HasPrefix(module.Sum, "h1:") {
			return fmt.Errorf("%s sum is not a Go h1 checksum", label)
		}
		digest, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(module.Sum, "h1:"))
		if err != nil || len(digest) != sha256.Size {
			return fmt.Errorf("%s sum is not a valid Go h1 SHA-256 checksum", label)
		}
	}
	return nil
}

func validateBuildValue(label, value string, required bool) error {
	if required && value == "" {
		return fmt.Errorf("%s is empty", label)
	}
	if len(value) > maxBuildInfoValue {
		return fmt.Errorf("%s exceeds %d bytes", label, maxBuildInfoValue)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", label)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains control characters", label)
		}
	}
	return nil
}

func moduleSortKey(module *debug.Module) string {
	key := module.Path + "\x00" + module.Version + "\x00" + module.Sum
	if module.Replace != nil {
		key += "\x00" + module.Replace.Path + "\x00" + module.Replace.Version + "\x00" + module.Replace.Sum
	}
	return key
}

func dependencyID(role string, requested *debug.Module, replacement *debug.Module) string {
	identity := role + "\x00" + requested.Path + "\x00" + requested.Version + "\x00" + requested.Sum
	if replacement != nil {
		identity += "\x00" + replacement.Path + "\x00" + replacement.Version + "\x00" + replacement.Sum
	}
	digest := sha256.Sum256([]byte(identity))
	role = strings.ToUpper(role[:1]) + role[1:]
	return "SPDXRef-Package-GoModule-" + role + "-" + hex.EncodeToString(digest[:])
}

func goModulePURL(path, version string) (string, bool) {
	parts := strings.Split(path, "/")
	if len(parts) < 2 || path != strings.ToLower(path) {
		return "", false
	}
	for _, part := range parts {
		if !purlPathSegment.MatchString(part) {
			return "", false
		}
	}
	if version != "" && !purlVersion.MatchString(version) {
		return "", false
	}
	for index, part := range parts {
		parts[index] = escapePURL(part)
	}
	result := "pkg:golang/" + strings.Join(parts, "/")
	if version != "" {
		result += "@" + escapePURL(version)
	}
	return result, true
}

func escapePURL(value string) string {
	// PathEscape leaves '+' untouched even though PURL reserves it in some
	// contexts. Replacing it keeps the emitted locator unambiguous.
	return strings.ReplaceAll(url.PathEscape(value), "+", "%2B")
}

func marshalDocument(doc document) ([]byte, error) {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode SPDX: %w", err)
	}
	return append(data, '\n'), nil
}

func inspectBinary(path string) (string, *debug.BuildInfo, error) {
	file, err := openRegularFile(path)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()

	info, err := debugbuildinfo.Read(file)
	if err != nil {
		return "", nil, fmt.Errorf("read embedded Go build information: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", nil, fmt.Errorf("rewind binary: %w", err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", nil, fmt.Errorf("hash binary: %w", err)
	}
	if err := verifyPathStable(path, file); err != nil {
		return "", nil, fmt.Errorf("verify binary path after hashing: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), info, nil
}

func hashFile(path string) (string, error) {
	file, err := openRegularFile(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	if err := verifyPathStable(path, file); err != nil {
		return "", fmt.Errorf("verify binary path after hashing: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func verifyPathStable(path string, file *os.File) error {
	if err := fileinput.RejectSymlinkedParents(path); err != nil {
		return err
	}
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	finalPath, err := os.Lstat(filepath.Clean(path))
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || finalPath.Mode()&os.ModeSymlink != 0 || !finalPath.Mode().IsRegular() ||
		!os.SameFile(opened, finalPath) || finalPath.Size() != opened.Size() {
		return errors.New("binary path changed while reading")
	}
	return nil
}

func openRegularFile(path string) (*os.File, error) {
	cleaned := filepath.Clean(path)
	if err := fileinput.RejectSymlinkedParents(cleaned); err != nil {
		return nil, err
	}
	metadata, err := os.Lstat(cleaned)
	if err != nil {
		return nil, err
	}
	if metadata.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("binary must not be a symbolic link")
	}
	if !metadata.Mode().IsRegular() {
		return nil, errors.New("binary is not a regular file")
	}
	if metadata.Size() > maxBinarySize {
		return nil, errors.New("binary exceeds 512 MiB")
	}
	file, err := os.Open(cleaned)
	if err != nil {
		return nil, err
	}
	openedMetadata, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	finalMetadata, err := os.Lstat(cleaned)
	if err != nil {
		file.Close()
		return nil, err
	}
	if !openedMetadata.Mode().IsRegular() || finalMetadata.Mode()&os.ModeSymlink != 0 || !finalMetadata.Mode().IsRegular() ||
		!os.SameFile(metadata, openedMetadata) || !os.SameFile(metadata, finalMetadata) {
		file.Close()
		return nil, errors.New("binary changed while it was opened")
	}
	return file, nil
}

func writeExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func sourceTime() (time.Time, error) {
	raw := os.Getenv("SOURCE_DATE_EPOCH")
	if raw == "" {
		return time.Now().UTC(), nil
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds < 0 {
		return time.Time{}, errors.New("SOURCE_DATE_EPOCH must be non-negative decimal seconds")
	}
	value := time.Unix(seconds, 0).UTC()
	if value.Year() < 0 || value.Year() > 9999 {
		return time.Time{}, errors.New("SOURCE_DATE_EPOCH is outside the RFC 3339 year range")
	}
	return value, nil
}
