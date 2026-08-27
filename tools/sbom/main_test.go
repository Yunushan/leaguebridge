package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/packageinfo"
)

const testH1Sum = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestDocumentContainsCanonicalBuildInventory(t *testing.T) {
	info := testBuildInfo()
	hash := strings.Repeat("a", 64)
	created := time.Unix(1787702400, 0)
	doc, err := newDocument("v1.2.3", "linux", "amd64", "leaguebridge", hash, created, info)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := marshalDocument(doc)
	if err != nil {
		t.Fatal(err)
	}

	if doc.SPDXVersion != "SPDX-2.3" || doc.DataLicense != "CC0-1.0" {
		t.Fatalf("unexpected document header: %+v", doc)
	}
	if len(doc.DocumentDescribes) != 1 || doc.DocumentDescribes[0] != artifactPackageID {
		t.Fatalf("documentDescribes = %v", doc.DocumentDescribes)
	}
	if got, want := len(doc.Packages), 6; got != want {
		t.Fatalf("package count = %d; want %d\n%s", got, want, encoded)
	}
	wantPackageOrder := []string{"leaguebridge", "Go toolchain", expectedMainModule, "example.com/ordinary", "example.com/requested", "example.com/replacement"}
	for index, want := range wantPackageOrder {
		if got := doc.Packages[index].Name; got != want {
			t.Fatalf("package %d name = %q; want %q", index, got, want)
		}
	}
	if got := packageByID(t, doc, artifactPackageID); got.Checksums[0].ChecksumValue != hash || got.BuiltDate != "2026-08-26T00:00:00Z" || got.PackageFileName != "leaguebridge" {
		t.Fatalf("artifact package = %+v", got)
	}
	if got := packageByID(t, doc, toolchainPackageID); got.VersionInfo != "go1.27.0" {
		t.Fatalf("toolchain package = %+v", got)
	}
	if got := packageByID(t, doc, mainModuleID); got.Name != expectedMainModule || got.VersionInfo != "v1.2.3-main" {
		t.Fatalf("main module package = %+v", got)
	}
	for _, pkg := range doc.Packages {
		if pkg.LicenseConcluded != "NOASSERTION" || pkg.LicenseDeclared != "NOASSERTION" || pkg.CopyrightText != "NOASSERTION" || pkg.LicenseComments != licenseExplanation {
			t.Fatalf("package %q makes an unsupported license or copyright assertion: %+v", pkg.Name, pkg)
		}
	}
	assertRelationshipReferencesResolve(t, doc)
	if bytes.Contains(encoded, []byte(`"0BSD"`)) {
		t.Fatalf("SBOM overclaims a license:\n%s", encoded)
	}

	requested := packagesNamed(doc, "example.com/requested")
	replacement := packagesNamed(doc, "example.com/replacement")
	if len(requested) != 1 || len(replacement) != 1 {
		t.Fatalf("replacement inventory missing: requested=%v replacement=%v", requested, replacement)
	}
	if !hasRelationship(doc, mainModuleID, "DEPENDS_ON", replacement[0].SPDXID, "") {
		t.Fatal("main module does not depend on effective replacement")
	}
	if !hasRelationship(doc, requested[0].SPDXID, "OTHER", replacement[0].SPDXID, "Go build information states that the related package replaced this requested module.") {
		t.Fatal("requested-to-replacement relationship is missing")
	}
	if !hasExternalReference(replacement[0], "go-module-sum", testH1Sum) {
		t.Fatalf("replacement Go sum is missing: %+v", replacement[0])
	}

	// Dependency input order is not part of canonical output.
	reversed := *info
	reversed.Deps = []*debug.Module{info.Deps[1], info.Deps[0]}
	docReversed, err := newDocument("v1.2.3", "linux", "amd64", "leaguebridge", hash, created, &reversed)
	if err != nil {
		t.Fatal(err)
	}
	encodedReversed, err := marshalDocument(docReversed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, encodedReversed) {
		t.Fatalf("dependency order changed canonical JSON\nfirst:\n%s\nsecond:\n%s", encoded, encodedReversed)
	}
}

func TestDocumentRejectsUntrustworthyBuildInformation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*debug.BuildInfo)
		want   string
	}{
		{name: "missing toolchain", mutate: func(info *debug.BuildInfo) { info.GoVersion = "" }, want: "toolchain"},
		{name: "wrong module", mutate: func(info *debug.BuildInfo) { info.Main.Path = "example.com/not-leaguebridge" }, want: "main module"},
		{name: "package outside module", mutate: func(info *debug.BuildInfo) { info.Path = "example.com/command" }, want: "outside module"},
		{name: "main replacement", mutate: func(info *debug.BuildInfo) { info.Main.Replace = &debug.Module{Path: "example.com/replacement"} }, want: "main module unexpectedly"},
		{name: "target mismatch", mutate: func(info *debug.BuildInfo) { info.Settings[0].Value = "freebsd" }, want: "GOOS"},
		{name: "missing target", mutate: func(info *debug.BuildInfo) { info.Settings = info.Settings[1:] }, want: "GOOS is missing"},
		{name: "duplicate target setting", mutate: func(info *debug.BuildInfo) {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: "GOOS", Value: "linux"})
		}, want: "duplicate"},
		{name: "nil dependency", mutate: func(info *debug.BuildInfo) { info.Deps[0] = nil }, want: "dependency 0 is nil"},
		{name: "empty dependency path", mutate: func(info *debug.BuildInfo) { info.Deps[0].Path = "" }, want: "path is empty"},
		{name: "wrong sum algorithm", mutate: func(info *debug.BuildInfo) { info.Deps[1].Sum = "sha256:" + strings.Repeat("0", 64) }, want: "not a Go h1"},
		{name: "invalid sum", mutate: func(info *debug.BuildInfo) { info.Deps[1].Sum = "h1:not-base64" }, want: "h1 SHA-256"},
		{name: "duplicate dependency", mutate: func(info *debug.BuildInfo) {
			copyOfDependency := *info.Deps[0]
			info.Deps = append(info.Deps, &copyOfDependency)
		}, want: "duplicate dependency"},
		{name: "nested replacement", mutate: func(info *debug.BuildInfo) {
			info.Deps[0].Replace.Replace = &debug.Module{Path: "example.com/nested"}
		}, want: "nested replacement"},
		{name: "control character", mutate: func(info *debug.BuildInfo) { info.Deps[1].Path = "example.com/bad\nmodule" }, want: "control characters"},
		{name: "invalid utf8", mutate: func(info *debug.BuildInfo) { info.Deps[1].Path = string([]byte{0xff}) }, want: "valid UTF-8"},
		{name: "oversized value", mutate: func(info *debug.BuildInfo) { info.Deps[1].Version = strings.Repeat("v", maxBuildInfoValue+1) }, want: "exceeds"},
		{name: "too many dependencies", mutate: func(info *debug.BuildInfo) { info.Deps = make([]*debug.Module, maxDependencies+1) }, want: "maximum"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := testBuildInfo()
			test.mutate(info)
			_, err := newDocument("v1.2.3", "linux", "amd64", "leaguebridge", strings.Repeat("a", 64), time.Unix(1787702400, 0), info)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("newDocument() error = %v; want substring %q", err, test.want)
			}
		})
	}
}

func TestDocumentCanonicalizesApprovedVendoredDependency(t *testing.T) {
	makeInfo := func(sum string) *debug.BuildInfo {
		info := testBuildInfo()
		info.Deps = []*debug.Module{{
			Path:    packageinfo.ProductionDependencyPath,
			Version: packageinfo.ProductionDependencyVersion,
			Sum:     sum,
		}}
		return info
	}
	created := time.Unix(1787702400, 0)
	hash := strings.Repeat("a", 64)
	doc, err := newDocument("v1.2.3", "linux", "amd64", "leaguebridge", hash, created, makeInfo(""))
	if err != nil {
		t.Fatal(err)
	}
	dependencies := packagesNamed(doc, packageinfo.ProductionDependencyPath)
	if len(dependencies) != 1 {
		t.Fatalf("approved dependency packages = %d; want 1", len(dependencies))
	}
	dependency := dependencies[0]
	if dependency.VersionInfo != packageinfo.ProductionDependencyVersion || dependency.LicenseDeclared != packageinfo.ProductionDependencyLicense {
		t.Fatalf("approved dependency identity = %+v", dependency)
	}
	if !hasExternalReference(dependency, "go-module-sum", packageinfo.ProductionDependencySum) {
		t.Fatalf("approved dependency is missing pinned Go sum: %+v", dependency)
	}

	withSum, err := newDocument("v1.2.3", "linux", "amd64", "leaguebridge", hash, created, makeInfo(packageinfo.ProductionDependencySum))
	if err != nil {
		t.Fatal(err)
	}
	withoutSumJSON, err := marshalDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	withSumJSON, err := marshalDocument(withSum)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(withoutSumJSON, withSumJSON) {
		t.Fatalf("vendor-empty and module-cache sums produced different canonical SBOMs\nempty:\n%s\nwith sum:\n%s", withoutSumJSON, withSumJSON)
	}
}

func TestDocumentRejectsInvalidReleaseIdentity(t *testing.T) {
	validHash := strings.Repeat("a", 64)
	created := time.Unix(1787702400, 0)
	for _, test := range []struct {
		name       string
		version    string
		goos       string
		goarch     string
		binaryName string
		hash       string
		want       string
	}{
		{name: "unsafe version", version: "v1/2", goos: "linux", goarch: "amd64", binaryName: "leaguebridge", hash: validHash, want: "unsafe"},
		{name: "wrong unix binary", version: "v1.2.3", goos: "linux", goarch: "amd64", binaryName: "leaguebridge.exe", hash: validHash, want: "binary name"},
		{name: "wrong windows binary", version: "v1.2.3", goos: "windows", goarch: "amd64", binaryName: "leaguebridge", hash: validHash, want: "binary name"},
		{name: "invalid hash", version: "v1.2.3", goos: "linux", goarch: "amd64", binaryName: "leaguebridge", hash: strings.Repeat("A", 64), want: "SHA-256"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := newDocument(test.version, test.goos, test.goarch, test.binaryName, test.hash, created, testBuildInfo())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("newDocument() error = %v; want substring %q", err, test.want)
			}
		})
	}
}

func TestRunRejectsBadArgumentsAndNonGoBinary(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "unknown flag", args: []string{"-unknown"}, want: "flag provided but not defined"},
		{name: "positional argument", args: []string{"unexpected"}, want: "unexpected positional"},
		{name: "missing arguments", args: nil, want: "are required"},
		{name: "unsafe version", args: []string{"-binary", "unused", "-version", "v1/2", "-os", "linux", "-arch", "amd64", "-output", "unused"}, want: "unsafe"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := run(test.args); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("run() error = %v; want substring %q", err, test.want)
			}
		})
	}

	plain := filepath.Join(t.TempDir(), "leaguebridge")
	if err := os.WriteFile(plain, []byte("not a Go binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-binary", plain, "-version", "v1.2.3", "-os", runtime.GOOS, "-arch", runtime.GOARCH, "-output", plain + ".json"}); err == nil || !strings.Contains(err.Error(), "Go build information") {
		t.Fatalf("run(non-Go binary) error = %v", err)
	}
}

func TestRunReadsEmbeddedReplacementAndIsReproducible(t *testing.T) {
	if runtime.Version() != "go1.27.0" {
		t.Skipf("focused production-toolchain integration requires go1.27.0; running %s", runtime.Version())
	}
	binary := buildReplacementFixture(t)
	hash, build, err := inspectBinary(binary)
	if err != nil {
		t.Fatal(err)
	}
	if len(build.Deps) != 1 || build.Deps[0].Replace == nil {
		t.Fatalf("fixture build information does not contain its replacement: %+v", build.Deps)
	}

	t.Setenv("SOURCE_DATE_EPOCH", "1787702400")
	first := filepath.Join(t.TempDir(), "first.spdx.json")
	second := filepath.Join(t.TempDir(), "second.spdx.json")
	for _, output := range []string{first, second} {
		if err := run([]string{
			"-binary", binary,
			"-version", "v1.2.3",
			"-os", runtime.GOOS,
			"-arch", runtime.GOARCH,
			"-output", output,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := run([]string{
		"-binary", binary,
		"-version", "v1.2.3",
		"-os", runtime.GOOS,
		"-arch", differentArch(runtime.GOARCH),
		"-output", filepath.Join(t.TempDir(), "mismatch.spdx.json"),
	}); err == nil || !strings.Contains(err.Error(), "GOARCH") {
		t.Fatalf("run(target mismatch) error = %v", err)
	}
	if err := run([]string{
		"-binary", binary,
		"-version", "v1.2.3",
		"-os", runtime.GOOS,
		"-arch", runtime.GOARCH,
		"-output", filepath.Join(t.TempDir(), "missing", "output.spdx.json"),
	}); err == nil || !strings.Contains(err.Error(), "write SPDX") {
		t.Fatalf("run(unwritable output) error = %v", err)
	}
	firstData, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondData, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstData, secondData) {
		t.Fatal("identical binary and SOURCE_DATE_EPOCH produced different SBOM bytes")
	}

	var doc document
	if err := json.Unmarshal(firstData, &doc); err != nil {
		t.Fatal(err)
	}
	artifact := packageByID(t, doc, artifactPackageID)
	if artifact.Checksums[0].ChecksumValue != hash {
		t.Fatalf("artifact hash = %q; want %q", artifact.Checksums[0].ChecksumValue, hash)
	}
	if got := packageByID(t, doc, toolchainPackageID).VersionInfo; got != "go1.27.0" {
		t.Fatalf("toolchain version = %q", got)
	}
	if got := packagesNamed(doc, build.Deps[0].Path); len(got) != 1 || got[0].VersionInfo != build.Deps[0].Version {
		t.Fatalf("requested dependency mismatch: %+v", got)
	}
	if got := packagesNamed(doc, build.Deps[0].Replace.Path); len(got) != 1 || got[0].VersionInfo != build.Deps[0].Replace.Version {
		t.Fatalf("effective replacement mismatch: %+v", got)
	}
}

func TestHashFileRejectsOversize(t *testing.T) {
	root := t.TempDir()
	oversize := filepath.Join(root, "oversize")
	file, err := os.Create(oversize)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxBinarySize + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := hashFile(oversize); err == nil || !strings.Contains(err.Error(), "512 MiB") {
		t.Fatalf("hashFile(oversize) error = %v", err)
	}
}

func TestHashFileHashesRegularFileAndRejectsDirectory(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "binary")
	contents := []byte("leaguebridge")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%x", sha256.Sum256(contents))
	if got, err := hashFile(path); err != nil || got != want {
		t.Fatalf("hashFile() = %q, %v; want %q", got, err, want)
	}
	if _, err := hashFile(root); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("hashFile(directory) error = %v", err)
	}
	if _, err := hashFile(filepath.Join(root, "missing")); err == nil {
		t.Fatal("hashFile(missing) unexpectedly succeeded")
	}
}

func TestHashFileRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	if _, err := hashFile(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("hashFile(symlink) error = %v", err)
	}
}

func TestSourceTimeUsesOnlyValidEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1787702400")
	got, err := sourceTime()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(time.Unix(1787702400, 0)) {
		t.Fatalf("sourceTime() = %v", got)
	}

	for _, invalid := range []string{"-1", "not-a-number", " 1787702400"} {
		t.Run(invalid, func(t *testing.T) {
			t.Setenv("SOURCE_DATE_EPOCH", invalid)
			if _, err := sourceTime(); err == nil {
				t.Fatalf("sourceTime() accepted %q", invalid)
			}
		})
	}

	t.Setenv("SOURCE_DATE_EPOCH", "")
	before := time.Now().UTC().Add(-time.Second)
	current, err := sourceTime()
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC().Add(time.Second)
	if current.Before(before) || current.After(after) {
		t.Fatalf("sourceTime() without an epoch = %v", current)
	}
}

func TestGoModulePURLIsConservative(t *testing.T) {
	if got, ok := goModulePURL("example.com/module", "v1.2.3"); !ok || got != "pkg:golang/example.com/module@v1.2.3" {
		t.Fatalf("goModulePURL() = %q, %v", got, ok)
	}
	for _, test := range []struct {
		path    string
		version string
	}{
		{path: expectedMainModule, version: "v1.2.3"}, // PURL's Go type requires lowercase names.
		{path: "./local replacement", version: ""},
		{path: "example.com/module", version: "(devel)"},
	} {
		if got, ok := goModulePURL(test.path, test.version); ok {
			t.Fatalf("goModulePURL(%q, %q) unexpectedly returned %q", test.path, test.version, got)
		}
	}
}

func testBuildInfo() *debug.BuildInfo {
	return &debug.BuildInfo{
		GoVersion: "go1.27.0",
		Path:      expectedMainModule + "/cmd/leaguebridge",
		Main: debug.Module{
			Path:    expectedMainModule,
			Version: "v1.2.3-main",
		},
		Deps: []*debug.Module{
			{
				Path:    "example.com/requested",
				Version: "v2.0.0",
				Sum:     testH1Sum,
				Replace: &debug.Module{
					Path:    "example.com/replacement",
					Version: "v2.0.1",
					Sum:     testH1Sum,
				},
			},
			{Path: "example.com/ordinary", Version: "v1.0.0", Sum: testH1Sum},
		},
		Settings: []debug.BuildSetting{
			{Key: "GOOS", Value: "linux"},
			{Key: "GOARCH", Value: "amd64"},
		},
	}
}

func buildReplacementFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), `module github.com/Yunushan/leaguebridge

go 1.24

require example.com/original v1.2.3

replace example.com/original v1.2.3 => ./replacement
`)
	writeTestFile(t, filepath.Join(root, "main.go"), `package main

import (
	"fmt"
	"example.com/original/dep"
)

func main() { fmt.Print(dep.Value()) }
`)
	writeTestFile(t, filepath.Join(root, "replacement", "go.mod"), `module example.com/original

go 1.24
`)
	writeTestFile(t, filepath.Join(root, "replacement", "dep", "dep.go"), `package dep

func Value() string { return "replacement" }
`)
	binaryName := "leaguebridge"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binary := filepath.Join(root, binaryName)
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		goBinary += ".exe"
	}
	command := exec.Command(goBinary, "build", "-trimpath", "-buildvcs=false", "-o", binary, ".")
	command.Dir = root
	command.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS="+runtime.GOOS,
		"GOARCH="+runtime.GOARCH,
		"GOWORK=off",
		"GOPROXY=off",
		"GOSUMDB=off",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build replacement fixture: %v\n%s", err, output)
	}
	return binary
}

func differentArch(arch string) string {
	if arch == "amd64" {
		return "arm64"
	}
	return "amd64"
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func packageByID(t *testing.T, doc document, id string) spdxPackage {
	t.Helper()
	for _, pkg := range doc.Packages {
		if pkg.SPDXID == id {
			return pkg
		}
	}
	t.Fatalf("package %q is missing", id)
	return spdxPackage{}
}

func packagesNamed(doc document, name string) []spdxPackage {
	var result []spdxPackage
	for _, pkg := range doc.Packages {
		if pkg.Name == name {
			result = append(result, pkg)
		}
	}
	return result
}

func hasRelationship(doc document, from, kind, to, comment string) bool {
	for _, candidate := range doc.Relationships {
		if candidate.SPDXElementID == from && candidate.RelationshipType == kind && candidate.RelatedSPDXElement == to && candidate.Comment == comment {
			return true
		}
	}
	return false
}

func hasExternalReference(pkg spdxPackage, referenceType, locator string) bool {
	for _, ref := range pkg.ExternalRefs {
		if ref.ReferenceType == referenceType && ref.ReferenceLocator == locator {
			return true
		}
	}
	return false
}

func assertRelationshipReferencesResolve(t *testing.T, doc document) {
	t.Helper()
	ids := map[string]struct{}{doc.SPDXID: {}}
	for _, pkg := range doc.Packages {
		if _, exists := ids[pkg.SPDXID]; exists {
			t.Fatalf("duplicate SPDX ID %q", pkg.SPDXID)
		}
		ids[pkg.SPDXID] = struct{}{}
	}
	for _, relation := range doc.Relationships {
		if _, exists := ids[relation.SPDXElementID]; !exists {
			t.Fatalf("relationship source %q does not resolve", relation.SPDXElementID)
		}
		if _, exists := ids[relation.RelatedSPDXElement]; !exists {
			t.Fatalf("relationship target %q does not resolve", relation.RelatedSPDXElement)
		}
	}
}
