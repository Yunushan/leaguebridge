package releasecheck

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/packageinfo"
	"github.com/Yunushan/leaguebridge/internal/readiness"
)

const (
	testVersion         = "v1.2.3-rc.1+build.7"
	testEpoch           = int64(1787702400)
	testCommit          = "0123456789abcdef0123456789abcdef01234567"
	testTree            = "89abcdef0123456789abcdef0123456789abcdef"
	testDependencyH1Sum = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

var testBuilderGoVersion = runtime.Version()

type testMember struct {
	name    string
	mode    os.FileMode
	uid     int
	gid     int
	body    []byte
	modTime time.Time
	format  tar.Format
	uname   string
	pax     map[string]string
}

func TestCheckReleaseAcceptsCanonicalRelease(t *testing.T) {
	dir, commit, tree, scorecard := makeValidReleaseFixture(t)
	if err := checkRelease(dir, testVersion, testEpoch, commit, tree, testBuilderGoVersion, scorecard); err != nil {
		t.Fatalf("checkRelease() error = %v", err)
	}
}

func TestCanonicalReleaseFixtureCopiesAreIsolated(t *testing.T) {
	first, commit, tree, scorecard := makeValidReleaseFixture(t)
	second, secondCommit, secondTree, secondScorecard := makeValidReleaseFixture(t)
	if first == second || commit != secondCommit || tree != secondTree || !bytes.Equal(scorecard, secondScorecard) {
		t.Fatal("fixture copies did not preserve their independent paths and release identity")
	}
	artifacts, err := expectedArtifacts(testVersion)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{artifacts[0].name, "checksums.txt"} {
		firstPath, secondPath := filepath.Join(first, name), filepath.Join(second, name)
		firstInfo, err := os.Stat(firstPath)
		if err != nil {
			t.Fatal(err)
		}
		secondInfo, err := os.Stat(secondPath)
		if err != nil {
			t.Fatal(err)
		}
		if os.SameFile(firstInfo, secondInfo) {
			t.Fatalf("fixture copies share %s", name)
		}
		original, err := os.ReadFile(secondPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(firstPath, []byte("test-local mutation"), 0o644); err != nil {
			t.Fatal(err)
		}
		unchanged, err := os.ReadFile(secondPath)
		if err != nil || !bytes.Equal(unchanged, original) {
			t.Fatalf("mutating one fixture changed another %s: %v", name, err)
		}
	}
	scorecard[0] ^= 1
	third, thirdCommit, thirdTree, thirdScorecard := makeValidReleaseFixture(t)
	if thirdCommit != commit || thirdTree != tree || !bytes.Equal(thirdScorecard, secondScorecard) {
		t.Fatal("mutating a returned scorecard changed the cached release")
	}
	for _, name := range []string{artifacts[0].name, "checksums.txt"} {
		want, err := os.ReadFile(filepath.Join(second, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(third, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("a later fixture inherited a mutation to %s: %v", name, err)
		}
	}
}

func TestCheckReleaseRejectsUnexpectedTopLevelEntry(t *testing.T) {
	dir := makeStructuralReleaseFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("unexpected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkRelease(dir, testVersion, testEpoch, testCommit, testTree, testBuilderGoVersion, readiness.EmbeddedJSON()); err == nil || !strings.Contains(err.Error(), "unexpected release directory entry") {
		t.Fatalf("checkRelease() error = %v; want unexpected-entry error", err)
	}
}

func TestReleaseValidationRejectsSymlinkedDirectoryAndParent(t *testing.T) {
	target := t.TempDir()
	root := t.TempDir()
	linkedDirectory := filepath.Join(root, "dist")
	if err := os.Symlink(target, linkedDirectory); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	if err := checkDirectory(linkedDirectory, map[string]struct{}{}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("checkDirectory() error = %v; want symlink rejection", err)
	}

	inputRoot := filepath.Join(root, "input-target")
	if err := os.Mkdir(inputRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(inputRoot, "checksums.txt")
	if err := os.WriteFile(input, []byte("fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(root, "input-link")
	if err := os.Symlink(inputRoot, linkedParent); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	redirected := filepath.Join(linkedParent, "checksums.txt")
	if _, err := readFileBounded(redirected, maxChecksumSize); err == nil || !strings.Contains(err.Error(), "path parent") {
		t.Fatalf("readFileBounded() error = %v; want parent-symlink rejection", err)
	}
	if _, err := fileSHA256(redirected, maxChecksumSize); err == nil || !strings.Contains(err.Error(), "path parent") {
		t.Fatalf("fileSHA256() error = %v; want parent-symlink rejection", err)
	}
}

func TestCheckReleaseRejectsChecksumMismatch(t *testing.T) {
	dir := makeStructuralReleaseFixture(t)
	artifacts, err := expectedArtifacts(testVersion)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, artifacts[0].name)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("tampered")); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := checkRelease(dir, testVersion, testEpoch, testCommit, testTree, testBuilderGoVersion, readiness.EmbeddedJSON()); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("checkRelease() error = %v; want checksum mismatch", err)
	}
}

func TestCheckChecksumsRejectsNonCanonicalOrder(t *testing.T) {
	dir := makeStructuralReleaseFixture(t)
	path := filepath.Join(dir, "checksums.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	lines[0], lines[1] = lines[1], lines[0]
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	artifacts, _ := expectedArtifacts(testVersion)
	if err := checkChecksums(dir, artifacts); err == nil || !strings.Contains(err.Error(), "canonical entry") {
		t.Fatalf("checkChecksums() error = %v; want canonical-order error", err)
	}
}

func TestCheckChecksumsRejectsTextModeMarker(t *testing.T) {
	dir := makeStructuralReleaseFixture(t)
	path := filepath.Join(dir, "checksums.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(" *./"), []byte("  ./"), 1)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	artifacts, _ := expectedArtifacts(testVersion)
	if err := checkChecksums(dir, artifacts); err == nil || !strings.Contains(err.Error(), "binary-mode") {
		t.Fatalf("checkChecksums() error = %v; want binary-mode-marker error", err)
	}
}

func TestCheckTarGzipRejectsInvalidMembers(t *testing.T) {
	tests := []struct {
		name    string
		members []testMember
		want    string
	}{
		{
			name:    "nested path",
			members: []testMember{{name: "./LICENSE", mode: 0o644}},
			want:    "unexpected archive member",
		},
		{
			name: "duplicate",
			members: []testMember{
				{name: "LICENSE", mode: 0o644},
				{name: "LICENSE", mode: 0o644},
			},
			want: "duplicate archive member",
		},
		{
			name:    "wrong mode",
			members: []testMember{{name: "LICENSE", mode: 0o600}},
			want:    "has mode 0600; want 0644",
		},
		{
			name:    "wrong lifecycle mode",
			members: []testMember{{name: "install.sh", mode: 0o644}},
			want:    "has mode 0644; want 0755",
		},
		{
			name:    "nonzero owner",
			members: []testMember{{name: "LICENSE", mode: 0o644, uid: 1000, gid: 1000}},
			want:    "want 0:0",
		},
		{
			name: "noncanonical order",
			members: []testMember{
				{name: "README.md", mode: 0o644},
				{name: "LICENSE", mode: 0o644},
			},
			want: "out of canonical order",
		},
		{
			name:    "wrong timestamp",
			members: []testMember{{name: "LICENSE", mode: 0o644, modTime: time.Unix(testEpoch+2, 0)}},
			want:    "SOURCE_DATE_EPOCH",
		},
		{
			name:    "noncanonical ustar metadata",
			members: []testMember{{name: "LICENSE", mode: 0o644, uname: "root"}},
			want:    "non-canonical USTAR metadata",
		},
		{
			name:    "pax format",
			members: []testMember{{name: "LICENSE", mode: 0o644, format: tar.FormatPAX, pax: map[string]string{"comment": "noncanonical"}}},
			want:    "non-canonical USTAR metadata",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "release.tar.gz")
			writeTarGzip(t, path, test.members)
			_, err := readTarGzip(path, "leaguebridge", testEpoch)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("readTarGzip() error = %v; want substring %q", err, test.want)
			}
		})
	}
}

func TestCheckTarGzipRejectsNonCanonicalGzipOS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release.tar.gz")
	writeTarGzip(t, path, canonicalMembers("leaguebridge", true))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 10 {
		t.Fatal("gzip fixture is truncated")
	}
	data[9] = 3
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTarGzip(path, "leaguebridge", testEpoch); err == nil || !strings.Contains(err.Error(), "gzip header is not canonical") {
		t.Fatalf("readTarGzip() error = %v; want gzip-header rejection", err)
	}
}

func TestCheckTarGzipRejectsAlternateCompressionStream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release.tar.gz")
	members := canonicalMembers("leaguebridge", true)
	for index := range members {
		if members[index].name == "README.md" {
			members[index].body = []byte(strings.Repeat("canonical-compression-fixture-", 4096))
		}
	}
	writeTarGzipLevel(t, path, members, gzip.BestSpeed)
	if _, err := readTarGzip(path, "leaguebridge", testEpoch); err == nil || !strings.Contains(err.Error(), "compression contract") {
		t.Fatalf("readTarGzip() error = %v; want alternate-compression rejection", err)
	}
}

func TestCheckTarGzipRejectsTrailingAndConcatenatedStreams(t *testing.T) {
	for _, test := range []struct {
		name   string
		append func(*testing.T, string)
	}{
		{
			name: "trailing bytes",
			append: func(t *testing.T, path string) {
				appendFile(t, path, []byte("trailing"))
			},
		},
		{
			name: "additional gzip member",
			append: func(t *testing.T, path string) {
				file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				writer := gzip.NewWriter(file)
				if _, err := writer.Write([]byte("second member")); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "release.tar.gz")
			writeTarGzip(t, path, canonicalMembers("leaguebridge", true))
			test.append(t, path)
			_, err := readTarGzip(path, "leaguebridge", testEpoch)
			if err == nil || !strings.Contains(err.Error(), "trailing bytes or additional members") {
				t.Fatalf("readTarGzip() error = %v; want trailing-stream error", err)
			}
		})
	}

}

func TestCheckTarGzipRequiresLifecycleScripts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release.tar.gz")
	members := canonicalMembers("leaguebridge", true)
	writeTarGzip(t, path, members[:len(members)-1])
	_, err := readTarGzip(path, "leaguebridge", testEpoch)
	if err == nil || !strings.Contains(err.Error(), "want 9") {
		t.Fatalf("readTarGzip() error = %v; want exact-member-count error", err)
	}
}

func TestReleaseBinaryBindsTargetAndIdentity(t *testing.T) {
	repository, commit := makeCleanRepository(t)
	tree := strings.TrimSpace(runGit(t, repository, "rev-parse", "HEAD^{tree}"))
	linux := artifact{binaryName: "leaguebridge", goos: "linux", goarch: "amd64"}
	binary := buildTestBinary(t, repository, commit, linux, true, true, releaseIdentity(linux))
	if err := checkReleaseBinary(binary, linux, testVersion, testEpoch, commit, tree, testBuilderGoVersion, readiness.EmbeddedJSON()); err != nil {
		t.Fatalf("checkReleaseBinary() error = %v", err)
	}
	if err := checkReleaseBinary(binary, linux, testVersion, testEpoch, commit, tree, "go1.99.0", readiness.EmbeddedJSON()); err == nil || !strings.Contains(err.Error(), "Go builder version") {
		t.Fatalf("wrong-builder error = %v; want Go builder version rejection", err)
	}
	if err := checkReleaseBinary(binary, linux, testVersion, testEpoch+2, commit, tree, testBuilderGoVersion, readiness.EmbeddedJSON()); err == nil || !strings.Contains(err.Error(), "structured Go build ID") {
		t.Fatalf("wrong-epoch build ID error = %v; want structured-contract rejection", err)
	}
	if err := checkReleaseBinary(binary, linux, testVersion, testEpoch, commit, testTree, testBuilderGoVersion, readiness.EmbeddedJSON()); err == nil || !strings.Contains(err.Error(), "structured Go build ID") {
		t.Fatalf("wrong-tree build ID error = %v; want source-tree contract rejection", err)
	}

	freeBSD := linux
	freeBSD.goos = "freebsd"
	if err := checkReleaseBinary(binary, freeBSD, testVersion, testEpoch, commit, tree, testBuilderGoVersion, readiness.EmbeddedJSON()); err == nil || !strings.Contains(err.Error(), "ELF OSABI") {
		t.Fatalf("renamed Linux binary error = %v; want target container-identity rejection", err)
	}

	missingIdentity := append([]byte(nil), binary...)
	identity := []byte(releaseIdentity(linux))
	location := strings.Index(string(missingIdentity), string(identity))
	if location < 0 {
		t.Fatal("test binary is missing release identity")
	}
	copy(missingIdentity[location:location+len(identity)], strings.Repeat("x", len(identity)))
	if err := checkReleaseBinary(missingIdentity, linux, testVersion, testEpoch, commit, tree, testBuilderGoVersion, readiness.EmbeddedJSON()); err == nil || !strings.Contains(err.Error(), "occurs 0 times") {
		t.Fatalf("missing identity error = %v", err)
	}

	duplicateIdentity := append(append([]byte(nil), binary...), identity...)
	if err := checkReleaseBinary(duplicateIdentity, linux, testVersion, testEpoch, commit, tree, testBuilderGoVersion, readiness.EmbeddedJSON()); err == nil || !strings.Contains(err.Error(), "occurs 2 times") {
		t.Fatalf("duplicate identity error = %v", err)
	}

	verification := []byte(readiness.ExpectedRepositoryEvidenceVerification())
	missingVerification := append([]byte(nil), binary...)
	verificationLocation := bytes.Index(missingVerification, verification)
	if verificationLocation < 0 {
		t.Fatal("test binary is missing repository evidence verification")
	}
	copy(missingVerification[verificationLocation:verificationLocation+len(verification)], bytes.Repeat([]byte{'x'}, len(verification)))
	if err := checkReleaseBinary(missingVerification, linux, testVersion, testEpoch, commit, tree, testBuilderGoVersion, readiness.EmbeddedJSON()); err == nil || !strings.Contains(err.Error(), "repository evidence verification occurs 0 times") {
		t.Fatalf("missing repository verification error = %v", err)
	}

	mutatedScorecard := append([]byte(nil), binary...)
	scorecard := readiness.EmbeddedJSON()
	scorecardLocation := bytes.Index(mutatedScorecard, scorecard)
	if scorecardLocation < 0 {
		t.Fatal("test binary is missing the exact embedded readiness scorecard")
	}
	mutatedScorecard[scorecardLocation] ^= 1
	if err := checkReleaseBinary(mutatedScorecard, linux, testVersion, testEpoch, commit, tree, testBuilderGoVersion, readiness.EmbeddedJSON()); err == nil || !strings.Contains(err.Error(), "embedded readiness scorecard occurs 0 times") {
		t.Fatalf("mutated embedded scorecard error = %v", err)
	}

	if err := os.WriteFile(filepath.Join(repository, "DIRTY"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	vcsBinary := buildTestBinaryWithVCS(t, repository, commit, linux, releaseIdentity(linux))
	if err := checkReleaseBinary(vcsBinary, linux, testVersion, testEpoch, commit, tree, testBuilderGoVersion, readiness.EmbeddedJSON()); err == nil || !strings.Contains(err.Error(), "unexpected Go build setting") {
		t.Fatalf("VCS-stamped binary error = %v; want absent-VCS-setting rejection", err)
	}
}

func TestReleaseBinaryRequiresTrimpath(t *testing.T) {
	repository, commit := makeCleanRepository(t)
	tree := strings.TrimSpace(runGit(t, repository, "rev-parse", "HEAD^{tree}"))
	item := artifact{binaryName: "leaguebridge", goos: "linux", goarch: "amd64"}
	binary := buildTestBinary(t, repository, commit, item, false, true, releaseIdentity(item))
	if err := checkReleaseBinary(binary, item, testVersion, testEpoch, commit, tree, testBuilderGoVersion, readiness.EmbeddedJSON()); err == nil || !strings.Contains(err.Error(), "-trimpath") {
		t.Fatalf("checkReleaseBinary() error = %v; want trimpath error", err)
	}
}

func TestReleaseBinaryRequiresStripping(t *testing.T) {
	repository, commit := makeCleanRepository(t)
	tree := strings.TrimSpace(runGit(t, repository, "rev-parse", "HEAD^{tree}"))
	item := artifact{binaryName: "leaguebridge", goos: "linux", goarch: "amd64"}
	binary := buildTestBinary(t, repository, commit, item, true, false, releaseIdentity(item))
	if err := checkReleaseBinary(binary, item, testVersion, testEpoch, commit, tree, testBuilderGoVersion, readiness.EmbeddedJSON()); err == nil || !strings.Contains(err.Error(), "canonical -") {
		t.Fatalf("checkReleaseBinary() error = %v; want stripping error", err)
	}
}

func TestReleaseBinaryRejectsContainerIdentityMutations(t *testing.T) {
	repository, commit := makeCleanRepository(t)
	tree := strings.TrimSpace(runGit(t, repository, "rev-parse", "HEAD^{tree}"))

	tests := []struct {
		name   string
		item   artifact
		mutate func(*testing.T, []byte)
		want   string
	}{
		{
			name: "ELF class",
			item: artifact{binaryName: "leaguebridge", goos: "linux", goarch: "amd64"},
			mutate: func(t *testing.T, data []byte) {
				t.Helper()
				data[4] = byte(elf.ELFCLASS32)
			},
			want: "ELF class",
		},
		{
			name: "ELF data encoding",
			item: artifact{binaryName: "leaguebridge", goos: "linux", goarch: "amd64"},
			mutate: func(t *testing.T, data []byte) {
				t.Helper()
				data[5] = byte(elf.ELFDATA2MSB)
			},
			want: "ELF data encoding",
		},
		{
			name: "ELF machine",
			item: artifact{binaryName: "leaguebridge", goos: "linux", goarch: "amd64"},
			mutate: func(t *testing.T, data []byte) {
				t.Helper()
				binary.LittleEndian.PutUint16(data[18:20], uint16(elf.EM_386))
			},
			want: "ELF machine",
		},
		{
			name: "ELF type",
			item: artifact{binaryName: "leaguebridge", goos: "linux", goarch: "amd64"},
			mutate: func(t *testing.T, data []byte) {
				t.Helper()
				binary.LittleEndian.PutUint16(data[16:18], uint16(elf.ET_DYN))
			},
			want: "ELF type",
		},
		{
			name: "ELF OSABI",
			item: artifact{binaryName: "leaguebridge", goos: "linux", goarch: "amd64"},
			mutate: func(t *testing.T, data []byte) {
				t.Helper()
				data[7] = byte(elf.ELFOSABI_FREEBSD)
			},
			want: "ELF OSABI",
		},
	}

	binaries := make(map[string][]byte)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := test.item.goos + "/" + test.item.goarch
			binaryData, ok := binaries[key]
			if !ok {
				binaryData = buildTestBinary(t, repository, commit, test.item, true, true, releaseIdentity(test.item))
				binaries[key] = binaryData
				if err := checkBinaryContainer(binaryData, test.item); err != nil {
					t.Fatalf("valid container rejected: %v", err)
				}
			}
			mutated := append([]byte(nil), binaryData...)
			test.mutate(t, mutated)
			err := checkReleaseBinary(mutated, test.item, testVersion, testEpoch, commit, tree, testBuilderGoVersion, readiness.EmbeddedJSON())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("checkReleaseBinary() error = %v; want container-identity rejection containing %q", err, test.want)
			}
		})
	}
}

func TestReleaseBinaryRejectsAdditionalCompiledModule(t *testing.T) {
	repository, commit := makeExternalDependencyRepository(t)
	tree := strings.TrimSpace(runGit(t, repository, "rev-parse", "HEAD^{tree}"))
	item := artifact{binaryName: "leaguebridge", goos: "linux", goarch: "amd64"}
	binary := buildTestBinary(t, repository, commit, item, true, true, releaseIdentity(item))
	if err := checkReleaseBinary(binary, item, testVersion, testEpoch, commit, tree, testBuilderGoVersion, readiness.EmbeddedJSON()); err == nil || !strings.Contains(err.Error(), "compiled dependency modules") {
		t.Fatalf("checkReleaseBinary() error = %v; want additional-module rejection", err)
	}
	digest := sha256.Sum256(binary)
	if _, err := expectedSBOM(binary, item, testVersion, testEpoch, fmt.Sprintf("%x", digest)); err == nil || !strings.Contains(err.Error(), "compiled dependency modules") {
		t.Fatalf("expectedSBOM() error = %v; want additional-module rejection", err)
	}
}

func TestCanonicalProductionDependencyFailsClosed(t *testing.T) {
	approved := func() *debug.Module {
		return &debug.Module{
			Path:    packageinfo.ProductionDependencyPath,
			Version: packageinfo.ProductionDependencyVersion,
		}
	}
	got, err := canonicalProductionDependency([]*debug.Module{approved()})
	if err != nil {
		t.Fatalf("canonicalProductionDependency() error = %v", err)
	}
	if got.Path != packageinfo.ProductionDependencyPath || got.Version != packageinfo.ProductionDependencyVersion || got.Sum != packageinfo.ProductionDependencySum || got.Replace != nil {
		t.Fatalf("canonicalProductionDependency() = %+v", got)
	}

	tests := []struct {
		name         string
		dependencies func() []*debug.Module
		want         string
	}{
		{name: "missing", dependencies: func() []*debug.Module { return nil }, want: "exactly one"},
		{name: "nil", dependencies: func() []*debug.Module { return []*debug.Module{nil} }, want: "is nil"},
		{name: "wrong path", dependencies: func() []*debug.Module {
			dependency := approved()
			dependency.Path = "example.com/unapproved"
			return []*debug.Module{dependency}
		}, want: "path"},
		{name: "wrong version", dependencies: func() []*debug.Module {
			dependency := approved()
			dependency.Version = "v1.1.0"
			return []*debug.Module{dependency}
		}, want: "version"},
		{name: "wrong sum", dependencies: func() []*debug.Module {
			dependency := approved()
			dependency.Sum = testDependencyH1Sum
			return []*debug.Module{dependency}
		}, want: "sum"},
		{name: "nonempty pinned sum", dependencies: func() []*debug.Module {
			dependency := approved()
			dependency.Sum = packageinfo.ProductionDependencySum
			return []*debug.Module{dependency}
		}, want: "sum"},
		{name: "replacement", dependencies: func() []*debug.Module {
			dependency := approved()
			dependency.Replace = &debug.Module{Path: dependency.Path, Version: dependency.Version, Sum: dependency.Sum}
			return []*debug.Module{dependency}
		}, want: "replacement"},
		{name: "additional", dependencies: func() []*debug.Module {
			return []*debug.Module{approved(), {Path: "example.com/additional", Version: "v1.0.0", Sum: testDependencyH1Sum}}
		}, want: "exactly one"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := canonicalProductionDependency(test.dependencies()); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("canonicalProductionDependency() error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestStrictSBOMBindsHashVersionTargetAndEpoch(t *testing.T) {
	repository, commit := makeCleanRepository(t)
	item := artifact{binaryName: "leaguebridge", goos: "linux", goarch: "amd64"}
	binary := buildTestBinary(t, repository, commit, item, true, true, releaseIdentity(item))
	digest := sha256.Sum256(binary)
	hash := fmt.Sprintf("%x", digest)
	valid := generateSBOM(t, item, binary)
	if err := checkSBOM(valid, binary, item, testVersion, testEpoch, hash); err != nil {
		t.Fatalf("checkSBOM(valid) error = %v", err)
	}

	for _, test := range []struct {
		name string
		old  string
		new  string
	}{
		{name: "hash", old: hash, new: strings.Repeat("b", 64)},
		{name: "version", old: testVersion, new: "v9.9.9"},
		{name: "target", old: "linux", new: "freebsd"},
		{name: "epoch", old: time.Unix(testEpoch, 0).UTC().Format(time.RFC3339), new: time.Unix(testEpoch+2, 0).UTC().Format(time.RFC3339)},
	} {
		t.Run(test.name, func(t *testing.T) {
			tampered := []byte(strings.Replace(string(valid), test.old, test.new, 1))
			if err := checkSBOM(tampered, binary, item, testVersion, testEpoch, hash); err == nil {
				t.Fatal("checkSBOM() unexpectedly accepted tampered document")
			}
		})
	}
}

func TestStrictPackageManifestBindsPayloadTargetAndProvenance(t *testing.T) {
	item := artifact{
		name:       "leaguebridge_1.2.3_linux_amd64.tar.gz",
		binaryName: "leaguebridge",
		goos:       "linux",
		goarch:     "amd64",
	}
	members := canonicalMembers(item.binaryName, true)
	payload := archivePayload{members: make(map[string][]byte, len(members))}
	for _, member := range members {
		body := member.body
		if body == nil {
			body = []byte("content for " + member.name)
		}
		payload.members[member.name] = body
		if member.name == packageinfo.ManifestName {
			payload.packageManifest = body
		}
	}
	bodies := make(map[string][]byte, len(payload.members)-1)
	for name, body := range payload.members {
		if name != packageinfo.ManifestName {
			bodies[name] = body
		}
	}
	manifest, err := packageinfo.Build(testVersion, item.goos, item.goarch, testEpoch, testCommit, testTree, testBuilderGoVersion, bodies)
	if err != nil {
		t.Fatal(err)
	}
	payload.packageManifest, err = packageinfo.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	payload.members[packageinfo.ManifestName] = payload.packageManifest
	if err := checkPackageManifest(payload, item, testVersion, testEpoch, testCommit, testTree, testBuilderGoVersion); err != nil {
		t.Fatalf("checkPackageManifest(valid) error = %v", err)
	}

	for _, test := range []struct {
		name string
		old  string
		new  string
	}{
		{name: "target", old: `"goos": "linux"`, new: `"goos": "freebsd"`},
		{name: "commit", old: testCommit, new: strings.Repeat("a", len(testCommit))},
		{name: "tree", old: testTree, new: strings.Repeat("c", len(testTree))},
		{name: "builder", old: testBuilderGoVersion, new: "go1.99.0"},
		{name: "payload hash", old: manifest.Payload[0].SHA256, new: strings.Repeat("b", 64)},
		{name: "validation scope", old: packageinfo.ValidationScope, new: "runtime-validated"},
	} {
		t.Run(test.name, func(t *testing.T) {
			tampered := payload
			tampered.packageManifest = []byte(strings.Replace(string(payload.packageManifest), test.old, test.new, 1))
			if err := checkPackageManifest(tampered, item, testVersion, testEpoch, testCommit, testTree, testBuilderGoVersion); err == nil {
				t.Fatal("checkPackageManifest() unexpectedly accepted tampered document")
			}
		})
	}

	t.Run("payload bytes", func(t *testing.T) {
		tampered := payload
		tampered.members = make(map[string][]byte, len(payload.members))
		for name, body := range payload.members {
			tampered.members[name] = body
		}
		tampered.members["README.md"] = []byte("tampered readme")
		if err := checkPackageManifest(tampered, item, testVersion, testEpoch, testCommit, testTree, testBuilderGoVersion); err == nil {
			t.Fatal("checkPackageManifest() accepted payload bytes that do not match the manifest")
		}
	})
}

func TestParseSourceDateEpoch(t *testing.T) {
	if got, err := parseSourceDateEpoch(fmt.Sprint(testEpoch)); err != nil || got != testEpoch {
		t.Fatalf("parseSourceDateEpoch() = %d, %v", got, err)
	}
	for _, value := range []string{"", "-1", "+1", "abc", "0", "999999999999999999999"} {
		if _, err := parseSourceDateEpoch(value); err == nil {
			t.Errorf("parseSourceDateEpoch(%q) unexpectedly succeeded", value)
		}
	}
	if err := validateCommit(testCommit); err != nil {
		t.Fatalf("validateCommit(valid) error = %v", err)
	}
	if err := validateTree(testTree); err != nil {
		t.Fatalf("validateTree(valid) error = %v", err)
	}
	for _, tree := range []string{"", strings.Repeat("A", 40), strings.Repeat("a", 39), strings.Repeat("g", 40)} {
		if err := validateTree(tree); err == nil {
			t.Errorf("validateTree(%q) unexpectedly succeeded", tree)
		}
	}
	for _, commit := range []string{"", "ABCDEF0123456789abcdef0123456789abcdef01", strings.Repeat("a", 39), strings.Repeat("g", 40)} {
		if err := validateCommit(commit); err == nil {
			t.Errorf("validateCommit(%q) unexpectedly succeeded", commit)
		}
	}
}

func TestProductionBuilderVersionIsExact(t *testing.T) {
	if err := validateProductionBuilderGoVersion(productionBuilderGoVersion); err != nil {
		t.Fatalf("validateProductionBuilderGoVersion(valid) error = %v", err)
	}
	for _, value := range []string{"", "go1.24.13", packageinfo.MinimumSupportedGoVersion, "go1.26.3", "go1.27.0", "devel go1.28"} {
		if err := validateProductionBuilderGoVersion(value); err == nil {
			t.Errorf("validateProductionBuilderGoVersion(%q) unexpectedly succeeded", value)
		}
	}
}

func TestExpectedArtifactsRejectsInvalidVersionAndCarriesTargets(t *testing.T) {
	for _, version := range []string{"", "1.2.3", "v1.02.3", "v1.2.3/escape"} {
		if _, err := expectedArtifacts(version); err == nil {
			t.Errorf("expectedArtifacts(%q) unexpectedly succeeded", version)
		}
	}
	artifacts, err := expectedArtifacts(testVersion)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 9 {
		t.Fatalf("artifact count = %d; want 9", len(artifacts))
	}
	wantTargets := map[string]bool{
		"linux/amd64": true, "linux/arm64": true,
		"freebsd/amd64": true, "freebsd/arm64": true,
		"openbsd/amd64": true, "openbsd/arm64": true,
		"netbsd/amd64": true, "netbsd/arm64": true,
		"dragonfly/amd64": true,
	}
	for _, item := range artifacts {
		if item.goos == "" || item.goarch == "" || !strings.Contains(item.name, "_"+item.goos+"_"+item.goarch) {
			t.Errorf("artifact is not target-bound: %+v", item)
		}
		delete(wantTargets, item.goos+"/"+item.goarch)
	}
	if len(wantTargets) != 0 {
		t.Fatalf("missing exact artifact targets: %v", wantTargets)
	}
}

var canonicalReleaseCache struct {
	sync.Mutex
	fixture *canonicalReleaseSnapshot
}

type canonicalReleaseSnapshot struct {
	commit, tree, scorecard string
	files                   map[string]string
}

// Cache only the completed, immutable release bytes. Each caller gets its own
// ordinary files and scorecard slice, so mutations cannot affect another test.
// The nondefault card lets both acceptance tests share the expensive nine-target
// builds and Go best-compression streams while exercising explicit card selection.
func makeValidReleaseFixture(t *testing.T) (string, string, string, []byte) {
	t.Helper()
	canonicalReleaseCache.Lock()
	defer canonicalReleaseCache.Unlock()
	if canonicalReleaseCache.fixture == nil {
		scorecard := append(readiness.EmbeddedJSON(), '\n')
		dir, commit, tree := makeValidReleaseFixtureWithScorecard(t, scorecard)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := &canonicalReleaseSnapshot{commit: commit, tree: tree, scorecard: string(scorecard), files: make(map[string]string, len(entries))}
		for _, entry := range entries {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			snapshot.files[entry.Name()] = string(data)
		}
		canonicalReleaseCache.fixture = snapshot
	}
	snapshot := canonicalReleaseCache.fixture
	dir := t.TempDir()
	for name, data := range snapshot.files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, snapshot.commit, snapshot.tree, []byte(snapshot.scorecard)
}

func makeValidReleaseFixtureWithScorecard(t *testing.T, scorecard []byte) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	canonicalTar := buildCanonicalTarFixtureTool(t)
	repository, commit := makeCleanRepository(t)
	if scorecard != nil {
		path := filepath.Join(repository, "internal", "readiness", "data", "scorecard.json")
		if err := os.WriteFile(path, scorecard, 0o644); err != nil {
			t.Fatal(err)
		}
		runGit(t, repository, "add", "internal/readiness/data/scorecard.json")
		runGit(t, repository, "commit", "--quiet", "--no-gpg-sign", "-m", "selected release scorecard")
		commit = strings.TrimSpace(runGit(t, repository, "rev-parse", "HEAD"))
	}
	tree := strings.TrimSpace(runGit(t, repository, "rev-parse", "HEAD^{tree}"))
	artifacts, err := expectedArtifacts(testVersion)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range artifacts {
		binaryData := buildTestBinary(t, repository, commit, item, true, true, releaseIdentity(item))
		sbom := generateSBOM(t, item, binaryData)
		members := canonicalMembers(item.binaryName, true)
		for index := range members {
			switch members[index].name {
			case item.binaryName:
				members[index].body = binaryData
			case "SBOM.spdx.json":
				members[index].body = sbom
			}
		}
		bodies := make(map[string][]byte, len(members)-1)
		for _, member := range members {
			if member.name == packageinfo.ManifestName {
				continue
			}
			body := member.body
			if body == nil {
				body = []byte("content for " + member.name)
			}
			bodies[member.name] = body
		}
		packageManifest, err := packageinfo.Build(testVersion, item.goos, item.goarch, testEpoch, commit, tree, testBuilderGoVersion, bodies)
		if err != nil {
			t.Fatal(err)
		}
		packageManifestData, err := packageinfo.Marshal(packageManifest)
		if err != nil {
			t.Fatal(err)
		}
		for index := range members {
			if members[index].name == packageinfo.ManifestName {
				members[index].body = packageManifestData
			}
		}
		path := filepath.Join(dir, item.name)
		writeCanonicalReleaseFixture(t, canonicalTar, path, members)
	}
	writeChecksums(t, dir, artifacts)
	return dir, commit, tree
}

// Fixture generation uses the repository's Go compressor built without race
// instrumentation. The release validator still reconstructs and compares every
// archive under -race; malformed-archive tests retain their independent writer.
func buildCanonicalTarFixtureTool(t *testing.T) string {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	goExecutable := filepath.Join(runtime.GOROOT(), "bin", "go")
	tool := filepath.Join(t.TempDir(), "canonicaltar")
	if runtime.GOOS == "windows" {
		goExecutable += ".exe"
		tool += ".exe"
	}
	command := exec.Command(goExecutable, "build", "-mod=vendor", "-buildvcs=false", "-o", tool, "./tools/canonicaltar")
	command.Dir = source
	command.Env = append(os.Environ(),
		"CGO_ENABLED=0", "GOENV=off", "GOEXPERIMENT=", "GOFLAGS=",
		"GOTOOLCHAIN=local", "GOWORK=off", "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build canonical fixture compressor: %v\n%s", err, output)
	}
	return tool
}

func writeCanonicalReleaseFixture(t *testing.T, tool, path string, members []testMember) {
	t.Helper()
	payload := t.TempDir()
	for _, member := range members {
		body := member.body
		if body == nil {
			body = []byte("content for " + member.name)
		}
		if err := os.WriteFile(filepath.Join(payload, member.name), body, member.mode); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command(tool, "-root", payload, "-output", path, "-source-date-epoch", fmt.Sprint(testEpoch))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("create canonical release fixture: %v\n%s", err, output)
	}
}

func makeStructuralReleaseFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	artifacts, err := expectedArtifacts(testVersion)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range artifacts {
		members := canonicalMembers(item.binaryName, true)
		path := filepath.Join(dir, item.name)
		writeTarGzip(t, path, members)
	}
	writeChecksums(t, dir, artifacts)
	return dir
}

func canonicalMembers(binaryName string, includeLifecycle bool) []testMember {
	names := expectedMemberNames(binaryName, includeLifecycle)
	members := make([]testMember, 0, len(names))
	for _, name := range names {
		mode, _ := expectedMemberMode(name, binaryName, includeLifecycle)
		members = append(members, testMember{name: name, mode: mode})
	}
	return members
}

func releaseIdentity(item artifact) string {
	return strings.Join([]string{"leaguebridge-release", testVersion, item.goos, item.goarch}, ":")
}

func generateSBOM(t *testing.T, item artifact, binaryData []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(binaryData)
	data, err := expectedSBOM(binaryData, item, testVersion, testEpoch, fmt.Sprintf("%x", digest))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func makeCleanRepository(t *testing.T) (string, string) {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	repository := filepath.Join(t.TempDir(), "repository")
	if err := os.MkdirAll(repository, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		copyTestFile(t, filepath.Join(source, name), filepath.Join(repository, name), 0o644)
	}
	for _, directory := range []string{"cmd", "internal", "vendor"} {
		sourceDirectory := filepath.Join(source, directory)
		err := filepath.WalkDir(sourceDirectory, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(source, path)
			if err != nil {
				return err
			}
			destination := filepath.Join(repository, relative)
			if entry.IsDir() {
				return os.MkdirAll(destination, 0o755)
			}
			if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
				return fmt.Errorf("unsupported fixture source entry %q", path)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(destination, data, 0o644)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, repository, "init", "--quiet")
	runGit(t, repository, "config", "user.name", "LeagueBridge Release Test")
	runGit(t, repository, "config", "user.email", "release-test@example.invalid")
	runGit(t, repository, "config", "core.autocrlf", "false")
	runGit(t, repository, "config", "core.longpaths", "true")
	runGit(t, repository, "add", "--all")
	runGit(t, repository, "commit", "--quiet", "--no-gpg-sign", "-m", "release fixture")
	commit := strings.TrimSpace(runGit(t, repository, "rev-parse", "HEAD"))
	if err := validateCommit(commit); err != nil {
		t.Fatalf("temporary repository commit: %v", err)
	}
	if status := runGit(t, repository, "status", "--porcelain"); status != "" {
		t.Fatalf("temporary repository is dirty: %q", status)
	}
	return repository, commit
}

func makeExternalDependencyRepository(t *testing.T) (string, string) {
	t.Helper()
	repository, _ := makeCleanRepository(t)
	dependency := filepath.Join(repository, "vendor", "example.com", "release-fixture")
	if err := os.MkdirAll(dependency, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dependency, "fixture.go"), []byte("package fixture\n\nfunc Value() string { return \"fixture\" }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mainFixture := "package main\n\nimport _ \"example.com/release-fixture\"\n"
	if err := os.WriteFile(filepath.Join(repository, "cmd", "leaguebridge", "external_fixture.go"), []byte(mainFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	appendTestFile(t, filepath.Join(repository, "go.mod"), "\nrequire example.com/release-fixture v0.0.0\n")
	appendTestFile(t, filepath.Join(repository, "vendor", "modules.txt"), "# example.com/release-fixture v0.0.0\n## explicit; go 1.24.0\nexample.com/release-fixture\n")
	runGit(t, repository, "add", "--all")
	runGit(t, repository, "commit", "--quiet", "--no-gpg-sign", "-m", "add external fixture")
	return repository, strings.TrimSpace(runGit(t, repository, "rev-parse", "HEAD"))
}

func copyTestFile(t *testing.T, source, destination string, mode os.FileMode) {
	t.Helper()
	file, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, file); err != nil {
		output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
}

func appendTestFile(t *testing.T, name, value string) {
	t.Helper()
	file, err := os.OpenFile(name, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(value); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func runGit(t *testing.T, repository string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = repository
	command.Env = append(os.Environ(),
		"GIT_AUTHOR_DATE=2026-08-26T00:00:00Z",
		"GIT_COMMITTER_DATE=2026-08-26T00:00:00Z",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func buildTestBinary(t *testing.T, repository, commit string, item artifact, trimpath, stripped bool, identity string) []byte {
	return buildTestBinaryMode(t, repository, commit, item, trimpath, stripped, false, identity)
}

func buildTestBinaryWithVCS(t *testing.T, repository, commit string, item artifact, identity string) []byte {
	return buildTestBinaryMode(t, repository, commit, item, true, true, true, identity)
}

func buildTestBinaryMode(t *testing.T, repository, commit string, item artifact, trimpath, stripped, buildVCS bool, identity string) []byte {
	t.Helper()
	if testBuilderGoVersion != productionBuilderGoVersion && testBuilderGoVersion != packageinfo.MinimumSupportedGoVersion {
		t.Skipf("binary fixture tests require Go %s or the source-compatibility Go %s; running %s", productionBuilderGoVersion, packageinfo.MinimumSupportedGoVersion, testBuilderGoVersion)
	}
	binaryPath := filepath.Join(t.TempDir(), item.binaryName)
	buildDate := time.Unix(testEpoch, 0).UTC().Format(time.RFC3339)
	tree := strings.TrimSpace(runGit(t, repository, "rev-parse", commit+"^{tree}"))
	scorecard, err := os.ReadFile(filepath.Join(repository, "internal", "readiness", "data", "scorecard.json"))
	if err != nil {
		t.Fatal(err)
	}
	ldflagParts := []string{
		"-buildid=" + expectedBuildID(testVersion, item, testEpoch, commit, tree, testBuilderGoVersion),
		"-X", mainModulePath + "/internal/version.Version=" + testVersion,
		"-X", mainModulePath + "/internal/version.Commit=" + commit,
		"-X", mainModulePath + "/internal/version.BuildDate=" + buildDate,
		"-X", mainModulePath + "/internal/version.ReleaseIdentity=" + identity,
		"-X", mainModulePath + "/internal/version.RepositoryEvidenceVerification=" + scorecardVerification(scorecard),
	}
	if stripped {
		ldflagParts = append([]string{"-s", "-w"}, ldflagParts...)
	}
	ldflags := strings.Join(ldflagParts, " ")
	arguments := []string{"build", "-mod=vendor", fmt.Sprintf("-buildvcs=%t", buildVCS), "-ldflags", ldflags, "-o", binaryPath}
	if trimpath {
		arguments = append(arguments, "-trimpath")
	}
	arguments = append(arguments, "./cmd/leaguebridge")
	goExecutable := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		goExecutable += ".exe"
	}
	command := exec.Command(goExecutable, arguments...)
	command.Dir = repository
	architectureSetting := "GOAMD64=v1"
	if item.goarch == "arm64" {
		architectureSetting = "GOARM64=v8.0"
	}
	command.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOENV=off",
		"GOEXPERIMENT=",
		"GOFLAGS=",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"GOOS="+item.goos,
		"GOARCH="+item.goarch,
		"GOAMD64=",
		"GOARM64=",
		architectureSetting,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s/%s test binary: %v\n%s", item.goos, item.goarch, err, output)
	}
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeTarGzip(t *testing.T, path string, members []testMember) {
	writeTarGzipLevel(t, path, members, gzip.BestCompression)
}

func writeTarGzipLevel(t *testing.T, path string, members []testMember, level int) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter, err := gzip.NewWriterLevel(file, level)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter.Header = gzip.Header{OS: 255}
	tarWriter := tar.NewWriter(gzipWriter)
	for _, member := range members {
		body := member.body
		if body == nil {
			body = []byte("content for " + member.name)
		}
		modTime := member.modTime
		if modTime.IsZero() {
			modTime = time.Unix(testEpoch, 0)
		}
		header := &tar.Header{
			Name:       member.name,
			Mode:       int64(member.mode),
			Size:       int64(len(body)),
			Typeflag:   tar.TypeReg,
			Uid:        member.uid,
			Gid:        member.gid,
			ModTime:    modTime,
			Format:     member.format,
			Uname:      member.uname,
			PAXRecords: member.pax,
		}
		if header.Format == tar.FormatUnknown {
			header.Format = tar.FormatUSTAR
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path string, data []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeChecksums(t *testing.T, dir string, artifacts []artifact) {
	t.Helper()
	lines := make(map[string]string, len(artifacts))
	names := make([]string, 0, len(artifacts))
	for _, item := range artifacts {
		data, err := os.ReadFile(filepath.Join(dir, item.name))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		lines[item.name] = fmt.Sprintf("%x *./%s", digest, item.name)
		names = append(names, item.name)
	}
	sort.Strings(names)
	ordered := make([]string, 0, len(names))
	for _, name := range names {
		ordered = append(ordered, lines[name])
	}
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(strings.Join(ordered, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
