package nativepackageattestation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/nativepackage"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
)

const (
	testCommit = "0123456789abcdef0123456789abcdef01234567"
	testTree   = "89abcdef0123456789abcdef0123456789abcdef"
)

func TestCIPackageV1MatrixIncludesLinuxArm64Packages(t *testing.T) {
	if !validFamilyTarget("debian", target{GOOS: "linux", GOARCH: "amd64"}) ||
		!validFamilyTarget("debian", target{GOOS: "linux", GOARCH: "arm64"}) ||
		!validFamilyTarget("rpm", target{GOOS: "linux", GOARCH: "arm64"}) ||
		!validFamilyTarget("freebsd-pkg", target{GOOS: "freebsd", GOARCH: "arm64"}) {
		t.Fatal("native package matrix targets are no longer accepted")
	}
	if job, runner, architecture, host := expectedExecution(target{GOOS: "linux", GOARCH: "arm64"}, "debian"); job != "native-package-linux" || runner != "Linux" || architecture != "ARM64" || host != "hosted" {
		t.Fatalf("Linux arm64 execution = %q/%q/%q/%q", job, runner, architecture, host)
	}
}

func TestBuildInventoriesVerifiedPackageStagingAndInstallEvidence(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	document := createPackageFixture(t, "debian", "linux", "amd64", nativepackage.FamilyDebian, "deb")
	if len(document.Subjects) != maxEvidenceFiles {
		t.Fatalf("subject count = %d, want %d", len(document.Subjects), maxEvidenceFiles)
	}
	if document.Execution.Package.Version != "v1.2.3" || document.Execution.Package.Family != string(nativepackage.FamilyDebian) || document.Execution.Package.Format != "deb" {
		t.Fatalf("package identity = %+v", document.Execution.Package)
	}
	if document.Execution.Package.Filename != "leaguebridge_1.2.3~ci_amd64.deb" {
		t.Fatalf("Debian package filename = %q; want a Debian epoch-safe filename with tilde", document.Execution.Package.Filename)
	}
	roles := map[string]int{}
	for _, item := range document.Subjects {
		roles[item.Role]++
	}
	if roles["package"] != 1 || roles["staging-manifest"] != 1 || roles["staging-payload"] != 7 || roles["package-install-evidence"] != 1 {
		t.Fatalf("subject roles = %+v", roles)
	}
	data, err := marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(data, []byte("\n")) || bytes.Contains(data, []byte(`"score"`)) || bytes.Contains(data, []byte(`"passed"`)) {
		t.Fatalf("package subject is not canonical and score-free: %s", data)
	}
}

func TestBuildRejectsUnsafePathsAndUnverifiedPackageEvidence(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	document := createPackageFixture(t, "debian", "linux", "amd64", nativepackage.FamilyDebian, "deb")
	input := BuildRequest{
		GeneratedAt: document.GeneratedAt, Repository: document.Source.Repository,
		Commit: document.Source.Commit, Tree: document.Source.Tree, Ref: document.Source.Ref,
		Workflow: document.Source.Workflow, WorkflowRef: document.Source.WorkflowRef,
		WorkflowSHA: document.Source.WorkflowSHA, RunID: document.Source.RunID,
		RunAttempt: document.Source.RunAttempt, Job: document.Execution.Job,
		RunnerOS: document.Execution.RunnerOS, RunnerArchitecture: document.Execution.RunnerArchitecture,
		HostClass: document.Execution.HostClass, GoVersion: document.Execution.GoVersion,
		Command: document.Execution.Command, TargetGOOS: document.Execution.Target.GOOS,
		TargetGOARCH: document.Execution.Target.GOARCH, Family: document.Execution.Package.Family,
		Format: document.Execution.Package.Format, PackagePath: findRolePath(document.Subjects, "package"),
		StagingDir:      filepath.ToSlash(filepath.Dir(document.Execution.Package.StagingManifestPath)),
		InstallEvidence: document.Execution.Package.InstallEvidencePath,
		OutputPath:      "subjects/debian-generated.json",
	}
	if _, err := Build(input); err != nil {
		t.Fatalf("valid package input was rejected: %v", err)
	}
	for _, test := range []struct {
		name, want string
		edit       func(*BuildRequest)
	}{
		{"traversing package path", "package path", func(value *BuildRequest) { value.PackagePath = "../package.deb" }},
		{"traversing staging path", "staging directory", func(value *BuildRequest) { value.StagingDir = "../staging" }},
		{"traversing install evidence", "install evidence path", func(value *BuildRequest) { value.InstallEvidence = "../install.txt" }},
		{"traversing output path", "output path", func(value *BuildRequest) { value.OutputPath = "../subject.json" }},
		{"wrong package family", "does not match", func(value *BuildRequest) { value.Family = "rpm" }},
		{"missing package file", "open subject", func(value *BuildRequest) {
			value.PackagePath = "packages/missing/" + document.Execution.Package.Filename
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := input
			test.edit(&candidate)
			if _, err := Build(candidate); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Build error = %v; want %q", err, test.want)
			}
		})
	}
	extra := filepath.Join(filepath.FromSlash(input.StagingDir), "root", "unexpected-file")
	if err := os.WriteFile(extra, []byte("undeclared staging data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(input); err == nil || !strings.Contains(err.Error(), "unexpected file") {
		t.Fatalf("undeclared staging file was accepted: %v", err)
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.FromSlash(input.InstallEvidence), []byte("install=pass\nuninstall=pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(input); err == nil || !strings.Contains(err.Error(), "install evidence") {
		t.Fatalf("install evidence lacking package identity was accepted: %v", err)
	}
}

func TestLoadDocumentRejectsPackagePromotionFields(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	document := createPackageFixture(t, "debian", "linux", "amd64", nativepackage.FamilyDebian, "deb")
	data, err := marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("subjects", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("subjects/native-package.json", data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDocument("subjects/native-package.json"); err != nil {
		t.Fatalf("canonical package subject rejected: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"score", "passed", "launch_authorization"} {
		fields[field] = json.RawMessage(`true`)
		candidate, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("subjects/native-package.json", candidate, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadDocument("subjects/native-package.json"); err == nil {
			t.Fatalf("loadDocument accepted promotion field %q", field)
		}
		delete(fields, field)
	}
}

func TestMarshalRejectsForgedNativePackageIdentityAndSubjects(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	base := createPackageFixture(t, "debian", "linux", "amd64", nativepackage.FamilyDebian, "deb")
	for _, test := range []struct {
		name, want string
		edit       func(*document)
	}{
		{"wrong schema", "identity", func(value *document) { value.Schema = "other" }},
		{"noncanonical timestamp", "canonical", func(value *document) { value.GeneratedAt = "2026-08-29T03:00:00+03:00" }},
		{"invalid source commit", "source:", func(value *document) { value.Source.Commit = "bad" }},
		{"invalid job", "execution:", func(value *document) { value.Execution.Job = "Not a job" }},
		{"wrong runner", "execution:", func(value *document) { value.Execution.RunnerOS = "Windows" }},
		{"physical host spoof", "execution:", func(value *document) { value.Execution.HostClass = "physical" }},
		{"invalid package version", "execution:", func(value *document) { value.Execution.Package.Version = "1.2.3" }},
		{"unsupported Linux architecture", "execution:", func(value *document) { value.Execution.Target.GOARCH = "386" }},
		{"wrong package format", "execution:", func(value *document) { value.Execution.Package.Format = "rpm" }},
		{"unsafe staging manifest path", "execution:", func(value *document) { value.Execution.Package.StagingManifestPath = "../manifest.json" }},
		{"missing subjects", "exactly 10", func(value *document) { value.Subjects = value.Subjects[:len(value.Subjects)-1] }},
		{"duplicate subject path", "strictly sorted", func(value *document) { value.Subjects[1].Path = value.Subjects[0].Path }},
		{"unsupported subject role", "unsupported role", func(value *document) { value.Subjects[0].Role = "production-proof" }},
		{"invalid subject digest", "invalid size or SHA-256", func(value *document) { value.Subjects[0].SHA256 = "bad" }},
		{"wrong subject role counts", "subject roles are invalid", func(value *document) { value.Subjects[0].Role = "staging-payload" }},
		{"package filename path", "basename", func(value *document) { value.Execution.Package.Filename = "other/package.deb" }},
		{"unbound package filename", "not bound", func(value *document) { value.Execution.Package.Filename = "other.deb" }},
		{"unbound staging manifest", "evidence paths are not bound", func(value *document) { value.Execution.Package.StagingManifestPath = "other/manifest.json" }},
		{"unbound install evidence", "evidence paths are not bound", func(value *document) { value.Execution.Package.InstallEvidencePath = "other/install.txt" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.Subjects = append([]subject(nil), base.Subjects...)
			test.edit(&candidate)
			if _, err := Marshal(candidate); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Marshal error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestLoadDocumentRejectsDuplicateKeysAndNoncanonicalJSON(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	document := createPackageFixture(t, "debian", "linux", "amd64", nativepackage.FamilyDebian, "deb")
	data, err := Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("subjects", 0o755); err != nil {
		t.Fatal(err)
	}
	path := "subjects/native-package.json"
	duplicate := bytes.Replace(data, []byte(`"kind": "native-package",`), []byte("\"kind\": \"native-package\",\n  \"kind\": \"native-package\","), 1)
	if bytes.Equal(data, duplicate) {
		t.Fatal("fixture did not contain the kind field")
	}
	for _, test := range []struct {
		name, want string
		data       []byte
	}{
		{"duplicate field", "duplicate JSON key", duplicate},
		{"noncanonical encoding", "not canonical", bytes.TrimSpace(data)},
		{"multiple JSON values", "multiple JSON values", append(append([]byte(nil), data...), data...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, test.data, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := loadDocument(path); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("loadDocument error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestWriteNewNeverReplacesAnExistingSubjectOrFollowsSymlink(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.MkdirAll("subjects", 0o755); err != nil {
		t.Fatal(err)
	}
	path := "subjects/native-package.json"
	first := []byte("first attestation\n")
	if err := WriteNew(path, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(path, []byte("replacement\n")); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing subject was replaceable: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("existing subject changed: %q, %v", got, err)
	}
	if err := WriteNew("subjects/missing/subject.json", first); err == nil {
		t.Fatal("write to missing parent directory succeeded")
	}
	if err := WriteNew("", first); err == nil {
		t.Fatal("empty output path succeeded")
	}
	t.Run("symlink", func(t *testing.T) {
		link := "subjects/link.json"
		if err := os.Symlink("native-package.json", link); err != nil {
			t.Skipf("symlink creation is unavailable: %v", err)
		}
		if err := WriteNew(link, []byte("replacement\n")); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("symlink output was accepted: %v", err)
		}
		if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, first) {
			t.Fatalf("symlink target changed: %q, %v", got, err)
		}
	})
}

func TestVerifyGitHubOutputRequiresSignedDigestAndCertificateIdentity(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	document := createPackageFixture(t, "debian", "linux", "amd64", nativepackage.FamilyDebian, "deb")
	digest := strings.Repeat("a", 64)
	valid := validPackageGHVerification(document.Source, digest)
	encode := func(value ghVerification) []byte {
		t.Helper()
		data, err := json.Marshal([]ghVerification{value})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if err := verifyGitHubOutput(encode(valid), digest, document.Source); err != nil {
		t.Fatalf("valid GitHub verification was rejected: %v", err)
	}
	for _, test := range []struct {
		name, want string
		edit       func(*ghVerification)
	}{
		{"unsigned digest", "signed subject", func(value *ghVerification) {
			value.VerificationResult.Statement.Subjects[0].Digest["sha256"] = strings.Repeat("b", 64)
		}},
		{"wrong predicate", "predicate type", func(value *ghVerification) {
			value.VerificationResult.Statement.PredicateType = "https://example.com/other"
		}},
		{"missing timestamp", "timestamp", func(value *ghVerification) {
			value.VerificationResult.VerifiedTimestamps = nil
		}},
		{"wrong repository", "githubWorkflowRepository", func(value *ghVerification) {
			value.VerificationResult.Signature.Certificate["githubWorkflowRepository"] = json.RawMessage(`"other/repository"`)
		}},
		{"wrong workflow digest", "buildSignerDigest", func(value *ghVerification) {
			value.VerificationResult.Signature.Certificate["buildSignerDigest"] = json.RawMessage(`"0000000000000000000000000000000000000000"`)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := validPackageGHVerification(document.Source, digest)
			test.edit(&candidate)
			if err := verifyGitHubOutput(encode(candidate), digest, document.Source); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verification error = %v; want %q", err, test.want)
			}
		})
	}
	for _, test := range []struct {
		name, want string
		data       []byte
	}{
		{"empty response", "no attestations", []byte(`[]`)},
		{"malformed response", "decode GitHub", []byte(`{`)},
		{"multiple responses", "multiple JSON values", append(encode(valid), encode(valid)...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := verifyGitHubOutput(test.data, digest, document.Source); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verification error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestValidateSetShapeRequiresCompleteNativePackageSet(t *testing.T) {
	if err := validateSetShape(nil); err == nil || !strings.Contains(err.Error(), "exactly 11") {
		t.Fatalf("incomplete package set error = %v; want exact eleven-subject requirement", err)
	}
}

func TestVerifyRejectsCanceledContextAndLeavesZeroResult(t *testing.T) {
	if (VerifiedSet{}).Valid() || (VerifiedSet{}).Version() != "" || (VerifiedSet{}).Packages() != nil {
		t.Fatal("zero-value verified set was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	set, err := Verify(ctx, VerifyRequest{})
	if err == nil || !strings.Contains(err.Error(), "context canceled") || set.Valid() {
		t.Fatalf("canceled verification returned set=%+v, err=%v", set, err)
	}
	set, err = Verify(nil, VerifyRequest{})
	if err == nil || set.Valid() {
		t.Fatalf("nil-context verification returned set=%+v, err=%v", set, err)
	}
}

func TestRepositoryIdentityRejectsDotPathComponents(t *testing.T) {
	for _, repository := range []string{"../leaguebridge", "Yunushan/..", "./leaguebridge", "Yunushan/."} {
		t.Run(repository, func(t *testing.T) {
			if err := validateSource(source{Repository: repository}); err == nil || !strings.Contains(err.Error(), "repository") {
				t.Fatalf("source repository %q was accepted: %v", repository, err)
			}
			set, err := Verify(context.Background(), VerifyRequest{
				GHPath: "stub", SubjectPaths: []string{"missing.json"}, ExpectedRepo: repository,
			})
			if err == nil || !strings.Contains(err.Error(), "expected repository") || set.Valid() {
				t.Fatalf("expected repository %q was accepted: set=%+v, err=%v", repository, set, err)
			}
		})
	}
}

func TestVerifyGitHubArtifactStopsWhenParentContextIsCanceled(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.WriteFile("package.deb", []byte("package bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	artifact, err := hashPath("package.deb", "package")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	originalRunner := runGitHubAttestation
	t.Cleanup(func() { runGitHubAttestation = originalRunner })
	runGitHubAttestation = func(received context.Context, _, _ string, _ source) ([]byte, error) {
		if received.Err() != nil {
			t.Fatalf("attestation runner received canceled context: %v", received.Err())
		}
		cancel()
		return []byte(`[]`), nil
	}
	err = verifyGitHubArtifact(ctx, verifiedArtifact{Path: artifact.Path, Digest: artifact.SHA256, Size: artifact.SizeBytes}, source{}, "stub")
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("verification did not stop on cancellation: %v", err)
	}
}

func TestHashPathContextStopsDuringLargeFileRead(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.WriteFile("package.deb", bytes.Repeat([]byte("p"), 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := &cancelDuringHashContext{Context: context.Background(), cancelAt: 3}
	item, err := hashPathContext(ctx, "package.deb", "package")
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "hash subject") || item.SHA256 != "" {
		t.Fatalf("hash did not stop during its file read: item=%+v, err=%v", item, err)
	}
	if ctx.checks < ctx.cancelAt {
		t.Fatalf("hash returned before cancellation trigger: %d checks", ctx.checks)
	}
}

func TestVerifyStagingDocumentPropagatesCancellation(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	document := createPackageFixture(t, "debian", "linux", "amd64", nativepackage.FamilyDebian, "deb")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyStagingDocument(ctx, document); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled package staging verification returned %v", err)
	}
}

type cancelDuringHashContext struct {
	context.Context
	checks   int
	cancelAt int
}

func (value *cancelDuringHashContext) Err() error {
	value.checks++
	if value.checks >= value.cancelAt {
		return context.Canceled
	}
	return nil
}

func TestExpectedExecutionUsesDragonFlyPackageJob(t *testing.T) {
	job, runner, architecture, hostClass := expectedExecution(target{GOOS: "dragonfly", GOARCH: "amd64"}, string(nativepackage.FamilyDPorts))
	if job != "dragonfly-native-package" || runner != "Linux" || architecture != "X64" || hostClass != "virtualized" {
		t.Fatalf("DragonFly package execution = %q/%q/%q/%q", job, runner, architecture, hostClass)
	}
}

func TestValidateInstallEvidenceRequiresBoundedPassMarkers(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	path := "install.txt"
	if err := os.WriteFile(filepath.FromSlash(path), []byte("package=debian\nversion=v1.2.3\nfilename=leaguebridge_1.2.3_amd64.deb\ntarget=linux/amd64\ninstall=pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateInstallEvidence(path, "debian", "v1.2.3", "leaguebridge_1.2.3_amd64.deb", target{GOOS: "linux", GOARCH: "amd64"}); err == nil || !strings.Contains(err.Error(), "uninstall=pass") {
		t.Fatalf("incomplete install evidence error = %v; want missing uninstall marker", err)
	}
	if err := os.WriteFile(filepath.FromSlash(path), []byte("package=debian\nversion=v1.2.3\nfilename=leaguebridge_1.2.3_amd64.deb\ntarget=linux/amd64\ninstall=pass\nuninstall=pass\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateInstallEvidence(path, "debian", "v1.2.3", "leaguebridge_1.2.3_amd64.deb", target{GOOS: "linux", GOARCH: "amd64"}); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("NUL-containing install evidence was accepted: %v", err)
	}
	validEvidence := "package=debian\nversion=v1.2.3\nfilename=leaguebridge_1.2.3_amd64.deb\ntarget=linux/amd64\ninstall=pass\nuninstall=pass\n"
	if err := os.WriteFile(filepath.FromSlash(path), []byte(validEvidence+"install=fail\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateInstallEvidence(path, "debian", "v1.2.3", "leaguebridge_1.2.3_amd64.deb", target{GOOS: "linux", GOARCH: "amd64"}); err == nil || !strings.Contains(err.Error(), "invalid install marker") {
		t.Fatalf("contradictory install marker was accepted: %v", err)
	}
	if err := os.WriteFile(filepath.FromSlash(path), []byte(validEvidence+"install=pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateInstallEvidence(path, "debian", "v1.2.3", "leaguebridge_1.2.3_amd64.deb", target{GOOS: "linux", GOARCH: "amd64"}); err == nil || !strings.Contains(err.Error(), "duplicate install markers") {
		t.Fatalf("duplicate install marker was accepted: %v", err)
	}
}

func TestVerifySetAuthenticatesAndRehashesCompleteNativePackageSet(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	targets := []struct {
		name, goos, goarch string
		family             nativepackage.Family
		format             string
	}{
		{"debian", "linux", "amd64", nativepackage.FamilyDebian, "deb"},
		{"debian-arm64", "linux", "arm64", nativepackage.FamilyDebian, "deb"},
		{"rpm", "linux", "amd64", nativepackage.FamilyRPM, "rpm"},
		{"rpm-arm64", "linux", "arm64", nativepackage.FamilyRPM, "rpm"},
		{"freebsd", "freebsd", "amd64", nativepackage.FamilyFreeBSD, "pkg"},
		{"freebsd-arm64", "freebsd", "arm64", nativepackage.FamilyFreeBSD, "pkg"},
		{"openbsd", "openbsd", "amd64", nativepackage.FamilyOpenBSD, "pkg"},
		{"openbsd-arm64", "openbsd", "arm64", nativepackage.FamilyOpenBSD, "pkg"},
		{"pkgsrc", "netbsd", "amd64", nativepackage.FamilyPkgsrc, "pkg"},
		{"pkgsrc-arm64", "netbsd", "arm64", nativepackage.FamilyPkgsrc, "pkg"},
		{"dports", "dragonfly", "amd64", nativepackage.FamilyDPorts, "pkg"},
	}
	if err := os.MkdirAll("subjects", 0o755); err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		target := target
		document := createPackageFixture(t, target.name, target.goos, target.goarch, target.family, target.format)
		data, err := marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("subjects", target.name+".json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	originalRunner := runGitHubAttestation
	t.Cleanup(func() { runGitHubAttestation = originalRunner })
	runGitHubAttestation = func(_ context.Context, _ string, artifactPath string, sourceValue source) ([]byte, error) {
		artifact, err := hashPath(artifactPath, "verified-artifact")
		if err != nil {
			return nil, err
		}
		return json.Marshal([]ghVerification{validPackageGHVerification(sourceValue, artifact.SHA256)})
	}
	paths := make([]string, 0, len(targets))
	for _, target := range targets {
		paths = append(paths, filepath.ToSlash(filepath.Join("subjects", target.name+".json")))
	}
	verified, err := Verify(context.Background(), VerifyRequest{
		SubjectPaths: paths, ExpectedRepo: "Yunushan/leaguebridge", ExpectedWorkflow: defaultWorkflow,
		ExpectedCommit: testCommit, ExpectedTree: testTree, ExpectedRef: "refs/heads/main",
		WorkflowSHA: strings.Repeat("c", 40), RunID: "1234", RunAttempt: "1", GHPath: "stub",
	})
	if err != nil {
		t.Fatalf("complete package set rejected: %v", err)
	}
	if !verified.Valid() || verified.Version() != "v1.2.3" || len(verified.Packages()) != len(targets) {
		t.Fatalf("verified set = %+v", verified)
	}
	for _, item := range verified.Packages() {
		if item.SubjectSHA256 == "" || item.SHA256 == "" || item.StagingManifestSHA256 == "" || item.InstallEvidenceSHA256 == "" {
			t.Fatalf("verified package is missing artifact digests: %+v", item)
		}
	}
	packages := verified.Packages()
	packages[0].SHA256 = "tampered"
	if verified.Packages()[0].SHA256 == "tampered" {
		t.Fatal("verified package inventory was mutable through its accessor")
	}
}

func createPackageFixture(t *testing.T, name, goos, goarch string, family nativepackage.Family, format string) document {
	t.Helper()
	stagingDir := filepath.ToSlash(filepath.Join("staging", name))
	packageDir := filepath.ToSlash(filepath.Join("packages", name))
	packageFilename := "leaguebridge-1.2.3." + format
	if family == nativepackage.FamilyDebian {
		packageFilename = "leaguebridge_1.2.3~ci_" + goarch + ".deb"
	} else if family == nativepackage.FamilyRPM {
		rpmArchitecture := "x86_64"
		if goarch == "arm64" {
			rpmArchitecture = "aarch64"
		}
		packageFilename = "leaguebridge-1.2.3-1.ci." + rpmArchitecture + ".rpm"
	} else if format == "pkg" {
		packageFilename = "leaguebridge-1.2.3.pkg"
	}
	packagePath := filepath.ToSlash(filepath.Join(packageDir, packageFilename))
	installEvidence := filepath.ToSlash(filepath.Join("package-evidence", name, "install.txt"))
	outputPath := filepath.ToSlash(filepath.Join("subjects", name+"-generated.json"))
	if err := os.MkdirAll(filepath.FromSlash(stagingDir+"/root"), 0o755); err != nil {
		t.Fatal(err)
	}
	names, err := packageinfo.ExpectedPayloadNames(goos, goarch)
	if err != nil {
		t.Fatal(err)
	}
	bodies := make(map[string][]byte, len(names))
	for _, sourcePath := range names {
		bodies[sourcePath] = []byte("package fixture: " + name + ":" + sourcePath + "\n")
	}
	sourceManifest, err := packageinfo.Build("v1.2.3", goos, goarch, 1787702400, testCommit, testTree, "go1.27.1", bodies)
	if err != nil {
		t.Fatal(err)
	}
	sourceData, err := packageinfo.Marshal(sourceManifest)
	if err != nil {
		t.Fatal(err)
	}
	stagingManifest, err := nativepackage.Build(sourceManifest, sourceData, strings.Repeat("a", 64), family)
	if err != nil {
		t.Fatal(err)
	}
	stagingData, err := nativepackage.Marshal(stagingManifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.FromSlash(filepath.Join(stagingDir, nativepackage.StagingManifestName)), stagingData, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, entry := range stagingManifest.Payload {
		body := bodies[entry.SourcePath]
		if entry.SourcePath == packageinfo.ManifestName {
			body = sourceData
		}
		relative := strings.TrimPrefix(entry.InstallPath, "/")
		destination := filepath.Join(filepath.FromSlash(stagingDir), "root", filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, body, 0o644); err != nil {
			t.Fatal(err)
		}
		if entry.Mode == "0755" {
			if err := os.Chmod(destination, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.MkdirAll(filepath.FromSlash(packageDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.FromSlash(packagePath), []byte("native package bytes: "+name+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.FromSlash(installEvidence)), 0o755); err != nil {
		t.Fatal(err)
	}
	evidence := "package=" + string(family) + "\n" +
		"version=v1.2.3\n" +
		"filename=" + packageFilename + "\n" +
		"target=" + goos + "/" + goarch + "\n" +
		"install=pass\n" +
		"uninstall=pass\n"
	if err := os.WriteFile(filepath.FromSlash(installEvidence), []byte(evidence), 0o644); err != nil {
		t.Fatal(err)
	}
	job, runner, architecture, hostClass := expectedExecution(target{GOOS: goos, GOARCH: goarch}, string(family))
	value, err := build(BuildRequest{
		GeneratedAt: "2026-08-29T00:00:00Z", Repository: "Yunushan/leaguebridge", Commit: testCommit,
		Tree: testTree, Ref: "refs/heads/main", Workflow: "CI",
		WorkflowRef: "Yunushan/leaguebridge/.github/workflows/ci.yml@refs/heads/main",
		WorkflowSHA: strings.Repeat("c", 40), RunID: "1234", RunAttempt: "1", Job: job,
		RunnerOS: runner, RunnerArchitecture: architecture, HostClass: hostClass, GoVersion: "go1.27.1",
		Command:    "native package build; package-manager install; native install smoke",
		TargetGOOS: goos, TargetGOARCH: goarch, Family: string(family), Format: format,
		PackagePath: packagePath, StagingDir: stagingDir, InstallEvidence: installEvidence, OutputPath: outputPath,
	})
	if err != nil {
		t.Fatalf("build package fixture %s: %v", name, err)
	}
	return value
}

func validPackageGHVerification(value source, digest string) ghVerification {
	repositoryURI := "https://github.com/" + value.Repository
	workflowURI := "https://github.com/" + value.WorkflowRef
	runURI := repositoryURI + "/actions/runs/" + value.RunID + "/attempts/" + value.RunAttempt
	certificate := make(map[string]json.RawMessage)
	for name, text := range map[string]string{
		"issuer": githubOIDCIssuer, "subjectAlternativeName": workflowURI,
		"githubWorkflowRepository": value.Repository, "githubWorkflowRef": value.Ref,
		"githubWorkflowSHA": value.WorkflowSHA, "buildSignerURI": workflowURI,
		"buildSignerDigest": value.WorkflowSHA, "buildConfigURI": workflowURI,
		"buildConfigDigest": value.WorkflowSHA, "runnerEnvironment": "github-hosted",
		"sourceRepositoryURI": repositoryURI, "sourceRepositoryDigest": value.Commit,
		"sourceRepositoryRef": value.Ref, "runInvocationURI": runURI,
	} {
		encoded, _ := json.Marshal(text)
		certificate[name] = encoded
	}
	return ghVerification{VerificationResult: ghVerificationResult{
		Statement: ghStatement{PredicateType: slsaPredicateType, Subjects: []ghSubject{{Name: "artifact", Digest: map[string]string{"sha256": digest}}}},
		Signature: ghSignature{Certificate: certificate}, VerifiedTimestamps: []json.RawMessage{json.RawMessage(`{}`)},
	}}
}
