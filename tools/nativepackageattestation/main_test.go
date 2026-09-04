package main

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestValidateSetShapeRequiresCompleteNativePackageSet(t *testing.T) {
	if err := validateSetShape(nil); err == nil || !strings.Contains(err.Error(), "exactly 9") {
		t.Fatalf("incomplete package set error = %v; want exact nine-subject requirement", err)
	}
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
		{"rpm", "linux", "amd64", nativepackage.FamilyRPM, "rpm"},
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
	if err := verifySet(verifyRequest{
		SubjectPaths: paths, ExpectedRepo: "Yunushan/leaguebridge", ExpectedWorkflow: defaultWorkflow,
		ExpectedCommit: testCommit, ExpectedTree: testTree, ExpectedRef: "refs/heads/main",
		WorkflowSHA: strings.Repeat("c", 40), RunID: "1234", RunAttempt: "1", GHPath: "stub",
	}); err != nil {
		t.Fatalf("complete package set rejected: %v", err)
	}
}

func createPackageFixture(t *testing.T, name, goos, goarch string, family nativepackage.Family, format string) document {
	t.Helper()
	stagingDir := filepath.ToSlash(filepath.Join("staging", name))
	packageDir := filepath.ToSlash(filepath.Join("packages", name))
	packageFilename := "leaguebridge-1.2.3." + format
	if family == nativepackage.FamilyDebian {
		packageFilename = "leaguebridge_1.2.3~ci_amd64.deb"
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
	value, err := build(request{
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
