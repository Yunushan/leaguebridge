package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkflowFormatChecksExcludeVendoredGoFiles(t *testing.T) {
	for _, relative := range []string{
		filepath.Join("..", "..", ".github", "workflows", "ci.yml"),
		filepath.Join("..", "..", ".github", "workflows", "release.yml"),
	} {
		data, err := os.ReadFile(relative)
		if err != nil {
			t.Fatal(err)
		}
		workflow := string(data)
		if strings.Contains(workflow, "gofmt -l .") {
			t.Errorf("%s formats the entire tree, including vendored Go files", relative)
		}
		for _, required := range []string{
			"mapfile -t go_files < <(git ls-files -- '*.go' ':!vendor/**')",
			`test -z "$(gofmt -l "${go_files[@]}")"`,
		} {
			if !strings.Contains(workflow, required) {
				t.Errorf("%s is missing scoped format-check fragment %q", relative, required)
			}
		}
	}
}

func TestBSDPackageSmokeAllowsTargetNativeVersionChecker(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "native-package-bsd-smoke.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"usage: native-package-bsd-smoke.sh VERSION GOOS FAMILY [VERSION_CHECKER]",
		`if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then`,
		"version_checker=${4:-}",
		`if [ -n "$version_checker" ]; then`,
		`if [ -L "$version_checker" ] || [ ! -f "$version_checker" ]; then`,
		`if ! "$version_checker" "$version" >/dev/null 2>&1; then`,
		`elif command -v go >/dev/null 2>&1; then`,
		"no VERSION_CHECKER was supplied",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("BSD package smoke script is missing target-validator fragment %q", required)
		}
	}
	for _, required := range []string{
		`command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1`,
		`command -v doas >/dev/null 2>&1 && doas -n true >/dev/null 2>&1`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("BSD package smoke script is missing non-interactive privilege preflight %q", required)
		}
	}
}

func TestWorkflowsUseTheResolvedSetupGoPinEverywhere(t *testing.T) {
	const expected = "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16"
	for _, relative := range []string{
		filepath.Join("..", "..", ".github", "workflows", "ci.yml"),
		filepath.Join("..", "..", ".github", "workflows", "release.yml"),
	} {
		data, err := os.ReadFile(relative)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, "actions/setup-go@") {
				continue
			}
			count++
			if !strings.Contains(line, expected) {
				t.Errorf("%s has an unexpected setup-go pin: %s", relative, line)
			}
		}
		if count == 0 {
			t.Errorf("%s has no setup-go action reference", relative)
		}
	}
}

func TestNativeReleaseContractsExcludeWindowsAndMacOS(t *testing.T) {
	for _, relative := range []string{
		filepath.Join("..", "..", "scripts", "release.sh"),
		filepath.Join("..", "..", "scripts", "verify-install.sh"),
		filepath.Join("..", "..", ".github", "workflows", "ci.yml"),
		filepath.Join("..", "..", ".github", "workflows", "release.yml"),
	} {
		data, err := os.ReadFile(relative)
		if err != nil {
			t.Fatal(err)
		}
		contract := strings.ToLower(string(data))
		for _, forbidden := range []string{
			"windows/amd64",
			"darwin/amd64",
			"macos/amd64",
			"goos: windows",
			"goos: darwin",
			"goos: macos",
			"goos=windows",
			"goos=darwin",
			"goos=macos",
			"windows amd64",
			"darwin amd64",
			"macos amd64",
		} {
			if strings.Contains(contract, forbidden) {
				t.Errorf("%s contains an out-of-scope native target %q", relative, forbidden)
			}
		}
	}
}

func TestCIWorkflowEmitsBoundAttestationSubjects(t *testing.T) {
	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for _, required := range []string{
		"id-token: write",
		"attestations: write",
		"artifact-metadata: write",
		"github.event_name != 'pull_request'",
		"ci-attestation must be a real directory",
		"ci-build must be a real directory",
		"actual_commit=\"$(git rev-parse HEAD)\"",
		"does not match GITHUB_SHA",
		"export CI_ATTESTATION_TREE=\"$actual_tree\"",
		"./tools/ciattestation",
		"./tools/nativeattestation",
		"-kind race-vet",
		"-kind cross-build",
		"-kind linux-runtime",
		"-kind bsd-runtime",
		"host-class virtualized",
		"-target-goos \"${{ matrix.goos }}\"",
		"-target-goarch \"${{ matrix.goarch }}\"",
		"-subject \"ci-build/leaguebridge-${{ matrix.goos }}-${{ matrix.goarch }}\"",
		"actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
		"subject-path: ci-attestation-input/ci-attestation/race-vet.json",
		"ci-attestation/cross-build.json",
		"native-package-linux:",
		"native-package-bsd:",
		"./tools/nativepackageattestation",
		"native-package-output/",
		"native-package-staging/",
		"native-package-evidence/",
		"scripts/native-package-linux-smoke.sh",
		"scripts/native-package-bsd-smoke.sh",
		"Build guest version validator for ${{ matrix.goos }}/amd64",
		"-o \"bsd-ci/versioncheck-${{ matrix.goos }}-amd64\"",
		"bsd-ci/versioncheck-${{ matrix.goos }}-amd64\"",
		"apt-get install --yes --no-install-recommends rpm",
		"native-package-bsd-${{ matrix.goos }}",
		"native-package-evidence/debian/install.txt",
		"native-package-evidence/rpm/install.txt",
		"native-package-evidence/${{ matrix.family }}/install.txt",
		"verify-native-package-attestations:",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("ci.yml is missing attestation contract fragment %q", required)
		}
	}
	if count := strings.Count(workflow, "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26"); count != 6 {
		t.Fatalf("ci.yml has %d attestation action references; want Linux/BSD race/vet, cross-build, runtime, and package references", count)
	}
	if count := strings.Count(workflow, "-verify-subject native-package-evidence/"); count != 6 {
		t.Fatalf("ci.yml verifies %d native package subjects; want the complete Linux/BSD package set", count)
	}
}

func TestCIWorkflowVerifiesCompleteAttestationSets(t *testing.T) {
	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for _, required := range []string{
		"verify-ci-attestations:",
		"verify-native-runtime-attestations:",
		"verify-native-package-attestations:",
		"if: github.event_name != 'pull_request'",
		"needs: [attest-race-vet, attest-cross-build]",
		"needs: [native-package-linux, native-package-bsd]",
		"needs: [attest-linux-runtime, attest-bsd-runtime]",
		"attestations: read",
		"pattern: ci-attestation-*",
		"merge-multiple: false",
		"Arrange one-run verification set",
		"-verify",
		"-kind race-vet",
		"-kind cross-build",
		"-expected-repository \"$GITHUB_REPOSITORY\"",
		"-expected-workflow .github/workflows/ci.yml",
		"-expected-commit \"$actual_commit\"",
		"-expected-tree \"$actual_tree\"",
		"-expected-ref \"$GITHUB_REF\"",
		"-expected-workflow-sha \"$EXPECTED_WORKFLOW_SHA\"",
		"-run-id \"$EXPECTED_RUN_ID\"",
		"-run-attempt \"$EXPECTED_RUN_ATTEMPT\"",
		"-expected-host-class hosted",
		"-expected-host-class virtualized",
		"ci-attestation/race-vet-linux.json",
		"ci-attestation/cross-build-linux-amd64.json",
		"ci-attestation/cross-build-freebsd-amd64.json",
		"ci-attestation/cross-build-openbsd-amd64.json",
		"ci-attestation/cross-build-netbsd-amd64.json",
		"ci-attestation/cross-build-dragonfly-amd64.json",
		"native-package-evidence/debian/native-package.json",
		"native-package-evidence/rpm/native-package.json",
		"native-package-evidence/freebsd-pkg/native-package.json",
		"native-package-evidence/openbsd-pkg/native-package.json",
		"native-package-evidence/pkgsrc/native-package.json",
		"native-package-evidence/dports/native-package.json",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("ci.yml is missing complete-attestation verification fragment %q", required)
		}
	}
}

func TestReleaseWorkflowVerifiesEveryAttestedPublicationSubject(t *testing.T) {
	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for _, required := range []string{
		"Verify release attestations before publication",
		"EXPECTED_COMMIT: ${{ needs.build.outputs.tested_commit }}",
		"ref: ${{ needs.build.outputs.tested_commit }}",
		"Set up Go for release attestation verification",
		"dist/checksums.txt",
		"dist/leaguebridge_${{ steps.verify_artifacts.outputs.release_version }}_linux_amd64.tar.gz",
		"dist/leaguebridge_${{ steps.verify_artifacts.outputs.release_version }}_freebsd_amd64.tar.gz",
		"dist/leaguebridge_${{ steps.verify_artifacts.outputs.release_version }}_openbsd_amd64.tar.gz",
		"dist/leaguebridge_${{ steps.verify_artifacts.outputs.release_version }}_netbsd_amd64.tar.gz",
		"dist/leaguebridge_${{ steps.verify_artifacts.outputs.release_version }}_dragonfly_amd64.tar.gz",
		"go run -mod=vendor ./tools/ciattestation",
		"-verify -kind release",
		"-release-dir dist",
		"-release-version \"$GITHUB_REF_NAME\"",
		"-expected-repository \"$GITHUB_REPOSITORY\"",
		"-expected-workflow .github/workflows/release.yml",
		"-expected-commit \"$EXPECTED_COMMIT\"",
		"-expected-ref \"$GITHUB_REF\"",
		"-expected-workflow-sha \"$EXPECTED_WORKFLOW_SHA\"",
		"-run-id \"$EXPECTED_RUN_ID\"",
		"-run-attempt \"$EXPECTED_RUN_ATTEMPT\"",
		"for attempt in 1 2 3 4 5; do",
		"sleep 5",
		"Recheck the protected release tag immediately before publication",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("release.yml is missing publication-attestation fragment %q", required)
		}
	}
	attestIndex := strings.Index(workflow, "- name: Attest release artifacts")
	checkoutIndex := strings.Index(workflow, "- name: Check out the tested verifier source")
	downloadIndex := strings.Index(workflow, "- name: Download artifacts built by the unprivileged job")
	verifyIndex := strings.Index(workflow, "- name: Verify release attestations before publication")
	recheckIndex := strings.Index(workflow, "- name: Recheck the protected release tag immediately before publication")
	if checkoutIndex < 0 || downloadIndex < checkoutIndex || attestIndex < 0 || verifyIndex < attestIndex || recheckIndex < verifyIndex {
		t.Fatal("release attestation verification is not ordered between attestation and the final tag recheck")
	}
}

func TestAttestingWorkflowsGrantArtifactMetadataPermission(t *testing.T) {
	for _, relative := range []string{
		filepath.Join("..", "..", ".github", "workflows", "ci.yml"),
		filepath.Join("..", "..", ".github", "workflows", "release.yml"),
	} {
		data, err := os.ReadFile(relative)
		if err != nil {
			t.Fatal(err)
		}
		workflow := string(data)
		for _, required := range []string{"id-token: write", "attestations: write", "artifact-metadata: write"} {
			if !strings.Contains(workflow, required) {
				t.Errorf("%s is missing required attestation permission %q", relative, required)
			}
		}
	}
}

func TestCIReadOnlyJobsDoNotRequestAttestationWritePermissions(t *testing.T) {
	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	jobBody := func(name, next string) string {
		t.Helper()
		startMarker := "\n  " + name + ":\n"
		start := strings.Index(workflow, startMarker)
		if start < 0 {
			t.Fatalf("ci.yml is missing job %q", name)
		}
		end := strings.Index(workflow[start+len(startMarker):], "\n  "+next+":\n")
		if end < 0 {
			t.Fatalf("ci.yml is missing the job boundary after %q", name)
		}
		return workflow[start : start+len(startMarker)+end]
	}

	readOnlyJobs := map[string]string{
		"test":          "attest-race-vet",
		"cross-build":   "attest-cross-build",
		"bsd-runtime":   "attest-bsd-runtime",
		"linux-runtime": "attest-linux-runtime",
	}
	for name, next := range readOnlyJobs {
		body := jobBody(name, next)
		for _, forbidden := range []string{"id-token: write", "attestations: write", "artifact-metadata: write"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("read-only CI job %q requests %q", name, forbidden)
			}
		}
	}
	attestationJobs := map[string]string{
		"attest-race-vet":      "minimum-go",
		"attest-cross-build":   "verify-ci-attestations",
		"attest-bsd-runtime":   "release-smoke",
		"attest-linux-runtime": "verify-native-runtime-attestations",
	}
	for name, next := range attestationJobs {
		body := jobBody(name, next)
		for _, required := range []string{"id-token: write", "attestations: write", "artifact-metadata: write"} {
			if !strings.Contains(body, required) {
				t.Errorf("attestation job %q is missing %q", name, required)
			}
		}
	}
}
