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

func TestBSDRuntimeSmokeBindsSupportedArchitectureToTheGuest(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "bsd-runtime-smoke.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"usage: bsd-runtime-smoke.sh BINARY GOOS GOARCH UNAME EVIDENCE_DIR",
		`if [ "$#" -ne 5 ]; then`,
		"expected_goarch=$3",
		"freebsd:amd64:FreeBSD | freebsd:arm64:FreeBSD",
		"openbsd:amd64:OpenBSD | openbsd:arm64:OpenBSD",
		"netbsd:amd64:NetBSD | netbsd:arm64:NetBSD",
		"dragonfly:amd64:DragonFly",
		`\"architecture\": \"$expected_goarch\"`,
		`printf 'goarch=%s\n' "$expected_goarch"`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("BSD runtime smoke script is missing architecture contract fragment %q", required)
		}
	}
}

func TestRuntimeSmokeProtectsEvidenceOutputs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		label string
	}{
		{name: "linux-runtime-smoke.sh", label: "linux-runtime-smoke"},
		{name: "bsd-runtime-smoke.sh", label: "bsd-runtime-smoke"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join("..", "..", "scripts", tc.name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			script := string(data)
			for _, required := range []string{
				"if [ -L \"$evidence_dir\" ] || { [ -e \"$evidence_dir\" ] && [ ! -d \"$evidence_dir\" ]; }; then",
				"if [ -L \"$evidence_dir\" ] || [ ! -d \"$evidence_dir\" ]; then",
				"for output in",
				"kernel.txt",
				"version.json",
				"status.json",
				"readiness.json",
				"manifest-verify.json",
				"doctor.json",
				"result.txt; do",
				"if [ -e \"$evidence_dir/$output\" ] || [ -L \"$evidence_dir/$output\" ]; then",
				"refusing to overwrite existing evidence output",
			} {
				if !strings.Contains(script, required) {
					t.Errorf("%s is missing evidence-integrity fragment %q", tc.name, required)
				}
			}
			guardIndex := strings.Index(script, "if [ -L \"$evidence_dir\" ]")
			mkdirIndex := strings.Index(script, "mkdir -p \"$evidence_dir\"")
			writeIndex := strings.Index(script, "> \"$evidence_dir/kernel.txt\"")
			if guardIndex < 0 || mkdirIndex < 0 || writeIndex < 0 || guardIndex > mkdirIndex || mkdirIndex > writeIndex {
				t.Fatalf("%s must validate evidence paths before creating or writing evidence", tc.label)
			}
		})
	}
}

func TestLinuxBSDRemoteSmokeSupportsOptionalWakeBootstrap(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "linux-bsd-remote-smoke.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"usage: linux-bsd-remote-smoke.sh BINARY EVIDENCE_DIR CONFIG [EXPECTED_APPLICATION [WAKE_MAC [WAKE_WAIT [WAKE_BROADCAST [WAKE_PORT [WAKE_RETRIES [WAKE_RETRY_DELAY]]]]]]]",
		`if [ "$#" -lt 3 ] || [ "$#" -gt 10 ]; then`,
		"wake_mac=${5-}",
		"wake_wait=15",
		`if [ "$#" -ge 6 ]; then`,
		"wake_broadcast=255.255.255.255",
		"wake_port=9",
		"wake_retries=3",
		"wake_retry_delay=5",
		`if [ "$#" -ge 8 ]; then`,
		`if [ "$#" -ge 9 ]; then`,
		"wake_retry_delay=${10}",
		"--acknowledge-unverified-handoff --wake-mac \"$wake_mac\" \\",
		"--wake-wait \"$wake_wait\" --wake-broadcast \"$wake_broadcast\" \\",
		"--wake-port \"$wake_port\" --wake-retries \"$wake_retries\" \\",
		"--wake-retry-delay \"$wake_retry_delay\"; then",
		"printf 'wake_bootstrap=used\\n'",
		"printf 'wake_bootstrap=not-requested\\n'",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("Linux/BSD remote smoke script is missing Wake-on-LAN fragment %q", required)
		}
	}
	if strings.Contains(script, "printf 'wake_mac=") || strings.Contains(script, "printf 'wake_mac=%s") {
		t.Fatal("Linux/BSD remote smoke script must not write the Wake-on-LAN MAC to evidence")
	}
}

func TestWorkflowsUseTheResolvedSetupGoPinEverywhere(t *testing.T) {
	const expected = "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e"
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
		"Create score-free Linux runtime attestation subject",
		"Create score-free BSD runtime attestation subject",
		"-kind race-vet",
		"-kind cross-build",
		"-kind linux-runtime",
		"-kind bsd-runtime",
		"host-class virtualized",
		"-target-goos \"${{ matrix.goos }}\"",
		"-target-goarch \"${{ matrix.goarch }}\"",
		"-subject \"ci-build/leaguebridge-${{ matrix.goos }}-${{ matrix.goarch }}\"",
		"-evidence-dir \"bsd-evidence/${{ matrix.goos }}/${{ matrix.goarch }}\"",
		"actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
		"subject-path: ci-attestation-input/race-vet.json",
		"ci-attestation/cross-build.json",
		"native-package-linux:",
		"native-package-bsd:",
		"./tools/nativepackageattestation",
		"native-package-output/",
		"native-package-staging/",
		"native-package-evidence/",
		"scripts/native-package-linux-smoke.sh",
		"scripts/native-package-bsd-smoke.sh",
		"Build guest version validator for ${{ matrix.goos }}/${{ matrix.goarch }}",
		"-o \"bsd-ci/versioncheck-${{ matrix.goos }}-${{ matrix.goarch }}\"",
		"bsd-ci/versioncheck-${{ matrix.goos }}-${{ matrix.goarch }}\"",
		"apt-get install --yes --no-install-recommends rpm",
		"native-package-bsd-${{ matrix.goos }}-${{ matrix.goarch }}",
		"native-package-evidence/debian/install.txt",
		"native-package-evidence/rpm/install.txt",
		"native-package-evidence/${{ matrix.family }}/${{ matrix.goarch }}/install.txt",
		"verify-native-package-attestations:",
		"needs: [bsd-runtime, dragonfly-runtime]",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("ci.yml is missing attestation contract fragment %q", required)
		}
	}
	if count := strings.Count(workflow, "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"); count != 7 {
		t.Fatalf("ci.yml has %d attestation action references; want Linux/BSD race/vet, cross-build, runtime, and package references including DragonFly", count)
	}
	if count := strings.Count(workflow, "-verify-subject native-package-evidence/"); count != 9 {
		t.Fatalf("ci.yml verifies %d native package subjects; want the complete Linux/BSD package set", count)
	}
}

func TestBSDRuntimeMatrixCoversPortableArchitectures(t *testing.T) {
	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for _, required := range []string{
		"label: FreeBSD 15.1 arm64",
		"label: OpenBSD 7.9 arm64",
		"label: NetBSD 11.0 arm64",
		"cpa_architecture: arm64",
		"architecture: ${{ matrix.cpa_architecture }}",
		"GOARCH: ${{ matrix.goarch }}",
		"bsd-runtime-${{ matrix.goos }}-${{ matrix.guest_version }}-${{ matrix.goarch }}",
		"dist/leaguebridge_0.0.0-ci_${{ matrix.goos }}_${{ matrix.goarch }}.tar.gz",
		"bsd-evidence/${{ matrix.goos }}/${{ matrix.goarch }}",
		"dragonfly-runtime:",
		"vmactions/dragonflybsd-vm@7cd7c9b7f2b06e8e03d2337a9476995f3c112acf",
		"custom-shell-name: dragonflybsd",
		"mem: 6144",
		"shell: dragonflybsd {0}",
		"bsd-runtime-dragonfly-6.4.2-amd64",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("ci.yml is missing portable BSD runtime fragment %q", required)
		}
	}
	if strings.Contains(workflow, "label: DragonFly BSD 6.4.2 arm64") {
		t.Fatal("ci.yml added an unsupported DragonFly arm64 runtime guest")
	}
	if count := strings.Count(workflow, "-verify-subject bsd-evidence/"); count != 7 {
		t.Fatalf("ci.yml verifies %d native BSD runtime subjects; want 7", count)
	}
}

func TestCIWorkflowKeepsSmokeArgumentsAndVMHelperGuardsIntact(t *testing.T) {
	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for _, required := range []string{
		"run: |\n          set -euo pipefail\n          bash scripts/native-package-linux-smoke.sh \\\n            v0.0.0-ci \\\n            dist/leaguebridge_0.0.0-ci_linux_amd64.tar.gz",
		"run: |\n          set -eu\n          sh scripts/native-package-bsd-smoke.sh \\\n            v0.0.0-ci \"${{ matrix.goos }}\" \"${{ matrix.family }}\" \\\n            \"bsd-ci/versioncheck-${{ matrix.goos }}-${{ matrix.goarch }}\"",
		"run: |\n          set -eu\n          sh scripts/native-package-bsd-smoke.sh \\\n            v0.0.0-ci dragonfly dports \\\n            bsd-ci/versioncheck-dragonfly-amd64",
		"cp ci-attestation-input/ci-attestation-race-vet-ubuntu-24.04/race-vet.json",
		"id: cpa-ready",
		"command -v cpa.sh >/dev/null 2>&1",
		"evidence_file=\"bsd-evidence/${{ matrix.goos }}/${{ matrix.goarch }}/install-lifecycle.txt\"",
		"cat \"$evidence_file\" >&2",
		"evidence_file=bsd-evidence/dragonfly/amd64/install-lifecycle.txt",
		"evidence_file=linux-evidence/${{ matrix.goarch }}/install-lifecycle.txt",
		"if: success() && steps.start-vm.outcome == 'success' && steps.cpa-ready.outcome == 'success'\n        shell: cpa.sh {0}",
		"if: always() && steps.start-vm.outcome == 'success' && steps.cpa-ready.outcome == 'success'\n        run: cpa.sh --sync-files vm-to-runner",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("ci.yml is missing smoke/VM safety contract fragment %q", required)
		}
	}
	if count := strings.Count(workflow, "id: start-vm"); count != 2 {
		t.Fatalf("ci.yml has %d VM startup step IDs; want runtime and package jobs", count)
	}
	if count := strings.Count(workflow, "id: cpa-ready"); count != 2 {
		t.Fatalf("ci.yml has %d cpa.sh readiness gates; want runtime and package jobs", count)
	}
	if count := strings.Count(workflow, "if: always() && steps.start-vm.outcome == 'success' && steps.cpa-ready.outcome == 'success'"); count != 3 {
		t.Fatalf("ci.yml has %d guarded always-steps; want install and sync coverage", count)
	}
}

func TestCINativePackageFilenamesMatchSmokeScripts(t *testing.T) {
	workflowData, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	linuxData, err := os.ReadFile(filepath.Join("..", "..", "scripts", "native-package-linux-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	bsdData, err := os.ReadFile(filepath.Join("..", "..", "scripts", "native-package-bsd-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}

	linuxScript := string(linuxData)
	for _, required := range []string{
		"package_version=${version#v}",
		"package_version=${package_version%%+*}",
		`deb_version=$(printf '%s' "$package_version" | tr '-' '~')`,
		"rpm_release=1",
		`debian_package="native-package-output/debian/leaguebridge_${deb_version}_amd64.deb"`,
		`rpm_package="native-package-output/rpm/leaguebridge-${rpm_version}-${rpm_release}.x86_64.rpm"`,
	} {
		if !strings.Contains(linuxScript, required) {
			t.Errorf("Linux package smoke script is missing filename contract fragment %q", required)
		}
	}

	bsdScript := string(bsdData)
	for _, required := range []string{
		`package_name="leaguebridge-$package_version"`,
		`package="$package_dir/$package_name-$expected_goos-$expected_goarch.pkg"`,
		`package="$package_dir/$package_name-$expected_goos-$expected_goarch.tgz"`,
	} {
		if !strings.Contains(bsdScript, required) {
			t.Errorf("BSD package smoke script is missing filename contract fragment %q", required)
		}
	}

	workflow := string(workflowData)
	for _, required := range []string{
		"native-package-output/debian/leaguebridge_0.0.0~ci_amd64.deb",
		"native-package-output/rpm/leaguebridge-0.0.0-1.ci.x86_64.rpm",
		"package_file: leaguebridge-0.0.0-ci-freebsd-amd64.pkg",
		"package_file: leaguebridge-0.0.0-ci-freebsd-arm64.pkg",
		"package_file: leaguebridge-0.0.0-ci-openbsd-amd64.tgz",
		"package_file: leaguebridge-0.0.0-ci-openbsd-arm64.tgz",
		"package_file: leaguebridge-0.0.0-ci-netbsd-amd64.tgz",
		"package_file: leaguebridge-0.0.0-ci-netbsd-arm64.tgz",
		"native-package-output/dports/amd64/leaguebridge-0.0.0-ci-dragonfly-amd64.pkg",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("ci.yml is missing native package filename %q", required)
		}
	}
}

func TestRuntimeSmokeBuildsEmbedVerifiedRepositoryEvidence(t *testing.T) {
	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	const markerStep = "- name: Resolve verified repository-evidence marker"
	const markerOutput = "REPOSITORY_EVIDENCE_VERIFICATION: ${{ steps.repository-evidence.outputs.value }}"
	const markerLdflag = "-ldflags \"-X github.com/Yunushan/leaguebridge/internal/version.RepositoryEvidenceVerification=$REPOSITORY_EVIDENCE_VERIFICATION\""
	if count := strings.Count(workflow, markerStep); count != 3 {
		t.Fatalf("ci.yml resolves the repository-evidence marker %d times; want Linux, BSD, and DragonFly runtime jobs", count)
	}
	if count := strings.Count(workflow, markerOutput); count != 3 {
		t.Fatalf("ci.yml injects the repository-evidence output %d times; want Linux, BSD, and DragonFly runtime jobs", count)
	}
	if count := strings.Count(workflow, markerLdflag); count != 3 {
		t.Fatalf("ci.yml injects the repository-evidence ldflag %d times; want Linux, BSD, and DragonFly runtime builds", count)
	}
	for _, required := range []string{
		"go run -mod=vendor ./tools/readinesscheck -root .",
		"scorecard_sha256=\"$(sha256sum readiness/scorecard.json | awk '{print $1}')\"",
		"=~ ^[0-9a-f]{64}$",
		"printf 'value=leaguebridge-repository-evidence-v1:%s\\n' \"$scorecard_sha256\" >> \"$GITHUB_OUTPUT\"",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("ci.yml is missing repository-evidence marker fragment %q", required)
		}
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
		"dragonfly-native-package:",
		"native-package-bsd-dragonfly",
		"if: github.event_name != 'pull_request'",
		"needs: [attest-race-vet, attest-cross-build]",
		"needs: [native-package-linux, native-package-bsd, dragonfly-native-package]",
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
		"ci-attestation/cross-build-linux-arm64.json",
		"ci-attestation/cross-build-freebsd-amd64.json",
		"ci-attestation/cross-build-freebsd-arm64.json",
		"ci-attestation/cross-build-openbsd-amd64.json",
		"ci-attestation/cross-build-openbsd-arm64.json",
		"ci-attestation/cross-build-netbsd-amd64.json",
		"ci-attestation/cross-build-netbsd-arm64.json",
		"ci-attestation/cross-build-dragonfly-amd64.json",
		"native-package-evidence/debian/native-package.json",
		"native-package-evidence/rpm/native-package.json",
		"native-package-evidence/freebsd-pkg/amd64/native-package.json",
		"native-package-evidence/freebsd-pkg/arm64/native-package.json",
		"native-package-evidence/openbsd-pkg/amd64/native-package.json",
		"native-package-evidence/openbsd-pkg/arm64/native-package.json",
		"native-package-evidence/pkgsrc/amd64/native-package.json",
		"native-package-evidence/pkgsrc/arm64/native-package.json",
		"native-package-evidence/dports/amd64/native-package.json",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("ci.yml is missing complete-attestation verification fragment %q", required)
		}
	}
}

func TestLinuxRuntimeWorkflowCoversBothHostedArchitectures(t *testing.T) {
	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for _, required := range []string{
		"name: Hosted Linux runtime (${{ matrix.goarch }})",
		"runner: ubuntu-24.04",
		"runner: ubuntu-24.04-arm",
		"name: linux-runtime-${{ matrix.goarch }}",
		"pattern: linux-runtime-*",
		"linux-evidence/amd64/native-runtime.json",
		"linux-evidence/arm64/native-runtime.json",
		"ci-bin/leaguebridge-linux-${{ matrix.goarch }}",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("ci.yml is missing Linux multi-architecture runtime fragment %q", required)
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
		"dist/leaguebridge_${{ steps.verify_artifacts.outputs.release_version }}_linux_arm64.tar.gz",
		"dist/leaguebridge_${{ steps.verify_artifacts.outputs.release_version }}_freebsd_amd64.tar.gz",
		"dist/leaguebridge_${{ steps.verify_artifacts.outputs.release_version }}_freebsd_arm64.tar.gz",
		"dist/leaguebridge_${{ steps.verify_artifacts.outputs.release_version }}_openbsd_amd64.tar.gz",
		"dist/leaguebridge_${{ steps.verify_artifacts.outputs.release_version }}_openbsd_arm64.tar.gz",
		"dist/leaguebridge_${{ steps.verify_artifacts.outputs.release_version }}_netbsd_amd64.tar.gz",
		"dist/leaguebridge_${{ steps.verify_artifacts.outputs.release_version }}_netbsd_arm64.tar.gz",
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
