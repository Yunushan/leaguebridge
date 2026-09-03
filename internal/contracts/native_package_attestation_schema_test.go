package contracts

import (
	"encoding/json"
	"strings"
	"testing"
)

const nativePackageAttestationSchemaID = "https://github.com/Yunushan/leaguebridge/schemas/native-package-attestation.schema.json"

func TestNativePackageAttestationSchemaIsScoreFreeAndTargetBound(t *testing.T) {
	schema := compileOffline(t, "schemas/native-package-attestation.schema.json", nativePackageAttestationSchemaID)
	valid := map[string]any{
		"$schema": nativePackageAttestationSchemaID, "schema_version": json.Number("1"),
		"attestation_type": "leaguebridge.native-package-attestation.v1", "kind": "native-package",
		"generated_at": "2026-08-29T00:00:00Z",
		"source": map[string]any{
			"repository": "Yunushan/leaguebridge", "commit": strings.Repeat("a", 40),
			"tree": strings.Repeat("b", 40), "ref": "refs/heads/main", "workflow": "CI",
			"workflow_ref": "Yunushan/leaguebridge/.github/workflows/ci.yml@refs/heads/main",
			"workflow_sha": strings.Repeat("c", 40), "run_id": "1234", "run_attempt": "1",
		},
		"execution": map[string]any{
			"job": "native-package-linux", "runner_os": "Linux", "runner_architecture": "X64",
			"host_class": "hosted", "go_version": "go1.27.0", "command": "package build and install smoke",
			"target": map[string]any{"goos": "linux", "goarch": "amd64"},
			"package": map[string]any{
				"family": "debian", "format": "deb", "version": "v1.2.3",
				"filename":              "leaguebridge_1.2.3~ci_amd64.deb",
				"staging_manifest_path": "staging/debian/NATIVE-PACKAGE-MANIFEST.json",
				"install_evidence_path": "package-evidence/debian/install.txt",
			},
		},
		"subjects": []any{
			map[string]any{"path": "package-evidence/debian/install.txt", "role": "package-install-evidence", "size_bytes": json.Number("32"), "sha256": strings.Repeat("a", 64)},
			map[string]any{"path": "packages/debian/leaguebridge_1.2.3~ci_amd64.deb", "role": "package", "size_bytes": json.Number("32"), "sha256": strings.Repeat("b", 64)},
			map[string]any{"path": "staging/debian/NATIVE-PACKAGE-MANIFEST.json", "role": "staging-manifest", "size_bytes": json.Number("32"), "sha256": strings.Repeat("c", 64)},
			map[string]any{"path": "staging/debian/root/usr/bin/leaguebridge", "role": "staging-payload", "size_bytes": json.Number("32"), "sha256": strings.Repeat("d", 64)},
			map[string]any{"path": "staging/debian/root/usr/libexec/leaguebridge/linux-bsd-client-smoke.sh", "role": "staging-payload", "size_bytes": json.Number("32"), "sha256": strings.Repeat("2", 64)},
			map[string]any{"path": "staging/debian/root/usr/libexec/leaguebridge/linux-bsd-remote-session.sh", "role": "staging-payload", "size_bytes": json.Number("32"), "sha256": strings.Repeat("2", 64)},
			map[string]any{"path": "staging/debian/root/usr/share/doc/leaguebridge/LICENSE", "role": "staging-payload", "size_bytes": json.Number("32"), "sha256": strings.Repeat("e", 64)},
			map[string]any{"path": "staging/debian/root/usr/share/doc/leaguebridge/PACKAGE-MANIFEST.json", "role": "staging-payload", "size_bytes": json.Number("32"), "sha256": strings.Repeat("f", 64)},
			map[string]any{"path": "staging/debian/root/usr/share/doc/leaguebridge/README.md", "role": "staging-payload", "size_bytes": json.Number("32"), "sha256": strings.Repeat("0", 64)},
			map[string]any{"path": "staging/debian/root/usr/share/doc/leaguebridge/SBOM.spdx.json", "role": "staging-payload", "size_bytes": json.Number("32"), "sha256": strings.Repeat("1", 64)},
		},
	}
	if err := schema.Validate(valid); err != nil {
		t.Fatalf("valid native package subject rejected: %v", err)
	}
	data, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	freebsdArm64 := decodeJSONBytes(t, data).(map[string]any)
	freebsdArm64Execution := freebsdArm64["execution"].(map[string]any)
	freebsdArm64Execution["job"] = "native-package-bsd"
	freebsdArm64Execution["host_class"] = "virtualized"
	freebsdArm64Target := freebsdArm64Execution["target"].(map[string]any)
	freebsdArm64Target["goos"] = "freebsd"
	freebsdArm64Target["goarch"] = "arm64"
	freebsdArm64Package := freebsdArm64Execution["package"].(map[string]any)
	freebsdArm64Package["family"] = "freebsd-pkg"
	freebsdArm64Package["format"] = "pkg"
	freebsdArm64Package["filename"] = "leaguebridge-1.2.3-freebsd-arm64.pkg"
	freebsdArm64Package["staging_manifest_path"] = "staging/freebsd-pkg/arm64/NATIVE-PACKAGE-MANIFEST.json"
	freebsdArm64Package["install_evidence_path"] = "package-evidence/freebsd-pkg/arm64/install.txt"
	freebsdArm64Subjects := freebsdArm64["subjects"].([]any)
	freebsdArm64Subjects[0].(map[string]any)["path"] = "package-evidence/freebsd-pkg/arm64/install.txt"
	freebsdArm64Subjects[1].(map[string]any)["path"] = "packages/freebsd-pkg/arm64/leaguebridge-1.2.3-freebsd-arm64.pkg"
	freebsdArm64Subjects[2].(map[string]any)["path"] = "staging/freebsd-pkg/arm64/NATIVE-PACKAGE-MANIFEST.json"
	for index := 3; index < len(freebsdArm64Subjects); index++ {
		freebsdArm64Subjects[index].(map[string]any)["path"] = "staging/freebsd-pkg/arm64/payload-" + string(rune('a'+index))
	}
	if err := schema.Validate(freebsdArm64); err != nil {
		t.Fatalf("valid FreeBSD arm64 native package subject rejected: %v", err)
	}
	dragonfly := decodeJSONBytes(t, data).(map[string]any)
	dragonflyExecution := dragonfly["execution"].(map[string]any)
	dragonflyExecution["job"] = "dragonfly-native-package"
	dragonflyExecution["host_class"] = "virtualized"
	dragonflyTarget := dragonflyExecution["target"].(map[string]any)
	dragonflyTarget["goos"] = "dragonfly"
	dragonflyPackage := dragonflyExecution["package"].(map[string]any)
	dragonflyPackage["family"] = "dports"
	dragonflyPackage["format"] = "pkg"
	dragonflyPackage["filename"] = "leaguebridge-1.2.3.pkg"
	dragonflyPackage["staging_manifest_path"] = "staging/dports/NATIVE-PACKAGE-MANIFEST.json"
	dragonflyPackage["install_evidence_path"] = "package-evidence/dports/install.txt"
	dragonflySubjects := dragonfly["subjects"].([]any)
	dragonflySubjects[0].(map[string]any)["path"] = "package-evidence/dports/install.txt"
	dragonflySubjects[1].(map[string]any)["path"] = "packages/dports/leaguebridge-1.2.3.pkg"
	dragonflySubjects[2].(map[string]any)["path"] = "staging/dports/NATIVE-PACKAGE-MANIFEST.json"
	dragonflySubjects[3].(map[string]any)["path"] = "staging/dports/root/usr/local/bin/leaguebridge"
	dragonflySubjects[4].(map[string]any)["path"] = "staging/dports/root/usr/local/libexec/leaguebridge/linux-bsd-client-smoke.sh"
	dragonflySubjects[5].(map[string]any)["path"] = "staging/dports/root/usr/local/libexec/leaguebridge/linux-bsd-remote-session.sh"
	dragonflySubjects[6].(map[string]any)["path"] = "staging/dports/root/usr/local/share/doc/leaguebridge/LICENSE"
	dragonflySubjects[7].(map[string]any)["path"] = "staging/dports/root/usr/local/share/doc/leaguebridge/PACKAGE-MANIFEST.json"
	dragonflySubjects[8].(map[string]any)["path"] = "staging/dports/root/usr/local/share/doc/leaguebridge/README.md"
	dragonflySubjects[9].(map[string]any)["path"] = "staging/dports/root/usr/local/share/doc/leaguebridge/SBOM.spdx.json"
	if err := schema.Validate(dragonfly); err != nil {
		t.Fatalf("valid DragonFly native package subject rejected: %v", err)
	}
	dragonflyExecution["job"] = "native-package-bsd"
	if err := schema.Validate(dragonfly); err == nil {
		t.Fatal("schema accepted DragonFly package with the shared BSD job identity")
	}
	for name, mutate := range map[string]func(map[string]any){
		"score field":         func(value map[string]any) { value["score"] = json.Number("100") },
		"physical host claim": func(value map[string]any) { value["execution"].(map[string]any)["host_class"] = "physical" },
		"cross target family": func(value map[string]any) {
			value["execution"].(map[string]any)["target"].(map[string]any)["goos"] = "freebsd"
		},
		"missing staging payload": func(value map[string]any) {
			value["subjects"].([]any)[3].(map[string]any)["role"] = "package-install-evidence"
		},
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(valid)
			if err != nil {
				t.Fatal(err)
			}
			clone := decodeJSONBytes(t, data).(map[string]any)
			mutate(clone)
			if err := schema.Validate(clone); err == nil {
				t.Fatal("schema accepted invalid native package subject")
			}
		})
	}
}
