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
				"filename":              "leaguebridge-1.2.3.deb",
				"staging_manifest_path": "staging/debian/NATIVE-PACKAGE-MANIFEST.json",
				"install_evidence_path": "package-evidence/debian/install.txt",
			},
		},
		"subjects": []any{
			map[string]any{"path": "package-evidence/debian/install.txt", "role": "package-install-evidence", "size_bytes": json.Number("32"), "sha256": strings.Repeat("a", 64)},
			map[string]any{"path": "packages/debian/leaguebridge-1.2.3.deb", "role": "package", "size_bytes": json.Number("32"), "sha256": strings.Repeat("b", 64)},
			map[string]any{"path": "staging/debian/NATIVE-PACKAGE-MANIFEST.json", "role": "staging-manifest", "size_bytes": json.Number("32"), "sha256": strings.Repeat("c", 64)},
			map[string]any{"path": "staging/debian/root/usr/bin/leaguebridge", "role": "staging-payload", "size_bytes": json.Number("32"), "sha256": strings.Repeat("d", 64)},
			map[string]any{"path": "staging/debian/root/usr/share/doc/leaguebridge/LICENSE", "role": "staging-payload", "size_bytes": json.Number("32"), "sha256": strings.Repeat("e", 64)},
			map[string]any{"path": "staging/debian/root/usr/share/doc/leaguebridge/PACKAGE-MANIFEST.json", "role": "staging-payload", "size_bytes": json.Number("32"), "sha256": strings.Repeat("f", 64)},
			map[string]any{"path": "staging/debian/root/usr/share/doc/leaguebridge/README.md", "role": "staging-payload", "size_bytes": json.Number("32"), "sha256": strings.Repeat("0", 64)},
			map[string]any{"path": "staging/debian/root/usr/share/doc/leaguebridge/SBOM.spdx.json", "role": "staging-payload", "size_bytes": json.Number("32"), "sha256": strings.Repeat("1", 64)},
		},
	}
	if err := schema.Validate(valid); err != nil {
		t.Fatalf("valid native package subject rejected: %v", err)
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
