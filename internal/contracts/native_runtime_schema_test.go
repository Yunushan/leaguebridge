package contracts

import (
	"encoding/json"
	"strings"
	"testing"
)

const nativeRuntimeSchemaID = "https://github.com/Yunushan/leaguebridge/schemas/native-runtime-attestation.schema.json"

func TestNativeRuntimeAttestationSchemaIsScoreFreeAndHostClassBound(t *testing.T) {
	schema := compileOffline(t, "schemas/native-runtime-attestation.schema.json", nativeRuntimeSchemaID)
	valid := map[string]any{
		"$schema": nativeRuntimeSchemaID, "schema_version": json.Number("2"),
		"attestation_type": "leaguebridge.native-runtime-attestation.v2", "kind": "linux-runtime",
		"generated_at": "2026-08-29T00:00:00Z",
		"source": map[string]any{
			"repository": "Yunushan/leaguebridge", "commit": strings.Repeat("a", 40),
			"tree": strings.Repeat("b", 40), "ref": "refs/heads/main", "workflow": "CI",
			"workflow_ref": "Yunushan/leaguebridge/.github/workflows/ci.yml@refs/heads/main",
			"workflow_sha": strings.Repeat("c", 40), "run_id": "1234", "run_attempt": "1",
		},
		"execution": map[string]any{
			"job": "linux-runtime", "runner_os": "Linux", "runner_architecture": "X64",
			"host_class": "hosted", "go_version": "go1.27.0", "command": "native runtime smoke",
			"target": map[string]any{"goos": "linux", "goarch": "amd64"},
		},
		"subjects": []any{
			map[string]any{"path": "ci-bin/leaguebridge-linux-amd64", "role": "runtime-binary", "size_bytes": json.Number("128"), "sha256": strings.Repeat("d", 64)},
			map[string]any{"path": "linux-evidence/result.txt", "role": "runtime-evidence", "size_bytes": json.Number("32"), "sha256": strings.Repeat("e", 64)},
		},
	}
	if err := schema.Validate(valid); err != nil {
		t.Fatalf("valid native runtime subject rejected: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"score field":             func(value map[string]any) { value["score"] = json.Number("100") },
		"virtualized Linux claim": func(value map[string]any) { value["execution"].(map[string]any)["host_class"] = "virtualized" },
		"unsafe evidence path": func(value map[string]any) {
			value["subjects"].([]any)[1].(map[string]any)["path"] = "linux-evidence/../result.txt"
		},
		"missing binary": func(value map[string]any) { value["subjects"].([]any)[0].(map[string]any)["role"] = "runtime-evidence" },
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(valid)
			if err != nil {
				t.Fatal(err)
			}
			clone := decodeJSONBytes(t, data).(map[string]any)
			mutate(clone)
			if err := schema.Validate(clone); err == nil {
				t.Fatal("schema accepted invalid native runtime subject")
			}
		})
	}

	data, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	bsd := decodeJSONBytes(t, data).(map[string]any)
	bsd["kind"] = "bsd-runtime"
	bsdExecution := bsd["execution"].(map[string]any)
	bsdExecution["job"] = "bsd-runtime"
	bsdExecution["host_class"] = "virtualized"
	bsdTarget := bsdExecution["target"].(map[string]any)
	bsdTarget["goos"] = "freebsd"
	bsdTarget["goarch"] = "arm64"
	bsdSubjects := bsd["subjects"].([]any)
	bsdSubjects[0].(map[string]any)["path"] = "bsd-ci/leaguebridge-freebsd-arm64"
	bsdSubjects[1].(map[string]any)["path"] = "bsd-evidence/freebsd/arm64/result.txt"
	if err := schema.Validate(bsd); err != nil {
		t.Fatalf("valid FreeBSD arm64 native runtime subject rejected: %v", err)
	}
	bsdTarget["goos"] = "dragonfly"
	if err := schema.Validate(bsd); err == nil {
		t.Fatal("schema accepted DragonFly arm64 native runtime subject")
	}
}
