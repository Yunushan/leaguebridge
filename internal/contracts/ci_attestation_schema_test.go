package contracts

import (
	"encoding/json"
	"testing"
)

const ciAttestationSchemaID = "https://github.com/Yunushan/leaguebridge/schemas/ci-attestation.schema.json"

func TestCIAttestationSubjectsConformToPublicSchema(t *testing.T) {
	schema := compileOffline(t, "schemas/ci-attestation.schema.json", ciAttestationSchemaID)
	valid := map[string]any{
		"$schema": ciAttestationSchemaID, "schema_version": json.Number("1"),
		"attestation_type": "leaguebridge.ci-attestation.v1", "kind": "cross-build",
		"generated_at": "2026-08-28T12:00:00Z",
		"source": map[string]any{
			"repository": "Yunushan/leaguebridge", "commit": "0123456789abcdef0123456789abcdef01234567",
			"tree": "89abcdef0123456789abcdef0123456789abcdef", "ref": "refs/heads/main",
			"workflow": "CI", "workflow_ref": "Yunushan/leaguebridge/.github/workflows/ci.yml@refs/heads/main",
			"workflow_sha": "fedcba9876543210fedcba9876543210fedcba98", "run_id": "123456789", "run_attempt": "1",
		},
		"execution": map[string]any{
			"job": "cross-build", "runner_os": "Linux", "runner_architecture": "X64", "go_version": "go1.27.0",
			"command": "go build -mod=vendor ./cmd/leaguebridge",
			"target":  map[string]any{"goos": "freebsd", "goarch": "amd64"},
		},
		"subjects": []any{map[string]any{
			"path": "ci-build/leaguebridge-freebsd-amd64", "role": "cross-build-binary",
			"size_bytes": json.Number("128"), "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}},
	}
	if err := schema.Validate(valid); err != nil {
		t.Fatalf("valid CI attestation subject rejected: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"score field":         func(value map[string]any) { value["score"] = json.Number("100") },
		"invalid commit":      func(value map[string]any) { value["source"].(map[string]any)["commit"] = "not-a-commit" },
		"race binary subject": func(value map[string]any) { value["kind"] = "race-vet" },
		"target-bound path": func(value map[string]any) {
			value["subjects"].([]any)[0].(map[string]any)["path"] = "ci-build/leaguebridge-linux-amd64"
		},
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(valid)
			if err != nil {
				t.Fatal(err)
			}
			clone := decodeJSONBytes(t, data)
			mutate(clone.(map[string]any))
			if err := schema.Validate(clone); err == nil {
				t.Fatal("schema accepted invalid CI attestation subject")
			}
		})
	}
}
