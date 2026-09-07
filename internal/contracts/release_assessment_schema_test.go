package contracts

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
)

func TestReleaseAssessmentOutputSchemaMatchesDerivedProtocol(t *testing.T) {
	schema := compileOffline(t, "schemas/release-assessment.schema.json", "https://github.com/Yunushan/leaguebridge/schemas/release-assessment.schema.json")
	fixture := releaseassessment.Result{
		SchemaVersion: 1, Version: "v0.1.0", Commit: "a2202eb7072cdfef5e62c179d341a3d79d4d91ce", Tree: "313fb6ff2a1ce314441f23720ff8efdbf933ffc1",
		ReleaseID: 384256185, ReleaseRunID: 34150052066, ReleaseRunAttempt: 1, CIRunID: 34147122944, CIRunAttempt: 1,
		ObservedAt: time.Date(2026, 9, 7, 18, 30, 0, 0, time.UTC), ScorecardExpiresAt: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC),
		RepositoryScore: 74, Score: 83,
		Criteria: []releaseassessment.Criterion{
			{ID: "tests-race-vet-linux", Name: "Linux race and vet", EvidenceType: "ci-attestation-v1", VerifierID: "ci-race-vet-v1", Points: 3},
			{ID: "tests-nine-target-cross-build", Name: "Nine-target Linux/BSD cross-build", EvidenceType: "ci-attestation-v1", VerifierID: "ci-nine-target-cross-build-v1", Points: 3},
			{ID: "packaging-nine-release-archives", Name: "Nine published Linux/BSD release archives", EvidenceType: "release-attestation-v1", VerifierID: "release-nine-archives-v1", Points: 2},
			{ID: "packaging-publication-attestation", Name: "Release publication and attestation", EvidenceType: "release-attestation-v1", VerifierID: "release-publication-attestation-v1", Points: 1},
		},
	}
	data, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(decodeJSONBytes(t, data)); err != nil {
		t.Fatalf("valid output rejected: %v", err)
	}
	for name, change := range map[string]func(map[string]any){
		"unearned full score":    func(value map[string]any) { value["score"] = json.Number("100") },
		"gameplay authorization": func(value map[string]any) { value["launch_authorized"] = true },
		"durable receipt":        func(value map[string]any) { value["receipt_valid_until"] = "2027-01-01T00:00:00Z" },
		"missing release source": func(value map[string]any) { delete(value, "commit") },
		"missing attempt":        func(value map[string]any) { delete(value, "release_run_attempt") },
		"incomplete criteria":    func(value map[string]any) { value["criteria"] = value["criteria"].([]any)[:3] },
		"increased criterion weight": func(value map[string]any) {
			value["criteria"].([]any)[0].(map[string]any)["points"] = json.Number("20")
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := decodeJSONBytes(t, data).(map[string]any)
			change(value)
			if err := schema.Validate(value); err == nil {
				t.Fatal("output schema accepted a claim outside the protocol")
			}
		})
	}
}
