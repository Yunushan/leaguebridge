package contracts

import (
	"encoding/json"
	"strings"
	"testing"
)

const readinessPromotionSchemaID = "https://leaguebridge.dev/schemas/readiness-promotion-v4.schema.json"

func TestReadinessPromotionV4SchemaAcceptsOnlyDerivedCompleteRemoteCells(t *testing.T) {
	schema := compileOffline(t, "schemas/readiness-promotion-v4.schema.json", readinessPromotionSchemaID)
	for _, route := range []struct {
		name         string
		route        string
		hostPlatform string
		hostArch     string
	}{
		{name: "windows", route: "physical-windows-remote", hostPlatform: "windows", hostArch: "amd64"},
		{name: "macos-arm64", route: "physical-macos-remote", hostPlatform: "macos", hostArch: "arm64"},
		{name: "macos-amd64", route: "physical-macos-remote", hostPlatform: "macos", hostArch: "amd64"},
	} {
		route := route
		t.Run(route.name, func(t *testing.T) {
			document := readinessPromotionFixture(route.route, route.hostPlatform, route.hostArch)
			if err := schema.Validate(document); err != nil {
				t.Fatalf("valid readiness promotion rejected: %v", err)
			}
		})
	}
}

func TestReadinessPromotionV4SchemaRejectsForgedPromotionFields(t *testing.T) {
	schema := compileOffline(t, "schemas/readiness-promotion-v4.schema.json", readinessPromotionSchemaID)
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "wrong score", mutate: func(document map[string]any) { document["score"] = json.Number("99") }},
		{name: "false gate", mutate: func(document map[string]any) { document["gates"].([]any)[0].(map[string]any)["passed"] = false }},
		{name: "wrong Windows host", mutate: func(document map[string]any) { document["host_platform"] = "macos" }},
		{name: "wrong macOS host architecture", mutate: func(document map[string]any) { document["host_architecture"] = "mips64" }},
		{name: "local authorization field", mutate: func(document map[string]any) { document["launch_authorization"] = true }},
		{name: "wrong evidence type", mutate: func(document map[string]any) { document["evidence_type"] = "validation-evidence-v1" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := readinessPromotionFixture("physical-windows-remote", "windows", "amd64")
			test.mutate(document)
			if err := schema.Validate(document); err == nil {
				t.Fatal("forged readiness promotion was accepted")
			}
		})
	}
}

func readinessPromotionFixture(route, hostPlatform, hostArch string) map[string]any {
	gate := func(id string) map[string]any {
		return map[string]any{"id": id, "weight": json.Number("25"), "passed": true}
	}
	return map[string]any{
		"$schema":               readinessPromotionSchemaID,
		"schema_version":        json.Number("4"),
		"evidence_type":         "validation-evidence-v2",
		"promotion_boundary":    "readiness-schema-v4",
		"set_id":                "set-0123456789abcdef0123456789abcdef",
		"validation_run_id":     "run-0123456789abcdef0123456789abcdef",
		"route_id":              route,
		"test_profile_id":       "remote-play-v1",
		"policy_id":             "fixture-reviewers-v1",
		"created_at":            "2026-08-26T11:00:00Z",
		"expires_at":            "2026-09-02T11:00:00Z",
		"manifest_as_of":        "2026-08-26",
		"manifest_sha256":       strings.Repeat("a", 64),
		"host_platform":         hostPlatform,
		"host_architecture":     hostArch,
		"client_platform":       "linux",
		"client_architecture":   "amd64",
		"host_record_sha256":    strings.Repeat("b", 64),
		"client_record_sha256":  strings.Repeat("c", 64),
		"session_record_sha256": strings.Repeat("d", 64),
		"payload_sha256":        strings.Repeat("e", 64),
		"score":                 json.Number("100"),
		"state":                 "validated",
		"promotion_safe":        true,
		"gates": []any{
			gate("physical-host"), gate("client-runtime"), gate("session-quality"), gate("gameplay-interaction"),
		},
		"signer_key_ids":          []any{"reviewer-lab", "reviewer-independent"},
		"signer_principal_ids":    []any{"lab-observer", "independent-reviewer"},
		"signer_organization_ids": []any{"lab-org", "audit-org"},
	}
}
