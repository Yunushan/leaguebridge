package contracts

import (
	"encoding/json"
	"strings"
	"testing"
)

const productionAssessmentSchemaID = "https://github.com/Yunushan/leaguebridge/schemas/production-assessment.schema.json"

// This fixture exercises the output shape only. It is not a verified release
// assessment, accepted proof, or a claim about any published version.
func productionAssessmentFixture(t *testing.T) map[string]any {
	t.Helper()
	assetNames := []string{
		"checksums.txt",
		"leaguebridge_1.2.3_dragonfly_amd64.tar.gz",
		"leaguebridge_1.2.3_freebsd_amd64.tar.gz",
		"leaguebridge_1.2.3_freebsd_arm64.tar.gz",
		"leaguebridge_1.2.3_linux_amd64.tar.gz",
		"leaguebridge_1.2.3_linux_arm64.tar.gz",
		"leaguebridge_1.2.3_netbsd_amd64.tar.gz",
		"leaguebridge_1.2.3_netbsd_arm64.tar.gz",
		"leaguebridge_1.2.3_openbsd_amd64.tar.gz",
		"leaguebridge_1.2.3_openbsd_arm64.tar.gz",
	}
	assets := make([]any, 0, len(assetNames))
	for _, name := range assetNames {
		assets = append(assets, map[string]any{"name": name, "sha256": strings.Repeat("a", 64), "size_bytes": 1024})
	}
	criteria := []any{
		productionMissingRow("architecture-upstream-authorization", "Authorized upstream extension contract", 2, "vendor-authorization-v1", "riot-linux-bsd-authorization-v1"),
		productionMissingRow("implementation-native-validated-integration", "Native validated platform integration", 3, "native-runtime-attestation-v2", "native-integration-v2"),
		productionMissingRow("tests-native-bsd-physical-smoke", "Native BSD and physical-hardware smoke tests", 5, "native-runtime-attestation-v2", "native-bsd-physical-smoke-v2"),
		productionMissingRow("security-independent-audit-closed", "Closed independent audit findings", 2, "independent-audit-v1", "independent-audit-v1"),
		productionMissingRow("packaging-native-os-packages", "Native OS packages", 3, "package-attestation-v1", "native-packages-v1"),
		productionMissingRow("packaging-install-uninstall-native-smoke", "Install/uninstall and native smoke evidence", 2, "native-runtime-attestation-v2", "install-native-smoke-v2"),
	}
	value := map[string]any{
		"schema_version": 1,
		"release": map[string]any{
			"version": "v1.2.3", "commit": strings.Repeat("a", 40), "tree": strings.Repeat("b", 40),
			"release_id": 1, "release_run_id": 2, "release_run_attempt": 1, "ci_run_id": 3, "ci_run_attempt": 1,
			"scorecard_sha256": strings.Repeat("c", 64), "scorecard_expires_at": "2030-10-01T00:00:00Z", "assets": assets,
		},
		"observed_at": "2030-09-01T00:00:00Z", "evidence_expires_at": "2030-09-02T00:00:00Z",
		"repository_score": 74, "release_score": 83, "score": 83, "criteria": criteria,
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return decodeJSONBytes(t, data).(map[string]any)
}

func productionMissingRow(id, name string, weight int, evidenceType, verifierID string) map[string]any {
	return map[string]any{
		"id": id, "name": name, "weight": weight, "evidence_type": evidenceType, "verifier_id": verifierID,
		"points": 0, "status": "missing_evidence", "missing_evidence": []string{"Independent proof is unavailable"},
	}
}

func TestProductionAssessmentOutputSchema(t *testing.T) {
	schema := compileOffline(t, "schemas/production-assessment.schema.json", productionAssessmentSchemaID)
	if err := schema.Validate(productionAssessmentFixture(t)); err != nil {
		t.Fatalf("valid output shape rejected: %v", err)
	}
	withOneVerified := productionAssessmentFixture(t)
	verifiedRow := withOneVerified["criteria"].([]any)[0].(map[string]any)
	verifiedRow["status"] = "verified"
	verifiedRow["points"] = json.Number("2")
	delete(verifiedRow, "missing_evidence")
	withOneVerified["score"] = json.Number("85")
	if err := schema.Validate(withOneVerified); err != nil {
		t.Fatalf("valid full-weight row shape rejected: %v", err)
	}

	for name, change := range map[string]func(map[string]any){
		"wrong version":               func(v map[string]any) { v["schema_version"] = json.Number("3") },
		"caller evidence":             func(v map[string]any) { v["evidence"] = []any{} },
		"caller trust key":            func(v map[string]any) { v["trust_policy"] = map[string]any{"key": "caller"} },
		"gameplay overclaim":          func(v map[string]any) { v["launch_authorized"] = true },
		"missing source tree":         func(v map[string]any) { delete(v["release"].(map[string]any), "tree") },
		"invalid commit":              func(v map[string]any) { v["release"].(map[string]any)["commit"] = strings.Repeat("z", 40) },
		"invalid scorecard digest":    func(v map[string]any) { v["release"].(map[string]any)["scorecard_sha256"] = "unknown" },
		"missing CI attempt":          func(v map[string]any) { delete(v["release"].(map[string]any), "ci_run_attempt") },
		"repository baseline dropped": func(v map[string]any) { v["repository_score"] = json.Number("73") },
		"release baseline dropped":    func(v map[string]any) { v["release_score"] = json.Number("82") },
		"release score over ceiling":  func(v map[string]any) { v["release_score"] = json.Number("84") },
		"overall below baseline":      func(v map[string]any) { v["score"] = json.Number("82") },
		"missing expiry":              func(v map[string]any) { delete(v, "evidence_expires_at") },
		"malformed observation time":  func(v map[string]any) { v["observed_at"] = "yesterday" },
		"missing published asset": func(v map[string]any) {
			release := v["release"].(map[string]any)
			release["assets"] = release["assets"].([]any)[:9]
		},
		"duplicate target asset": func(v map[string]any) {
			assets := v["release"].(map[string]any)["assets"].([]any)
			assets[4].(map[string]any)["name"] = assets[3].(map[string]any)["name"]
		},
		"zero asset size": func(v map[string]any) {
			v["release"].(map[string]any)["assets"].([]any)[0].(map[string]any)["size_bytes"] = json.Number("0")
		},
		"asset-supplied signature": func(v map[string]any) {
			v["release"].(map[string]any)["assets"].([]any)[0].(map[string]any)["signature"] = "self"
		},
		"incomplete criteria": func(v map[string]any) { v["criteria"] = v["criteria"].([]any)[:5] },
		"reordered criteria": func(v map[string]any) {
			rows := v["criteria"].([]any)
			rows[0], rows[1] = rows[1], rows[0]
		},
		"changed verifier":          func(v map[string]any) { v["criteria"].([]any)[0].(map[string]any)["verifier_id"] = "caller-verifier" },
		"changed weight":            func(v map[string]any) { v["criteria"].([]any)[0].(map[string]any)["weight"] = json.Number("10") },
		"partial row credit":        func(v map[string]any) { v["criteria"].([]any)[2].(map[string]any)["points"] = json.Number("2") },
		"missing proof with credit": func(v map[string]any) { v["criteria"].([]any)[0].(map[string]any)["points"] = json.Number("2") },
		"zero-point verified row": func(v map[string]any) {
			row := v["criteria"].([]any)[0].(map[string]any)
			row["status"] = "verified"
			delete(row, "missing_evidence")
		},
		"verified row with missing reason": func(v map[string]any) {
			row := v["criteria"].([]any)[0].(map[string]any)
			row["status"] = "verified"
			row["points"] = json.Number("2")
		},
		"missing reason":      func(v map[string]any) { delete(v["criteria"].([]any)[0].(map[string]any), "missing_evidence") },
		"row-supplied proof":  func(v map[string]any) { v["criteria"].([]any)[0].(map[string]any)["proof"] = "caller" },
		"unearned full score": func(v map[string]any) { v["score"] = json.Number("100") },
	} {
		t.Run(name, func(t *testing.T) {
			if err := schema.Validate(changeProductionFixture(t, change)); err == nil {
				t.Fatal("output schema accepted a malformed or overclaiming result")
			}
		})
	}
}

func changeProductionFixture(t *testing.T, change func(map[string]any)) map[string]any {
	t.Helper()
	value := productionAssessmentFixture(t)
	change(value)
	return value
}
