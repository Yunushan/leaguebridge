package readiness

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

var readinessTestNow = time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)

func validTestScorecard(t *testing.T) Scorecard {
	t.Helper()
	scorecard, err := ParseAt(embedded, readinessTestNow)
	if err != nil {
		t.Fatalf("parse embedded scorecard: %v", err)
	}
	return scorecard
}

func TestEmbeddedV3ScoresAreDerived(t *testing.T) {
	scorecard := validTestScorecard(t)
	if scorecard.SchemaVersion != 3 {
		t.Fatalf("schema version = %d, want 3", scorecard.SchemaVersion)
	}
	if got := scorecard.EngineeringScore(); got != 74 {
		t.Fatalf("engineering score = %d, want 74", got)
	}
	wantCategories := map[string]int{
		"honest-scope": 10, "governance-legal-privacy": 10,
		"architecture-contracts": 13, "implementation": 17,
		"tests-ci": 9, "security-supply-chain": 13,
		"packaging-operations": 2,
	}
	criteria := 0
	for _, category := range scorecard.Engineering {
		criteria += len(category.Subcriteria)
		if got := scorecard.EngineeringCategoryScore(category.ID); got != wantCategories[category.ID] {
			t.Errorf("category %q score = %d, want %d", category.ID, got, wantCategories[category.ID])
		}
	}
	if criteria != 30 {
		t.Fatalf("subcriterion count = %d, want 30", criteria)
	}
	if scorecard.LocalGameplay.Score != 0 || scorecard.LocalGameplay.State != "blocked" {
		t.Fatalf("local gameplay = %+v, want 0/blocked", scorecard.LocalGameplay)
	}

	remoteHandoffs := scorecard.EvaluateRemoteHandoffs()
	if len(remoteHandoffs) != 2 || remoteHandoffs[0].RouteID != RemoteWindowsRouteID || remoteHandoffs[1].RouteID != RemoteMacOSRouteID {
		t.Fatalf("remote route evaluations = %+v", remoteHandoffs)
	}
	for _, remote := range remoteHandoffs {
		if remote.Score != 0 || remote.State != "unvalidated" || len(remote.Platforms) != 9 {
			t.Fatalf("remote evaluation = %+v", remote)
		}
		for _, platform := range remote.Platforms {
			if platform.Score != 0 || platform.State != "unvalidated" || len(platform.Gates) != 4 {
				t.Fatalf("remote platform = %+v", platform)
			}
			for _, gate := range platform.Gates {
				if gate.Passed || gate.Weight != 25 {
					t.Fatalf("remote gate = %+v", gate)
				}
			}
		}
	}
	if !strings.Contains(remoteHandoffs[1].Reason, "experimental") || !strings.Contains(remoteHandoffs[1].Reason, "gamepad hosting is unavailable") {
		t.Fatalf("macOS route limitations were lost: %q", remoteHandoffs[1].Reason)
	}
}

func TestEngineeringEvaluationRequiresExactBuildTimeVerification(t *testing.T) {
	scorecard := validTestScorecard(t)
	for _, value := range []string{
		"",
		strings.Repeat("0", 64),
		RepositoryEvidenceVerificationPrefix + strings.Repeat("0", 64),
		ExpectedRepositoryEvidenceVerification() + "-extra",
	} {
		evaluation := scorecard.EvaluateEngineering(value)
		if evaluation.RepositoryEvidenceVerified || evaluation.Score != 0 || evaluation.CategoryScore("honest-scope") != 0 || evaluation.VerificationReason != RepositoryEvidenceUnverifiedReason {
			t.Fatalf("verification %q produced %+v", value, evaluation)
		}
	}

	evaluation := scorecard.EvaluateEngineering(ExpectedRepositoryEvidenceVerification())
	if !evaluation.RepositoryEvidenceVerified || evaluation.Score != 74 || evaluation.CategoryScore("honest-scope") != 10 || evaluation.VerificationReason != RepositoryEvidenceVerifiedReason {
		t.Fatalf("verified evaluation = %+v", evaluation)
	}
	wantDigest := fmt.Sprintf("%x", sha256.Sum256(EmbeddedJSON()))
	if EmbeddedSHA256() != wantDigest {
		t.Fatalf("embedded digest = %q, want %q", EmbeddedSHA256(), wantDigest)
	}
}

func TestPublicScorecardMatchesEmbeddedSemantically(t *testing.T) {
	publicData, err := os.ReadFile(readinessRepositoryFile(t, "readiness", "scorecard.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publicData, embedded) {
		t.Fatal("public and embedded readiness scorecards differ byte-for-byte")
	}
	publicScorecard, err := ParseAt(publicData, readinessTestNow)
	if err != nil {
		t.Fatalf("parse public scorecard: %v", err)
	}
	if !reflect.DeepEqual(publicScorecard, validTestScorecard(t)) {
		t.Fatal("public and embedded readiness scorecards differ semantically")
	}
}

func TestParseRejectsScoreAndPromotionInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "category earned", mutate: func(document map[string]any) {
			document["engineering"].([]any)[0].(map[string]any)["earned"] = 100
		}},
		{name: "criterion passed", mutate: func(document map[string]any) {
			document["engineering"].([]any)[0].(map[string]any)["subcriteria"].([]any)[0].(map[string]any)["passed"] = true
		}},
		{name: "remote score", mutate: func(document map[string]any) {
			document["remote_handoffs"].([]any)[0].(map[string]any)["score"] = 100
		}},
		{name: "remote state", mutate: func(document map[string]any) {
			document["remote_handoffs"].([]any)[0].(map[string]any)["state"] = "candidate"
		}},
		{name: "remote gates", mutate: func(document map[string]any) {
			document["remote_handoffs"].([]any)[0].(map[string]any)["gates"] = []any{}
		}},
		{name: "platform passed", mutate: func(document map[string]any) {
			document["remote_handoffs"].([]any)[0].(map[string]any)["platforms"].([]any)[0].(map[string]any)["passed"] = true
		}},
		{name: "legacy singular remote handoff", mutate: func(document map[string]any) {
			document["remote_handoff"] = document["remote_handoffs"].([]any)[0]
			delete(document, "remote_handoffs")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := mutateEmbeddedDocument(t, test.mutate)
			if _, err := ParseAt(data, readinessTestNow); err == nil {
				t.Fatal("mutable score or promotion input was accepted")
			}
		})
	}
}

func TestValidateRejectsEveryFixedContractMutation(t *testing.T) {
	validReference := EvidenceReference{Path: "README.md", SHA256: strings.Repeat("a", 64)}
	tests := []struct {
		name   string
		mutate func(*Scorecard)
	}{
		{name: "schema version", mutate: func(s *Scorecard) { s.SchemaVersion = 2 }},
		{name: "missing assessed time", mutate: func(s *Scorecard) { s.AssessedAt = time.Time{} }},
		{name: "missing expires time", mutate: func(s *Scorecard) { s.ExpiresAt = time.Time{} }},
		{name: "category count", mutate: func(s *Scorecard) { s.Engineering = s.Engineering[:6] }},
		{name: "category order", mutate: func(s *Scorecard) { s.Engineering[0], s.Engineering[1] = s.Engineering[1], s.Engineering[0] }},
		{name: "category id", mutate: func(s *Scorecard) { s.Engineering[0].ID = "tests-ci" }},
		{name: "category name", mutate: func(s *Scorecard) { s.Engineering[0].Name = "Renamed" }},
		{name: "category weight", mutate: func(s *Scorecard) { s.Engineering[0].Weight = 99 }},
		{name: "subcriterion count", mutate: func(s *Scorecard) { s.Engineering[0].Subcriteria = s.Engineering[0].Subcriteria[:2] }},
		{name: "subcriterion order", mutate: func(s *Scorecard) {
			s.Engineering[0].Subcriteria[0], s.Engineering[0].Subcriteria[1] = s.Engineering[0].Subcriteria[1], s.Engineering[0].Subcriteria[0]
		}},
		{name: "subcriterion id", mutate: func(s *Scorecard) { s.Engineering[0].Subcriteria[0].ID = "other" }},
		{name: "subcriterion name", mutate: func(s *Scorecard) { s.Engineering[0].Subcriteria[0].Name = "Other" }},
		{name: "subcriterion weight", mutate: func(s *Scorecard) { s.Engineering[0].Subcriteria[0].Weight = 100 }},
		{name: "evidence type", mutate: func(s *Scorecard) { s.Engineering[0].Subcriteria[0].EvidenceType = CIAttestationV1 }},
		{name: "verifier id", mutate: func(s *Scorecard) { s.Engineering[0].Subcriteria[0].VerifierID = "other-v1" }},
		{name: "null repository evidence", mutate: func(s *Scorecard) { s.Engineering[0].Subcriteria[0].Evidence = nil }},
		{name: "missing repository evidence", mutate: func(s *Scorecard) { s.Engineering[0].Subcriteria[0].Evidence = []EvidenceReference{} }},
		{name: "additional repository evidence", mutate: func(s *Scorecard) {
			s.Engineering[0].Subcriteria[0].Evidence = append(s.Engineering[0].Subcriteria[0].Evidence, validReference)
		}},
		{name: "reordered repository evidence", mutate: func(s *Scorecard) {
			references := s.Engineering[1].Subcriteria[0].Evidence
			references[0], references[1] = references[1], references[0]
		}},
		{name: "arbitrary repository file", mutate: func(s *Scorecard) { s.Engineering[0].Subcriteria[0].Evidence[0].Path = "CHANGELOG.md" }},
		{name: "traversal repository file", mutate: func(s *Scorecard) { s.Engineering[0].Subcriteria[0].Evidence[0].Path = "../README.md" }},
		{name: "uppercase digest", mutate: func(s *Scorecard) { s.Engineering[0].Subcriteria[0].Evidence[0].SHA256 = strings.Repeat("A", 64) }},
		{name: "external criterion arbitrary file", mutate: func(s *Scorecard) { s.Engineering[2].Subcriteria[3].Evidence = []EvidenceReference{validReference} }},
		{name: "null external evidence", mutate: func(s *Scorecard) { s.Engineering[2].Subcriteria[3].Evidence = nil }},
		{name: "local score", mutate: func(s *Scorecard) { s.LocalGameplay.Score = 1 }},
		{name: "local state", mutate: func(s *Scorecard) { s.LocalGameplay.State = "candidate" }},
		{name: "local reason", mutate: func(s *Scorecard) { s.LocalGameplay.Reason = "League is supported locally through Wine" }},
		{name: "oversized local reason", mutate: func(s *Scorecard) { s.LocalGameplay.Reason = strings.Repeat("x", MaximumReasonSize+1) }},
		{name: "remote route count", mutate: func(s *Scorecard) { s.RemoteHandoffs = s.RemoteHandoffs[:1] }},
		{name: "remote route order", mutate: func(s *Scorecard) {
			s.RemoteHandoffs[0], s.RemoteHandoffs[1] = s.RemoteHandoffs[1], s.RemoteHandoffs[0]
		}},
		{name: "remote route", mutate: func(s *Scorecard) { s.RemoteHandoffs[0].RouteID = "wine" }},
		{name: "remote evidence version", mutate: func(s *Scorecard) { s.RemoteHandoffs[0].RequiredEvidenceSchemaVersion = 1 }},
		{name: "windows reason", mutate: func(s *Scorecard) { s.RemoteHandoffs[0].Reason = "unvalidated" }},
		{name: "macos limitations removed", mutate: func(s *Scorecard) { s.RemoteHandoffs[1].Reason = "unvalidated" }},
		{name: "remote platform count", mutate: func(s *Scorecard) { s.RemoteHandoffs[0].Platforms = s.RemoteHandoffs[0].Platforms[:4] }},
		{name: "remote platform order", mutate: func(s *Scorecard) { s.RemoteHandoffs[0].Platforms[0].Platform = "freebsd" }},
		{name: "remote architecture", mutate: func(s *Scorecard) { s.RemoteHandoffs[0].Platforms[0].Architecture = "arm64" }},
		{name: "null remote evidence sets", mutate: func(s *Scorecard) { s.RemoteHandoffs[0].Platforms[0].EvidenceSets = nil }},
		{name: "schema v1 manual remote evidence", mutate: func(s *Scorecard) {
			s.RemoteHandoffs[0].Platforms[0].EvidenceSets = []RemoteEvidenceSetReference{{EvidenceType: "validation-evidence-v1", SchemaVersion: 1, Path: "docs/evidence/examples/client-linux-unverified.json", SHA256: strings.Repeat("a", 64)}}
		}},
		{name: "plausible schema v2 remote evidence", mutate: func(s *Scorecard) {
			s.RemoteHandoffs[0].Platforms[0].EvidenceSets = []RemoteEvidenceSetReference{{EvidenceType: "validation-evidence-v2", SchemaVersion: 2, Path: "docs/evidence/reviewed.json", SHA256: strings.Repeat("a", 64)}}
		}},
		{name: "macos schema v2 remote evidence", mutate: func(s *Scorecard) {
			s.RemoteHandoffs[1].Platforms[0].EvidenceSets = []RemoteEvidenceSetReference{{EvidenceType: "validation-evidence-v2", SchemaVersion: 2, Path: "docs/evidence/macos-reviewed.json", SHA256: strings.Repeat("a", 64)}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scorecard := validTestScorecard(t)
			test.mutate(&scorecard)
			if err := scorecard.ValidateAt(readinessTestNow); err == nil {
				t.Fatal("fixed-contract mutation was accepted")
			}
		})
	}
}

func TestValidityAndParserBoundsFailClosed(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		now  time.Time
	}{
		{name: "empty", data: []byte(`{}`), now: readinessTestNow},
		{name: "duplicate root key", data: []byte(strings.Replace(string(embedded), `"schema_version": 3`, `"schema_version": 3, "schema_version": 3`, 1)), now: readinessTestNow},
		{name: "duplicate nested key", data: []byte(strings.Replace(string(embedded), `"platform":"linux"`, `"platform":"linux","platform":"linux"`, 1)), now: readinessTestNow},
		{name: "case-variant root key", data: []byte(strings.Replace(string(embedded), `"schema_version": 3`, `"Schema_Version": 3`, 1)), now: readinessTestNow},
		{name: "case-variant nested key", data: []byte(strings.Replace(string(embedded), `"evidence_type":"repository-content-v1"`, `"Evidence_Type":"repository-content-v1"`, 1)), now: readinessTestNow},
		{name: "case-variant array object key", data: []byte(strings.Replace(string(embedded), `"platform":"linux"`, `"Platform":"linux"`, 1)), now: readinessTestNow},
		{name: "null local score", data: []byte(strings.Replace(string(embedded), `"score": 0`, `"score": null`, 1)), now: readinessTestNow},
		{name: "missing local score", data: []byte(strings.Replace(string(embedded), "    \"score\": 0,\n", "", 1)), now: readinessTestNow},
		{name: "multiple values", data: append(append([]byte{}, embedded...), []byte(` {}`)...), now: readinessTestNow},
		{name: "malformed trailing value", data: append(append([]byte{}, embedded...), []byte(` {`)...), now: readinessTestNow},
		{name: "oversized", data: make([]byte, MaximumScorecardSize+1), now: readinessTestNow},
		{name: "excess nesting", data: []byte(strings.Repeat("[", 66) + strings.Repeat("]", 66)), now: readinessTestNow},
		{name: "future assessment", data: mutateEmbeddedDocument(t, func(document map[string]any) {
			document["assessed_at"] = readinessTestNow.Add(MaximumFutureSkew + time.Second).Format(time.RFC3339)
			document["expires_at"] = readinessTestNow.Add(24 * time.Hour).Format(time.RFC3339)
		}), now: readinessTestNow},
		{name: "expired", data: embedded, now: time.Date(2026, time.October, 3, 0, 0, 1, 0, time.UTC)},
		{name: "validity over maximum", data: mutateEmbeddedDocument(t, func(document map[string]any) {
			document["expires_at"] = time.Date(2026, time.October, 4, 0, 0, 1, 0, time.UTC).Format(time.RFC3339Nano)
		}), now: readinessTestNow},
		{name: "zero validity", data: mutateEmbeddedDocument(t, func(document map[string]any) {
			document["expires_at"] = document["assessed_at"]
		}), now: readinessTestNow},
		{name: "missing evaluation time", data: embedded, now: time.Time{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseAt(test.data, test.now); err == nil {
				t.Fatal("invalid or stale scorecard was accepted")
			}
		})
	}
}

func TestEngineeringScoreCannotBeInflatedByMalformedInputs(t *testing.T) {
	scorecard := validTestScorecard(t)
	scorecard.Engineering[0].Subcriteria[0].ID = "forged"
	if got := scorecard.EngineeringScore(); got != 70 {
		t.Fatalf("score after forged four-point criterion = %d, want 70", got)
	}
	scorecard = validTestScorecard(t)
	scorecard.Engineering[2].Subcriteria[3].Evidence = []EvidenceReference{{Path: "README.md", SHA256: strings.Repeat("a", 64)}}
	if got := scorecard.EngineeringScore(); got != 74 {
		t.Fatalf("unsupported external evidence inflated score to %d", got)
	}
	scorecard = validTestScorecard(t)
	scorecard.Engineering = append(scorecard.Engineering, scorecard.Engineering[0])
	if got := scorecard.EngineeringScore(); got != 74 {
		t.Fatalf("duplicate appended category changed derived score to %d", got)
	}
	scorecard = validTestScorecard(t)
	scorecard.Engineering[len(scorecard.Engineering)-1] = scorecard.Engineering[0]
	if got := scorecard.EngineeringScore(); got > 74 {
		t.Fatalf("duplicate replacement category inflated derived score to %d", got)
	}
}

func TestRemoteEvaluationCannotBeReplacedByMalformedInputs(t *testing.T) {
	scorecard := validTestScorecard(t)
	scorecard.RemoteHandoffs = []RemoteHandoff{{
		RouteID: "wine",
		Reason:  "supported",
		Platforms: []RemotePlatform{{
			Platform:     "windows",
			Architecture: "arm64",
		}},
	}}

	evaluations := scorecard.EvaluateRemoteHandoffs()
	if len(evaluations) != len(remoteRouteContract) {
		t.Fatalf("remote evaluation count = %d, want %d", len(evaluations), len(remoteRouteContract))
	}
	for routeIndex, route := range evaluations {
		contract := remoteRouteContract[routeIndex]
		if route.RouteID != contract.ID || route.Reason != contract.Reason || route.Score != 0 || route.State != "unvalidated" {
			t.Fatalf("remote route %d escaped fixed contract: %+v", routeIndex, route)
		}
		if len(route.Platforms) != len(remotePlatformContract) {
			t.Fatalf("remote route %d platform count = %d", routeIndex, len(route.Platforms))
		}
		for platformIndex, platform := range route.Platforms {
			contractPlatform := remotePlatformContract[platformIndex]
			if platform.Platform != contractPlatform.Platform || platform.Architecture != contractPlatform.Architecture || platform.Score != 0 || platform.State != "unvalidated" {
				t.Fatalf("remote route %d platform %d escaped fixed contract: %+v", routeIndex, platformIndex, platform)
			}
		}
	}
}

func TestEveryAuthenticatedEvidenceCriterionRemainsLocked(t *testing.T) {
	locked := 0
	seenTypes := map[string]bool{}
	for categoryIndex, category := range engineeringContract {
		for criterionIndex, criterion := range category.Subcriteria {
			if criterion.EvidenceType == RepositoryContentV1 {
				continue
			}
			locked++
			seenTypes[criterion.EvidenceType] = true
			t.Run(criterion.ID, func(t *testing.T) {
				scorecard := validTestScorecard(t)
				if evidence := scorecard.Engineering[categoryIndex].Subcriteria[criterionIndex].Evidence; evidence == nil || len(evidence) != 0 {
					t.Fatalf("locked criterion evidence = %#v, want an explicit empty array", evidence)
				}
				scorecard.Engineering[categoryIndex].Subcriteria[criterionIndex].Evidence = []EvidenceReference{{Path: "docs/evidence/self-asserted.json", SHA256: strings.Repeat("a", 64)}}
				if err := scorecard.ValidateAt(readinessTestNow); err == nil {
					t.Fatal("unauthenticated evidence was accepted")
				}
				if got := scorecard.EngineeringScore(); got != 74 {
					t.Fatalf("locked evidence changed derived score to %d", got)
				}
			})
		}
	}
	if locked != 10 {
		t.Fatalf("locked authenticated-evidence criterion count = %d, want 10", locked)
	}
	for _, evidenceType := range []string{CIAttestationV1, NativeRuntimeV2, VendorAuthorization, IndependentAuditV1, ReleaseAttestation, PackageAttestation} {
		if !seenTypes[evidenceType] {
			t.Errorf("authenticated evidence class %q is not represented", evidenceType)
		}
	}
}

func TestEmbeddedRepositoryEvidenceMatchesCheckout(t *testing.T) {
	scorecard := validTestScorecard(t)
	if err := scorecard.VerifyRepositoryEvidence(readinessRepositoryFile(t)); err != nil {
		t.Fatalf("verify repository evidence: %v", err)
	}
}

func TestRepositoryEvidenceIsContentAddressedRegularAndNonSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("trusted evidence")
	if err := os.WriteFile(filepath.Join(root, "real", "evidence.txt"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	reference := EvidenceReference{Path: "real/evidence.txt", SHA256: fmt.Sprintf("%x", sha256.Sum256(content))}
	if err := verifyEvidenceFile(root, reference); err != nil {
		t.Fatalf("regular evidence rejected: %v", err)
	}

	t.Run("digest mismatch", func(t *testing.T) {
		wrong := reference
		wrong.SHA256 = strings.Repeat("0", 64)
		if err := verifyEvidenceFile(root, wrong); err == nil || !strings.Contains(err.Error(), "SHA-256") {
			t.Fatalf("digest mismatch error = %v", err)
		}
	})
	t.Run("directory target", func(t *testing.T) {
		if err := verifyEvidenceFile(root, EvidenceReference{Path: "real", SHA256: strings.Repeat("0", 64)}); err == nil {
			t.Fatal("directory evidence accepted")
		}
	})
	t.Run("oversized target", func(t *testing.T) {
		path := filepath.Join(root, "large.bin")
		if err := os.WriteFile(path, make([]byte, MaximumEvidenceSize+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := verifyEvidenceFile(root, EvidenceReference{Path: "large.bin", SHA256: strings.Repeat("0", 64)}); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("oversized evidence error = %v", err)
		}
	})
	t.Run("final symlink", func(t *testing.T) {
		link := filepath.Join(root, "evidence-link.txt")
		if err := os.Symlink(filepath.Join(root, "real", "evidence.txt"), link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if err := verifyEvidenceFile(root, EvidenceReference{Path: "evidence-link.txt", SHA256: reference.SHA256}); err == nil {
			t.Fatal("final symlink accepted")
		}
	})
	t.Run("ancestor symlink", func(t *testing.T) {
		link := filepath.Join(root, "linked")
		if err := os.Symlink(filepath.Join(root, "real"), link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if err := verifyEvidenceFile(root, EvidenceReference{Path: "linked/evidence.txt", SHA256: reference.SHA256}); err == nil {
			t.Fatal("ancestor symlink accepted")
		}
	})
	t.Run("symlink repository root", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "root-link")
		if err := os.Symlink(root, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if err := verifyEvidenceFile(link, reference); err == nil {
			t.Fatal("symlink repository root accepted")
		}
	})
	t.Run("symlink repository root parent", func(t *testing.T) {
		parent := t.TempDir()
		link := filepath.Join(parent, "root-parent-link")
		if err := os.Symlink(filepath.Dir(root), link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		redirected := filepath.Join(link, filepath.Base(root))
		if err := verifyEvidenceFile(redirected, reference); err == nil || !strings.Contains(err.Error(), "path") {
			t.Fatalf("symlinked root parent accepted: %v", err)
		}
	})
}

func TestRepositoryEvidenceRejectsPathRedirectAfterPathCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pathname replacement may require elevated symlink privileges on Windows")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "evidence.txt")
	target := filepath.Join(directory, "target.txt")
	content := []byte("same trusted content")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	reference := EvidenceReference{Path: "evidence.txt", SHA256: fmt.Sprintf("%x", sha256.Sum256(content))}
	evidenceRoot, err := openEvidenceRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer evidenceRoot.Close()

	var replacementErr error
	err = verifyEvidenceFromRootWithHook(evidenceRoot, reference, func() {
		if removeErr := os.Remove(path); removeErr != nil {
			replacementErr = removeErr
			return
		}
		replacementErr = os.Symlink(target, path)
	})
	if replacementErr != nil {
		t.Skipf("pathname replacement unavailable: %v", replacementErr)
	}
	if err == nil || !strings.Contains(err.Error(), "changed during verification") {
		t.Fatalf("redirected evidence path result = %v; want a path-change error", err)
	}
}

func TestRepositoryEvidencePathLexicalSafety(t *testing.T) {
	valid := []string{"README.md", ".github/workflows/ci.yml", "docs/a+b_1.0.md"}
	invalid := []string{"", ".", "../README.md", "docs/../README.md", "/README.md", `docs\README.md`, "docs//README.md", "docs/./README.md", "docs/a b.md"}
	for _, value := range valid {
		if !validRepositoryEvidencePath(value) {
			t.Errorf("valid path %q rejected", value)
		}
	}
	for _, value := range invalid {
		if validRepositoryEvidencePath(value) {
			t.Errorf("unsafe path %q accepted", value)
		}
	}
}

func mutateEmbeddedDocument(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(embedded, &document); err != nil {
		t.Fatalf("decode embedded scorecard fixture: %v", err)
	}
	mutate(document)
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode mutated scorecard fixture: %v", err)
	}
	return data
}

func readinessRepositoryFile(t *testing.T, elements ...string) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	return filepath.Join(append([]string{root}, elements...)...)
}
