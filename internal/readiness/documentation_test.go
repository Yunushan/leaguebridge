package readiness

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestREADMEUsesCanonicalBinaryChecksumMarkers(t *testing.T) {
	data, err := os.ReadFile(readinessRepositoryFile(t, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(data)
	for _, required := range []string{
		`awk -v name="*./$artifact"`,
	} {
		if !strings.Contains(readme, required) {
			t.Errorf("README checksum verification is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		`awk -v name="./$artifact"`,
	} {
		if strings.Contains(readme, forbidden) {
			t.Errorf("README checksum verification retains text-mode form %q", forbidden)
		}
	}
}

func TestPublishedReadinessSummaryMatchesDerivedScorecard(t *testing.T) {
	scorecard := validTestScorecard(t)
	remoteHandoffs := scorecard.EvaluateRemoteHandoffs()
	if len(remoteHandoffs) != 2 {
		t.Fatalf("remote handoff count = %d, want 2", len(remoteHandoffs))
	}
	readmeData, err := os.ReadFile(readinessRepositoryFile(t, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(readmeData)
	for _, want := range []string{
		fmt.Sprintf("engineering%%20readiness-%d%%2F100", scorecard.EngineeringScore()),
		fmt.Sprintf("| LeagueBridge engineering | **%d/100 after build-time repository verification**", scorecard.EngineeringScore()),
		fmt.Sprintf("| Local League on Linux/BSD | **%d/100 — %s**", scorecard.LocalGameplay.Score, scorecard.LocalGameplay.State),
		fmt.Sprintf("| Physical Windows remote handoff | **%d/100 — %s**", remoteHandoffs[0].Score, remoteHandoffs[0].State),
		fmt.Sprintf("| Physical macOS remote handoff | **%d/100 — %s**", remoteHandoffs[1].Score, remoteHandoffs[1].State),
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("README missing derived summary %q", want)
		}
	}
	if strings.Contains(readme, "83/100") || strings.Contains(readme, "83%2F100") {
		t.Fatal("README retains the superseded 83-point claim")
	}

	documentData, err := os.ReadFile(readinessRepositoryFile(t, "docs", "READINESS.md"))
	if err != nil {
		t.Fatal(err)
	}
	document := string(documentData)
	for _, want := range []string{
		fmt.Sprintf("The current verified source tree derives %d points", scorecard.EngineeringScore()),
		fmt.Sprintf("for **%d/100**", scorecard.EngineeringScore()),
		"development or ad hoc build has no value and reports **0/100",
		"Both routes and all five platforms per route currently score **0/100 —",
		"`physical-windows-remote`",
		"`physical-macos-remote`",
		"gamepad hosting is unavailable",
		"schema-v1 manual record",
		"rejects every nonempty",
		"`evidence_sets` array for both routes",
	} {
		if !strings.Contains(document, want) {
			t.Errorf("readiness documentation missing %q", want)
		}
	}

	position := -1
	for _, category := range scorecard.Engineering {
		for _, criterion := range category.Subcriteria {
			index := strings.Index(document, "`"+criterion.ID+"`")
			if index < 0 {
				t.Errorf("readiness documentation omits %q", criterion.ID)
				continue
			}
			if index <= position {
				t.Errorf("readiness documentation reorders %q", criterion.ID)
			}
			position = index
		}
	}
}

func TestScorecardStoresNoDerivedEarnedOrPassedFields(t *testing.T) {
	for _, relative := range []string{"readiness/scorecard.json", "internal/readiness/data/scorecard.json"} {
		data, err := os.ReadFile(readinessRepositoryFile(t, strings.Split(relative, "/")...))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, forbidden := range []string{`"earned"`, `"passed"`, `"remote_handoff"`, `"remote_handoffs":{"score"`} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s contains mutable derived field %s", relative, forbidden)
			}
		}
	}
}
