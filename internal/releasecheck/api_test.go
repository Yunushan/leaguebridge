package releasecheck

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/readiness"
)

func TestCheckRequiresExplicitExpectedScorecardAndSourceIdentity(t *testing.T) {
	valid := CheckRequest{
		Dir: filepath.Join(t.TempDir(), "absent"), Version: testVersion,
		SourceDateEpoch: testEpoch, Commit: testCommit, Tree: testTree,
		BuilderGoVersion: productionBuilderGoVersion, ExpectedScorecard: readiness.EmbeddedJSON(),
	}
	for _, test := range []struct {
		name string
		edit func(*CheckRequest)
		want string
	}{
		{"missing scorecard", func(r *CheckRequest) { r.ExpectedScorecard = nil }, "scorecard is empty"},
		{"oversized scorecard", func(r *CheckRequest) { r.ExpectedScorecard = make([]byte, readiness.MaximumScorecardSize+1) }, "exceeds its bound"},
		{"invalid scorecard JSON", func(r *CheckRequest) { r.ExpectedScorecard = []byte("{") }, "JSON object"},
		{"scorecard scalar", func(r *CheckRequest) { r.ExpectedScorecard = []byte("null") }, "JSON object"},
		{"scorecard array", func(r *CheckRequest) { r.ExpectedScorecard = []byte("[]") }, "JSON object"},
		{"missing commit", func(r *CheckRequest) { r.Commit = "" }, "commit must"},
		{"missing tree", func(r *CheckRequest) { r.Tree = "" }, "tree must"},
		{"negative epoch", func(r *CheckRequest) { r.SourceDateEpoch = -1 }, "non-negative decimal"},
		{"unsupported epoch", func(r *CheckRequest) { r.SourceDateEpoch = 0 }, "timestamp range"},
		{"unsupported builder", func(r *CheckRequest) { r.BuilderGoVersion = "go1.99.0" }, "production releases require"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.edit(&request)
			if err := Check(request); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Check() = %v; want %q before opening any files", err, test.want)
			}
		})
	}
}

func TestCheckBindsSelectedReleaseScorecardRatherThanAssessorCard(t *testing.T) {
	// Simulate a release built from an earlier source-card revision. The newline
	// preserves every schema field, weight and gate while changing the exact
	// authenticated bytes and their build-time marker.
	assessorCard := readiness.EmbeddedJSON()
	releaseCard := append(append([]byte(nil), assessorCard...), '\n')
	dir, commit, tree := makeValidReleaseFixtureWithScorecard(t, releaseCard)
	request := CheckRequest{
		Dir: dir, Version: testVersion, SourceDateEpoch: testEpoch,
		Commit: commit, Tree: tree, BuilderGoVersion: testBuilderGoVersion,
		ExpectedScorecard: releaseCard,
	}
	check := Check
	if testBuilderGoVersion != productionBuilderGoVersion {
		// The minimum-Go suite still exercises every archive and card check with
		// native fixtures, while confirming the public API rejects that builder.
		if err := Check(request); err == nil || !strings.Contains(err.Error(), "production releases require") {
			t.Fatalf("Check(minimum-Go archive) = %v; want production-builder rejection", err)
		}
		check = func(r CheckRequest) error {
			return checkRelease(r.Dir, r.Version, r.SourceDateEpoch, r.Commit, r.Tree, r.BuilderGoVersion, r.ExpectedScorecard)
		}
	}
	if err := check(request); err != nil {
		t.Fatalf("selected release card failed: %v", err)
	}
	for _, test := range []struct {
		name string
		edit func(*CheckRequest)
		want string
	}{
		{"assessor card cannot replace release card", func(r *CheckRequest) { r.ExpectedScorecard = assessorCard }, "repository evidence verification occurs 0 times"},
		{"different card", func(r *CheckRequest) { r.ExpectedScorecard = []byte("{\"schema_version\":3}\n") }, "embedded readiness scorecard occurs 0 times"},
		{"different source commit", func(r *CheckRequest) { r.Commit = testCommit }, "structured Go build ID"},
		{"different source tree", func(r *CheckRequest) { r.Tree = testTree }, "structured Go build ID"},
		{"different source epoch", func(r *CheckRequest) { r.SourceDateEpoch++ }, "timestamp"},
	} {
		t.Run(test.name, func(t *testing.T) {
			mismatch := request
			test.edit(&mismatch)
			if err := check(mismatch); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("mismatched release = %v; want %q", err, test.want)
			}
		})
	}
	artifacts, err := expectedArtifacts(testVersion)
	if err != nil {
		t.Fatal(err)
	}
	item := artifacts[0]
	payload, err := readTarGzip(filepath.Join(dir, item.name), item.binaryName, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	// Correct selected JSON with a marker for the assessor's newer card is also
	// rejected, independently of the archive/card and source mismatch cases.
	tampered := bytes.Replace(payload.binary, []byte(scorecardVerification(releaseCard)), []byte(scorecardVerification(assessorCard)), 1)
	if bytes.Equal(tampered, payload.binary) {
		t.Fatal("fixture did not contain the selected scorecard marker")
	}
	if err := checkReleaseBinary(tampered, item, testVersion, testEpoch, commit, tree, testBuilderGoVersion, releaseCard); err == nil || !strings.Contains(err.Error(), "repository evidence verification occurs 0 times") {
		t.Fatalf("mismatched selected-card marker = %v", err)
	}
}
