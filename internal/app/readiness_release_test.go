package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/readiness"
	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
	"github.com/Yunushan/leaguebridge/internal/target"
)

func TestReleaseAssessmentRejectsClaimInputsBeforeVerification(t *testing.T) {
	base := []string{"--version", "v0.1.0", "--release-dir", "downloads"}
	for _, extra := range [][]string{
		{"--score", "100"}, {"--passed", "true"}, {"--commit", strings.Repeat("a", 40)},
		{"--run-id", "1"}, {"--policy", "mine.json"}, {"--observation", "prior.json"}, {"extra"},
	} {
		t.Run(strings.Join(extra, " "), func(t *testing.T) {
			var output, diagnostic bytes.Buffer
			a := New(strings.NewReader(""), &output, &diagnostic)
			called := false
			code := a.assessRelease(context.Background(), append(append([]string(nil), base...), extra...),
				func(context.Context, releaseassessment.Request) (releaseassessment.Result, error) {
					called = true
					return releaseassessment.Result{}, nil
				})
			if code != ExitUsage || called || strings.Contains(output.String(), "engineering readiness:") {
				t.Fatalf("untrusted claim reached verifier or score output: code=%d called=%v output=%q", code, called, output.String())
			}
		})
	}
}

func TestReleaseAssessmentFailureNeverFallsBackToEmbeddedScore(t *testing.T) {
	var output, diagnostic bytes.Buffer
	a := New(strings.NewReader(""), &output, &diagnostic)
	a.RepositoryEvidenceVerification = readiness.ExpectedRepositoryEvidenceVerification()
	code := a.assessRelease(context.Background(), []string{"--version", "v0.1.0", "--release-dir", "downloads", "--json"},
		func(context.Context, releaseassessment.Request) (releaseassessment.Result, error) {
			return releaseassessment.Result{}, errors.New("signed published release evidence failed")
		})
	if code != ExitBlocked {
		t.Fatalf("failed attestation returned %d", code)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if data, ok := envelope["data"]; ok && string(data) != "null" {
		t.Fatalf("failure emitted score-bearing data: %s", data)
	}
	if strings.Contains(output.String(), "74") || strings.Contains(output.String(), "83") {
		t.Fatalf("failed authentication fell back to a score: %s", output.String())
	}
}

func TestReleaseAssessmentUsesLiveResultAndFixedEvidenceInventory(t *testing.T) {
	var output, diagnostic bytes.Buffer
	a := New(strings.NewReader(""), &output, &diagnostic)
	a.RepositoryEvidenceVerification = ""
	ctx := context.WithValue(context.Background(), struct{ name string }{"request"}, "live")
	observed := time.Date(2026, 9, 7, 18, 0, 0, 0, time.UTC)
	code := a.assessRelease(ctx, []string{"--version", "v0.1.0", "--release-dir", "actual-assets", "--gh", "trusted-gh", "--json"},
		func(received context.Context, input releaseassessment.Request) (releaseassessment.Result, error) {
			// CI subject identifiers use portable slash paths even on Windows;
			// the attestation protocol rejects native backslash separators.
			if received != ctx || input.Version != "v0.1.0" || input.ReleaseDir != "actual-assets" || input.GHPath != "trusted-gh" || input.RaceVetSubject != "ci-attestation/race-vet-linux.json" {
				t.Fatalf("unexpected verifier selection: %+v", input)
			}
			if len(input.CrossBuildSubjects) != len(target.Ordered()) {
				t.Fatalf("missing cross-build evidence: %+v", input.CrossBuildSubjects)
			}
			for index, candidate := range target.Ordered() {
				want := "ci-attestation/cross-build-" + candidate.GOOS + "-" + candidate.GOARCH + ".json"
				if input.CrossBuildSubjects[index] != want {
					t.Fatalf("cross-build input %d = %q, want %q", index, input.CrossBuildSubjects[index], want)
				}
			}
			return releaseassessment.Result{Version: "v0.1.0", Commit: strings.Repeat("a", 40), RepositoryScore: 74, Score: 83, ObservedAt: observed, ScorecardExpiresAt: observed.Add(time.Hour)}, nil
		})
	if code != ExitOK {
		t.Fatalf("verified result returned %d: %s", code, diagnostic.String())
	}
	var envelope struct {
		Command string                   `json:"command"`
		Data    releaseassessment.Result `json:"data"`
	}
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Command != "readiness verify-release" || envelope.Data.Score != 83 || envelope.Data.RepositoryScore != 74 || !envelope.Data.ObservedAt.Equal(observed) {
		t.Fatalf("live result lost its identity or score: %s", output.String())
	}
}

func TestReleaseAssessmentCancellationDoesNotProduceScore(t *testing.T) {
	var output, diagnostic bytes.Buffer
	a := New(strings.NewReader(""), &output, &diagnostic)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code := a.assessRelease(ctx, []string{"--version", "v0.1.0", "--release-dir", "downloads"},
		func(received context.Context, _ releaseassessment.Request) (releaseassessment.Result, error) {
			return releaseassessment.Result{}, received.Err()
		})
	if code != ExitBlocked || strings.Contains(output.String(), "/100") {
		t.Fatalf("cancellation emitted a score: code=%d output=%q", code, output.String())
	}
}
