package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/productionassessment"
	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
	"github.com/Yunushan/leaguebridge/internal/target"
)

func TestProductionAssessmentRejectsCallerClaimsBeforeVerification(t *testing.T) {
	base := []string{"--version", "v0.1.0", "--release-dir", "downloads"}
	for _, extra := range [][]string{
		{"--score", "100"}, {"--passed", "true"}, {"--commit", strings.Repeat("a", 40)},
		{"--policy", "mine.json"}, {"--trust-key", "mine.pub"}, {"--observation", "prior.json"}, {"extra"},
	} {
		t.Run(strings.Join(extra, " "), func(t *testing.T) {
			var output, diagnostic bytes.Buffer
			a := New(strings.NewReader(""), &output, &diagnostic)
			called := false
			code := a.assessProduction(context.Background(), append(append([]string(nil), base...), extra...),
				func(context.Context, releaseassessment.Request) (productionassessment.Result, error) {
					called = true
					return productionassessment.Result{}, nil
				})
			if code != ExitUsage || called || strings.Contains(output.String(), "/100") {
				t.Fatalf("untrusted claim reached verifier or score output: code=%d called=%v output=%q", code, called, output.String())
			}
		})
	}
}

func TestProductionAssessmentFailureDoesNotEmitScore(t *testing.T) {
	var output, diagnostic bytes.Buffer
	a := New(strings.NewReader(""), &output, &diagnostic)
	code := a.assessProduction(context.Background(), []string{"--version", "v0.1.0", "--release-dir", "downloads", "--json"},
		func(context.Context, releaseassessment.Request) (productionassessment.Result, error) {
			return productionassessment.Result{}, errors.New("live release verification failed")
		})
	if code != ExitBlocked {
		t.Fatalf("failed assessment returned %d", code)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if data, ok := envelope["data"]; ok && string(data) != "null" {
		t.Fatalf("failure emitted score-bearing data: %s", data)
	}
	if strings.Contains(output.String(), "83") || strings.Contains(output.String(), "100") {
		t.Fatalf("failed authentication emitted a score: %s", output.String())
	}
}

func TestProductionAssessmentUsesFixedLiveRequestInventory(t *testing.T) {
	var output, diagnostic bytes.Buffer
	a := New(strings.NewReader(""), &output, &diagnostic)
	ctx := context.WithValue(context.Background(), struct{ name string }{"request"}, "live")
	observed := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	code := a.assessProduction(ctx, []string{"--version", "v0.1.0", "--release-dir", "actual-assets", "--gh", "trusted-gh", "--json"},
		func(received context.Context, input releaseassessment.Request) (productionassessment.Result, error) {
			if received != ctx || input.Version != "v0.1.0" || input.ReleaseDir != "actual-assets" || input.GHPath != "trusted-gh" || input.RaceVetSubject != "ci-attestation/race-vet-linux.json" {
				t.Fatalf("unexpected release selection: %+v", input)
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
			return productionassessment.Result{SchemaVersion: 1, Score: 83, ReleaseScore: 83,
				Release: productionassessment.Release{Version: input.Version}, ObservedAt: observed}, nil
		})
	if code != ExitOK {
		t.Fatalf("assessment returned %d: %s", code, diagnostic.String())
	}
	var envelope struct {
		Command string                      `json:"command"`
		Data    productionassessment.Result `json:"data"`
	}
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Command != "readiness verify-production" || envelope.Data.Score != 83 || envelope.Data.Release.Version != "v0.1.0" || !envelope.Data.ObservedAt.Equal(observed) {
		t.Fatalf("live result lost its identity or score: %s", output.String())
	}
}
