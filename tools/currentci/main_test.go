package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/currentci"
)

func arguments() []string {
	result := []string{"-race-vet-subject", "ci-attestation/race-vet-linux.json"}
	for _, cell := range []string{"linux-amd64", "linux-arm64", "freebsd-amd64", "freebsd-arm64", "openbsd-amd64", "openbsd-arm64", "netbsd-amd64", "netbsd-arm64", "dragonfly-amd64"} {
		result = append(result, "-cross-build-subject", "ci-attestation/cross-build-"+cell+".json")
	}
	return result
}

func TestCLIRejectsIncompleteOrCallerSelectedIdentitiesBeforeVerification(t *testing.T) {
	cases := map[string][]string{
		"missing paths":              nil,
		"missing cross-build target": arguments()[:len(arguments())-2],
		"too many paths":             append(arguments(), "-cross-build-subject", "extra.json"),
		"empty race subject":         append(arguments(), "-race-vet-subject", ""),
		"empty cross-build subject":  append(arguments()[:len(arguments())-2], "-cross-build-subject", " "),
		"empty executable":           append(arguments(), "-gh", " "),
		"positional argument":        append(arguments(), "unexpected"),
		"caller commit":              append(arguments(), "-commit", strings.Repeat("a", 40)),
		"caller run":                 append(arguments(), "-run-id", "1"),
		"caller repository":          append(arguments(), "-repository", "other/repo"),
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), args, &stdout, &stderr, func(context.Context, currentci.VerifyRequest) (currentci.Observation, error) {
				t.Fatal("invalid command reached verifier")
				return currentci.Observation{}, nil
			})
			if code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestCLIReportsOnlyTheVerifiedObservation(t *testing.T) {
	observed := time.Date(2026, 9, 7, 16, 0, 0, 123, time.UTC)
	value := currentci.Observation{Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), RunID: 123, RunAttempt: 2, ObservedAt: observed}
	ctx := context.WithValue(context.Background(), struct{}{}, "preserved")
	var stdout, stderr bytes.Buffer
	code := run(ctx, append(arguments(), "-gh", "/trusted/gh"), &stdout, &stderr, func(gotCtx context.Context, input currentci.VerifyRequest) (currentci.Observation, error) {
		if gotCtx != ctx || input.GHPath != "/trusted/gh" || input.RaceVetSubject != "ci-attestation/race-vet-linux.json" || len(input.CrossBuildSubjects) != 9 || input.CrossBuildSubjects[8] != "ci-attestation/cross-build-dragonfly-amd64.json" {
			t.Fatalf("wrong verification inputs: %+v", input)
		}
		return value, nil
	})
	want := fmt.Sprintf("verified current main CI evidence commit=%s tree=%s run=123 attempt=2 observed_at=2026-09-07T16:00:00.000000123Z\n", value.Commit, value.Tree)
	if code != 0 || stderr.Len() != 0 || stdout.String() != want {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestCLIFailureCannotPrintAnObservation(t *testing.T) {
	for _, failure := range []error{errors.New("main changed during verification"), context.Canceled} {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), arguments(), &stdout, &stderr, func(_ context.Context, input currentci.VerifyRequest) (currentci.Observation, error) {
			if input.GHPath != "gh" {
				t.Fatalf("default executable=%q", input.GHPath)
			}
			return currentci.Observation{Commit: "must-not-be-printed"}, failure
		})
		if code != 1 || stdout.Len() != 0 || stderr.String() != "currentci: "+failure.Error()+"\n" {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	}
}

func TestCLIHelpDescribesScopeWithoutVerification(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-h"}, &stdout, &stderr, func(context.Context, currentci.VerifyRequest) (currentci.Observation, error) {
		t.Fatal("help reached verifier")
		return currentci.Observation{}, nil
	})
	if code != 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "does not award readiness points or prove publication") || !strings.Contains(stderr.String(), "binary paths resolve") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
