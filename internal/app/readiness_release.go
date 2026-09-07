package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
	"github.com/Yunushan/leaguebridge/internal/releaseversion"
	"github.com/Yunushan/leaguebridge/internal/target"
)

type releaseAssessor func(context.Context, releaseassessment.Request) (releaseassessment.Result, error)

func (a *App) runReadinessRelease(ctx context.Context, args []string) int {
	return a.assessRelease(ctx, args, releaseassessment.Verify)
}

// assessRelease keeps the verifier dependency private to application tests.
// No score, stored observation, signature result, or policy is a CLI input.
func (a *App) assessRelease(ctx context.Context, args []string, verify releaseAssessor) int {
	const command = "readiness verify-release"
	set := a.flagSet(command)
	version := set.String("version", "", "published release tag to assess")
	directory := set.String("release-dir", "", "directory containing the ten downloaded release files")
	gh := set.String("gh", "gh", "trusted GitHub CLI executable")
	asJSON := set.Bool("json", false, "emit JSON")
	if err := parseFlags(set, args); err != nil {
		return a.commandError(command, *asJSON, ExitUsage, "%v", err)
	}
	if !releaseversion.Valid(*version) || strings.TrimSpace(*directory) == "" || strings.TrimSpace(*gh) == "" {
		return a.commandError(command, *asJSON, ExitUsage, "supply --version TAG, --release-dir DIR, and a trusted --gh executable; run from the downloaded CI evidence directory")
	}
	input := releaseassessment.Request{
		GHPath: *gh, Version: *version, ReleaseDir: *directory,
		RaceVetSubject: "ci-attestation/race-vet-linux.json",
	}
	for _, candidate := range target.Ordered() {
		input.CrossBuildSubjects = append(input.CrossBuildSubjects,
			"ci-attestation/cross-build-"+candidate.GOOS+"-"+candidate.GOARCH+".json")
	}
	result, err := verify(ctx, input)
	if err != nil {
		// The live verifier sanitizes external diagnostics. Keep its failure out
		// of the score channel and do not fall back to an embedded baseline.
		return a.commandError(command, *asJSON, ExitBlocked, "release assessment failed: %v", err)
	}
	if *asJSON {
		return a.writeJSON(command, result)
	}
	_, err = fmt.Fprintf(a.Stdout,
		"Release engineering readiness: %d/100\nRelease: %s\nSource: %s\nRepository criteria: %d/100\nVerified CI and publication criteria: %d/100\nObserved at: %s\nRelease scorecard expires: %s\n\nThis is a live assessment of the named release. Re-run it to assess later state.\nLocal Linux/BSD gameplay remains blocked; physical remote gameplay remains unvalidated.\nPhysical testing, vendor authorization, independent audit, native integration, and production native packages require their own evidence.\n",
		result.Score, result.Version, result.Commit, result.RepositoryScore,
		result.Score-result.RepositoryScore, result.ObservedAt.UTC().Format(time.RFC3339Nano),
		result.ScorecardExpiresAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return a.commandError(command, false, ExitInternal, "write release assessment failed")
	}
	return ExitOK
}
