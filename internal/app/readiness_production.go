package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/productionassessment"
	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
	"github.com/Yunushan/leaguebridge/internal/releaseversion"
	"github.com/Yunushan/leaguebridge/internal/target"
)

type productionAssessor func(context.Context, releaseassessment.Request) (productionassessment.Result, error)

func (a *App) runReadinessProduction(ctx context.Context, args []string) int {
	return a.assessProduction(ctx, args, productionassessment.Verify)
}

// assessProduction keeps the live verifier dependency private to tests. The
// command accepts selectors and local release bytes, never a score or policy.
func (a *App) assessProduction(ctx context.Context, args []string, verify productionAssessor) int {
	const command = "readiness verify-production"
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
		return a.commandError(command, *asJSON, ExitBlocked, "production assessment failed: %v", err)
	}
	if *asJSON {
		return a.writeJSON(command, result)
	}
	if _, err := fmt.Fprintf(a.Stdout,
		"Production engineering readiness: %d/100\nRelease: %s\nSource: %s\nVerified repository and release criteria: %d/100\nObserved at: %s\nEvidence expires at: %s\n\nExternal criteria still requiring authenticated evidence:\n",
		result.Score, result.Release.Version, result.Release.Commit, result.ReleaseScore,
		result.ObservedAt.UTC().Format(time.RFC3339Nano), result.EvidenceExpiresAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return a.commandError(command, false, ExitInternal, "write production assessment failed")
	}
	for _, item := range result.Criteria {
		if item.Status != "missing_evidence" {
			continue
		}
		if _, err := fmt.Fprintf(a.Stdout, "  %s: %d/%d — %s\n", item.ID, item.Points, item.Weight, strings.Join(item.MissingEvidence, "; ")); err != nil {
			return a.commandError(command, false, ExitInternal, "write production assessment failed")
		}
	}
	if _, err := fmt.Fprint(a.Stdout, "\nThis is a live observation of the named release. Local Linux/BSD gameplay and remote physical-host gameplay remain separate gates.\n"); err != nil {
		return a.commandError(command, false, ExitInternal, "write production assessment failed")
	}
	return ExitOK
}
