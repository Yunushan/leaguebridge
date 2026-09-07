package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/readiness"
)

type readinessCategoryResult struct {
	ID          string                   `json:"id"`
	Name        string                   `json:"name"`
	Score       int                      `json:"score"`
	Weight      int                      `json:"weight"`
	Subcriteria []readiness.Subcriterion `json:"subcriteria"`
}

func (a *App) runReadiness(ctx context.Context, args []string) int {
	if len(args) > 0 && args[0] == "verify-release" {
		return a.runReadinessRelease(ctx, args[1:])
	}
	set := a.flagSet("readiness")
	asJSON := set.Bool("json", false, "emit JSON")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("readiness", *asJSON, ExitUsage, "%v", err)
	}
	scorecard, err := readiness.Embedded()
	if err != nil {
		return a.commandError("readiness", *asJSON, ExitInternal, "load scorecard: %v", err)
	}
	engineeringEvaluation := scorecard.EvaluateEngineering(a.RepositoryEvidenceVerification)
	remoteHandoffs := scorecard.EvaluateRemoteHandoffs()
	categories := make([]readinessCategoryResult, 0, len(scorecard.Engineering))
	for _, category := range scorecard.Engineering {
		categories = append(categories, readinessCategoryResult{
			ID:          category.ID,
			Name:        category.Name,
			Score:       engineeringEvaluation.CategoryScore(category.ID),
			Weight:      category.Weight,
			Subcriteria: category.Subcriteria,
		})
	}
	if *asJSON {
		return a.writeJSON("readiness", struct {
			SchemaVersion                        int                          `json:"schema_version"`
			AssessedAt                           time.Time                    `json:"assessed_at"`
			ExpiresAt                            time.Time                    `json:"expires_at"`
			EngineeringScore                     int                          `json:"engineering_score"`
			RepositoryEvidenceVerified           bool                         `json:"repository_evidence_verified"`
			RepositoryEvidenceVerificationReason string                       `json:"repository_evidence_verification_reason"`
			Engineering                          []readinessCategoryResult    `json:"engineering"`
			LocalGameplay                        readiness.Outcome            `json:"local_gameplay"`
			RemoteHandoffs                       []readiness.RemoteEvaluation `json:"remote_handoffs"`
		}{scorecard.SchemaVersion, scorecard.AssessedAt, scorecard.ExpiresAt, engineeringEvaluation.Score, engineeringEvaluation.RepositoryEvidenceVerified, engineeringEvaluation.VerificationReason, categories, scorecard.LocalGameplay, remoteHandoffs})
	}
	fmt.Fprintf(a.Stdout, "Engineering readiness: %d/100\n", engineeringEvaluation.Score)
	verificationState := "UNVERIFIED"
	if engineeringEvaluation.RepositoryEvidenceVerified {
		verificationState = "VERIFIED"
	}
	fmt.Fprintf(a.Stdout, "Repository evidence: %s — %s\n\n", verificationState, engineeringEvaluation.VerificationReason)
	for _, category := range scorecard.Engineering {
		fmt.Fprintf(a.Stdout, "%-34s %2d/%2d\n", category.Name, engineeringEvaluation.CategoryScore(category.ID), category.Weight)
	}
	fmt.Fprintf(a.Stdout, "\nLocal Linux/BSD gameplay: %d/100 — %s\n%s\n", scorecard.LocalGameplay.Score, strings.ToUpper(scorecard.LocalGameplay.State), scorecard.LocalGameplay.Reason)
	fmt.Fprintln(a.Stdout, "\nRemote physical-host handoffs (independent; no aggregate support score):")
	for _, remote := range remoteHandoffs {
		fmt.Fprintf(a.Stdout, "\n%s: %d/100 — %s\n%s\n", remote.RouteID, remote.Score, strings.ToUpper(remote.State), remote.Reason)
		for _, platform := range remote.Platforms {
			fmt.Fprintf(a.Stdout, "%-18s %3d/100 — %s\n", platform.Platform+"/"+platform.Architecture, platform.Score, strings.ToUpper(platform.State))
			for _, gate := range platform.Gates {
				status := "pending"
				if gate.Passed {
					status = "passed"
				}
				fmt.Fprintf(a.Stdout, "  %-22s %2d/25 — %s\n", gate.ID, gate.Weight*boolInt(gate.Passed), strings.ToUpper(status))
			}
		}
	}
	return ExitOK
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
