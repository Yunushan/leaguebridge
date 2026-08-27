package app

import (
	"fmt"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/compat"
	"github.com/Yunushan/leaguebridge/internal/readiness"
)

type statusData struct {
	ManifestID                           string                       `json:"manifest_id"`
	EvidenceAsOf                         string                       `json:"evidence_as_of"`
	Freshness                            compat.Freshness             `json:"freshness"`
	EngineeringScore                     int                          `json:"engineering_score"`
	RepositoryEvidenceVerified           bool                         `json:"repository_evidence_verified"`
	RepositoryEvidenceVerificationReason string                       `json:"repository_evidence_verification_reason"`
	LocalGameplay                        readiness.Outcome            `json:"local_gameplay"`
	RemoteHandoffs                       []readiness.RemoteEvaluation `json:"remote_handoffs"`
	Backends                             []compat.Backend             `json:"backends"`
}

func (a *App) runStatus(args []string) int {
	set := a.flagSet("status")
	asJSON := set.Bool("json", false, "emit JSON")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("status", *asJSON, ExitUsage, "%v", err)
	}
	manifest, err := compat.Embedded()
	if err != nil {
		return a.commandError("status", *asJSON, ExitInternal, "load embedded compatibility authority: %v", err)
	}
	freshness, err := manifest.FreshnessAt(a.now())
	if err != nil {
		return a.commandError("status", *asJSON, ExitInternal, "verify compatibility freshness: %v", err)
	}
	scorecard, err := readiness.Embedded()
	if err != nil {
		return a.commandError("status", *asJSON, ExitInternal, "load readiness scorecard: %v", err)
	}
	engineering := scorecard.EvaluateEngineering(a.RepositoryEvidenceVerification)
	data := statusData{
		ManifestID:                           manifest.ManifestID,
		EvidenceAsOf:                         manifest.AsOf,
		Freshness:                            freshness,
		EngineeringScore:                     engineering.Score,
		RepositoryEvidenceVerified:           engineering.RepositoryEvidenceVerified,
		RepositoryEvidenceVerificationReason: engineering.VerificationReason,
		LocalGameplay:                        scorecard.LocalGameplay,
		RemoteHandoffs:                       scorecard.EvaluateRemoteHandoffs(),
		Backends:                             manifest.Backends,
	}
	if *asJSON {
		return a.writeJSON("status", data)
	}
	fmt.Fprintf(a.Stdout, "Evidence: %s (as of %s, age %d/%d days)\n", strings.ToUpper(string(freshness.State)), manifest.AsOf, freshness.AgeDays, freshness.MaxAgeDays)
	fmt.Fprintf(a.Stdout, "Engineering readiness: %d/100\n", data.EngineeringScore)
	verificationState := "UNVERIFIED"
	if data.RepositoryEvidenceVerified {
		verificationState = "VERIFIED"
	}
	fmt.Fprintf(a.Stdout, "Repository evidence: %s — %s\n", verificationState, data.RepositoryEvidenceVerificationReason)
	fmt.Fprintf(a.Stdout, "Local Linux/BSD gameplay: %d/100 — %s\n", data.LocalGameplay.Score, strings.ToUpper(data.LocalGameplay.State))
	fmt.Fprintln(a.Stdout, "Remote physical-host handoffs (independent; no aggregate support score):")
	for _, remote := range data.RemoteHandoffs {
		fmt.Fprintf(a.Stdout, "  %s: %d/100 — %s\n", remote.RouteID, remote.Score, strings.ToUpper(remote.State))
		fmt.Fprintf(a.Stdout, "    %s\n", remote.Reason)
		for _, platform := range remote.Platforms {
			fmt.Fprintf(a.Stdout, "    %-18s %3d/100 — %s\n", platform.Platform+"/"+platform.Architecture, platform.Score, strings.ToUpper(platform.State))
		}
	}
	fmt.Fprintln(a.Stdout)
	fmt.Fprintln(a.Stdout, "Backend                         State          Launch   Reason")
	for _, backend := range manifest.Backends {
		fmt.Fprintf(a.Stdout, "%-31s %-14s %-8s %s\n", backend.ID, backend.State, backend.LaunchVerdict, backend.ReasonCode)
	}
	fmt.Fprintln(a.Stdout, "\nNo flag can turn a denied local backend into an allowed one.")
	return ExitOK
}

func (a *App) runAssess(args []string) int {
	set := a.flagSet("assess")
	backend := set.String("backend", "", "backend ID")
	platform := set.String("platform", a.GOOS, "host platform")
	architecture := set.String("arch", a.GOARCH, "host architecture")
	asJSON := set.Bool("json", false, "emit JSON")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("assess", *asJSON, ExitUsage, "%v", err)
	}
	if *backend == "" {
		return a.commandError("assess", *asJSON, ExitUsage, "--backend is required")
	}
	policy, err := compat.DefaultPolicy()
	if err != nil {
		return a.commandError("assess", *asJSON, ExitInternal, "load policy: %v", err)
	}
	verdict := policy.EvaluateAt(compat.LaunchRequest{
		BackendID:        compat.BackendID(*backend),
		HostPlatform:     normalizeCompatPlatform(*platform),
		HostArchitecture: compat.Architecture(*architecture),
	}, a.now())
	if *asJSON {
		if code := a.writeJSON("assess", verdict); code != ExitOK {
			return code
		}
	} else {
		fmt.Fprintf(a.Stdout, "%s: %s\n%s\n", strings.ToUpper(string(verdict.Decision)), verdict.Code, verdict.Message)
		for _, source := range verdict.EvidenceURLs {
			fmt.Fprintf(a.Stdout, "- %s\n", source)
		}
	}
	if !verdict.IsAllowed() {
		return ExitBlocked
	}
	return ExitOK
}

func normalizeCompatPlatform(value string) compat.Platform {
	switch strings.ToLower(value) {
	case "dragonfly", "dragonflybsd":
		return compat.PlatformDragonFlyBSD
	default:
		return compat.Platform(strings.ToLower(value))
	}
}
