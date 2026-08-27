package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/Yunushan/leaguebridge/internal/compat"
	"github.com/Yunushan/leaguebridge/internal/diagnostics"
	"github.com/Yunushan/leaguebridge/internal/probe"
	"github.com/Yunushan/leaguebridge/internal/readiness"
	"github.com/Yunushan/leaguebridge/internal/version"
)

func (a *App) runBundle(ctx context.Context, args []string) int {
	set := a.flagSet("bundle")
	profileName := set.String("profile", defaultProfileName(a.GOOS), "client, windows-host, or macos-host")
	preview := set.Bool("preview", false, "print sanitized report without writing")
	output := set.String("output", "", "write support bundle zip")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("bundle", false, ExitUsage, "%v", err)
	}
	if *preview && *output != "" {
		return a.commandError("bundle", false, ExitUsage, "--preview and --output are mutually exclusive")
	}
	profile, err := parseProfile(*profileName)
	if err != nil {
		return a.commandError("bundle", false, ExitUsage, "%v", err)
	}
	probeReport := a.prober().Run(ctx, profile)
	report, err := a.diagnosticReport(probeReport)
	if err != nil {
		return a.commandError("bundle", false, ExitInternal, "build diagnostic report: %v", err)
	}
	if *output == "" {
		data, err := diagnostics.Preview(report)
		if err != nil {
			return a.commandError("bundle", false, ExitInternal, "preview diagnostic report: %v", err)
		}
		if _, err := a.Stdout.Write(data); err != nil {
			return a.commandError("bundle", false, ExitInternal, "write preview: %v", err)
		}
		return ExitOK
	}
	if err := diagnostics.WriteBundle(*output, report); err != nil {
		if errors.Is(err, diagnostics.ErrBundleExists) {
			return a.commandError("bundle", false, ExitUsage, "refusing to overwrite existing support bundle")
		}
		return a.commandError("bundle", false, ExitInternal, "write support bundle: %v", err)
	}
	fmt.Fprintf(a.Stdout, "Wrote local support bundle to %s. Inspect it and its filesystem access controls before sharing.\n", *output)
	return ExitOK
}

func (a *App) diagnosticReport(report probe.Report) (diagnostics.Report, error) {
	checks := make([]diagnostics.Check, 0, len(report.Checks)+4)
	for _, check := range report.Checks {
		checks = append(checks, diagnostics.Check{
			ID:          check.ID,
			Status:      diagnosticStatus(check.Status),
			Summary:     check.Summary,
			Remediation: check.Guidance,
		})
	}
	manifest, err := compat.Embedded()
	if err != nil {
		return diagnostics.Report{}, err
	}
	freshness, err := manifest.FreshnessAt(a.now())
	if err != nil {
		return diagnostics.Report{}, err
	}
	freshnessStatus := diagnostics.StatusPass
	if freshness.State != compat.FreshnessFresh {
		freshnessStatus = diagnostics.StatusFail
	}
	checks = append(checks,
		diagnostics.Check{
			ID:          "manifest.freshness",
			Status:      freshnessStatus,
			Summary:     fmt.Sprintf("Embedded compatibility evidence is %s.", freshness.State),
			Detail:      fmt.Sprintf("Evidence age is %d days with a %d-day limit.", freshness.AgeDays, freshness.MaxAgeDays),
			Remediation: "Install a current LeagueBridge release after evidence review.",
		},
		diagnostics.Check{
			ID:          "compat.gameplay-local",
			Status:      diagnostics.StatusFail,
			Summary:     "Local League gameplay on Linux and BSD is blocked by current Riot Vanguard requirements.",
			Remediation: "Use supported physical Windows directly or an explicitly acknowledged remote handoff; do not use Wine, a VM, copied DLLs, or a bypass.",
		},
		diagnostics.Check{
			ID:          "compat.remote-handoff",
			Status:      diagnostics.StatusInfo,
			Summary:     "Physical Windows and experimental macOS remote streaming are handoffs, not local compatibility.",
			Remediation: "Validate the native host, Moonlight, and Sunshine manually; stop if Riot software reports an error.",
		},
	)
	scorecard, err := readiness.Embedded()
	if err != nil {
		return diagnostics.Report{}, err
	}
	engineering := scorecard.EvaluateEngineering(a.RepositoryEvidenceVerification)
	readinessStatus := diagnostics.StatusInfo
	readinessRemediation := ""
	if !engineering.RepositoryEvidenceVerified {
		readinessStatus = diagnostics.StatusFail
		readinessRemediation = "Install a release whose build-time repository evidence verification matches its embedded scorecard."
	}
	checks = append(checks, diagnostics.Check{
		ID:          "readiness.engineering",
		Status:      readinessStatus,
		Summary:     fmt.Sprintf("Repository engineering readiness is %d of 100.", engineering.Score),
		Detail:      engineering.VerificationReason,
		Remediation: readinessRemediation,
	})
	info := version.Current()
	return diagnostics.NewReport(info.Version, checks...), nil
}

func diagnosticStatus(status probe.Status) diagnostics.Status {
	switch status {
	case probe.StatusPass:
		return diagnostics.StatusPass
	case probe.StatusWarn:
		return diagnostics.StatusWarn
	case probe.StatusFail:
		return diagnostics.StatusFail
	default:
		return diagnostics.StatusInfo
	}
}
