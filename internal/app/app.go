// Package app implements the LeagueBridge command-line application.
package app

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/Yunushan/leaguebridge/internal/probe"
	"github.com/Yunushan/leaguebridge/internal/remote"
	"github.com/Yunushan/leaguebridge/internal/version"
)

const (
	ExitOK       = 0
	ExitUsage    = 2
	ExitBlocked  = 3
	ExitInternal = 4
)

type ProbeRunner interface {
	Run(ctx context.Context, profile probe.Profile) probe.Report
}

type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	Now          func() time.Time
	GOOS         string
	GOARCH       string
	NewProber    func() ProbeRunner
	RemoteEnv    remote.Environment
	RemoteRunner remote.Runner

	RepositoryEvidenceVerification string
}

func New(stdin io.Reader, stdout, stderr io.Writer) *App {
	return &App{
		Stdin:                          stdin,
		Stdout:                         stdout,
		Stderr:                         stderr,
		Now:                            time.Now,
		GOOS:                           runtime.GOOS,
		GOARCH:                         runtime.GOARCH,
		NewProber:                      func() ProbeRunner { return probe.NewSystem() },
		RemoteEnv:                      remote.RealEnvironment{},
		RemoteRunner:                   remote.ExecRunner{},
		RepositoryEvidenceVerification: version.RepositoryEvidenceVerification,
	}
}

func (a *App) Run(ctx context.Context, args []string) int {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(args) == 0 {
		a.printUsage(a.Stdout)
		return ExitUsage
	}
	switch args[0] {
	case "help", "-h", "--help":
		a.printUsage(a.Stdout)
		return ExitOK
	case "version":
		return a.runVersion(args[1:])
	case "status":
		return a.runStatus(args[1:])
	case "assess":
		return a.runAssess(args[1:])
	case "doctor":
		return a.runDoctor(ctx, args[1:])
	case "bundle":
		return a.runBundle(ctx, args[1:])
	case "config":
		return a.runConfig(args[1:])
	case "manifest":
		return a.runManifest(args[1:])
	case "readiness":
		return a.runReadiness(args[1:])
	case "evidence":
		return a.runEvidence(args[1:])
	case "remote":
		return a.runRemote(ctx, args[1:])
	default:
		fmt.Fprintf(a.Stderr, "leaguebridge: unknown command %q\n\n", args[0])
		a.printUsage(a.Stderr)
		return ExitUsage
	}
}

func (a *App) printUsage(w io.Writer) {
	fmt.Fprintln(w, `LeagueBridge — honest League of Legends compatibility diagnostics

Usage:
  leaguebridge status [--json]
  leaguebridge assess --backend ID [--platform OS] [--arch ARCH] [--json]
  leaguebridge doctor [--profile client|windows-host|macos-host|compatibility] [--client CLIENT] [--platform PLATFORM | --qt-platform PLATFORM] [--json]
  leaguebridge bundle [--profile client|windows-host|macos-host|compatibility] [--preview | --output FILE]
  leaguebridge config example [--route windows|macos]
  leaguebridge config init --host HOST [--route windows|macos] [--kvm-url URL] [options]
  leaguebridge config validate [--file FILE]
  leaguebridge config path
  leaguebridge manifest show
  leaguebridge manifest verify [--json]
  leaguebridge manifest validate --file FILE
  leaguebridge readiness [--json]
  leaguebridge evidence template --type host|client|session [--route windows|macos] [--platform OS] [--arch ARCH] [--run-id ID]
  leaguebridge evidence template-set --directory DIR [--route windows|macos] [--host-arch ARCH] [--client-platform OS] [--client-arch amd64|arm64] [--run-id ID] [--json]
  leaguebridge evidence validate --file FILE [--artifacts DIR] [--json]
  leaguebridge evidence verify-set --host FILE --client FILE --session FILE [--host-artifacts DIR --client-artifacts DIR --session-artifacts DIR] [--json]
  leaguebridge evidence v2 prepare --host FILE --client FILE --session FILE --host-artifacts DIR --client-artifacts DIR --session-artifacts DIR --route physical-windows-remote|physical-macos-remote --client-platform OS --client-arch amd64|arm64 [--output FILE | --json]
  leaguebridge evidence v2 verify --envelope FILE --host FILE --client FILE --session FILE --host-artifacts DIR --client-artifacts DIR --session-artifacts DIR --route physical-windows-remote|physical-macos-remote --client-platform OS --client-arch amd64|arm64 [--json]
  leaguebridge evidence v2 promote --envelope FILE --host FILE --client FILE --session FILE --host-artifacts DIR --client-artifacts DIR --session-artifacts DIR --route physical-windows-remote|physical-macos-remote --client-platform OS --client-arch amd64|arm64 [--json]
  leaguebridge remote map|kvm|wake|pair|unpair|list|play|stream|quit [options]
  leaguebridge version [--json]

League does not run locally on Linux/BSD today: Riot says Wine cannot meet
Vanguard requirements and Vanguard does not support virtual machines. The
remote command is an explicit handoff to a user-owned physical Windows PC or
an unvalidated physical Mac using Sunshine's experimental macOS host. The
remote wake subcommand can send one standard magic packet to a confirmed
physical host, and remote kvm only opens a separately managed hardware-KVM web
UI; neither operation implements a League/Vanguard backend or claims Riot
compatibility.`)
}

func (a *App) now() time.Time {
	if a.Now == nil {
		return time.Now()
	}
	return a.Now()
}

func (a *App) prober() ProbeRunner {
	if a.NewProber == nil {
		return probe.NewSystem()
	}
	return a.NewProber()
}
