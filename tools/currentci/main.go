// Command currentci verifies signed CI evidence against the currently observed
// main commit and its latest complete successful CI attempt.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/currentci"
	"github.com/Yunushan/leaguebridge/internal/target"
)

type verifier func(context.Context, currentci.VerifyRequest) (currentci.Observation, error)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, currentci.Verify)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, verify verifier) int {
	set := flag.NewFlagSet("currentci", flag.ContinueOnError)
	set.SetOutput(stderr)
	gh := set.String("gh", "gh", "trusted GitHub CLI executable")
	raceVet := set.String("race-vet-subject", "", "Linux race/vet subject JSON from the CI run")
	var crossBuild subjectPaths
	set.Var(&crossBuild, "cross-build-subject", "cross-build subject JSON; repeat once for each of the nine targets")
	set.Usage = func() {
		fmt.Fprintln(stderr, "Usage: currentci -race-vet-subject PATH -cross-build-subject PATH ...")
		fmt.Fprintln(stderr, "Verifies current main and its latest complete CI attempt using live GitHub data.")
		fmt.Fprintln(stderr, "Run from the evidence directory; binary paths resolve from that directory.")
		fmt.Fprintln(stderr, "A successful observation does not award readiness points or prove publication.")
		set.PrintDefaults()
	}
	if err := set.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if set.NArg() != 0 || strings.TrimSpace(*gh) == "" || strings.TrimSpace(*raceVet) == "" || len(crossBuild) != len(target.Ordered()) {
		fmt.Fprintln(stderr, "currentci: supply one -race-vet-subject, all nine -cross-build-subject paths, and a trusted -gh executable; positional arguments are not accepted")
		return 2
	}
	result, err := verify(ctx, currentci.VerifyRequest{
		GHPath: *gh, RaceVetSubject: *raceVet, CrossBuildSubjects: append([]string(nil), crossBuild...),
	})
	if err != nil {
		fmt.Fprintf(stderr, "currentci: %v\n", err)
		return 1
	}
	if _, err := fmt.Fprintf(stdout, "verified current main CI evidence commit=%s tree=%s run=%d attempt=%d observed_at=%s\n", result.Commit, result.Tree, result.RunID, result.RunAttempt, result.ObservedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		fmt.Fprintln(stderr, "currentci: write verification result failed")
		return 1
	}
	return 0
}

type subjectPaths []string

func (paths *subjectPaths) String() string { return strings.Join(*paths, ",") }

func (paths *subjectPaths) Set(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("cross-build subject path must not be empty")
	}
	if len(*paths) >= len(target.Ordered()) {
		return errors.New("only nine cross-build subject paths are accepted")
	}
	*paths = append(*paths, path)
	return nil
}
