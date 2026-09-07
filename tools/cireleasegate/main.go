// Command cireleasegate requires a complete successful CI attempt on main for
// the exact release commit. GitHub job state is read live; cached artifacts or
// pull-request checks cannot stand in for the privileged post-merge CI gates.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/Yunushan/leaguebridge/internal/cireleasegate"
)

var commitPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

func main() {
	commit := flag.String("commit", "", "exact lowercase release commit SHA")
	gh := flag.String("gh", "gh", "trusted GitHub CLI executable")
	flag.Parse()
	if flag.NArg() != 0 || !commitPattern.MatchString(*commit) || *gh == "" {
		fmt.Fprintln(os.Stderr, "cireleasegate: a complete -commit SHA is required; positional arguments are not accepted")
		os.Exit(2)
	}
	run, err := cireleasegate.Verify(context.Background(), cireleasegate.VerifyRequest{
		Commit: *commit,
		GHPath: *gh,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cireleasegate: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("verified complete CI run %d attempt %d for release commit %s\n", run.ID, run.Attempt, run.Commit)
}
