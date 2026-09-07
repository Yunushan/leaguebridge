// Command releasecheck validates the complete layout and integrity of a
// LeagueBridge release directory before it can be published.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Yunushan/leaguebridge/internal/readiness"
	"github.com/Yunushan/leaguebridge/internal/releasecheck"
)

func main() {
	dir := flag.String("dir", "dist", "release directory to validate")
	version := flag.String("version", "", "v-prefixed release version")
	sourceDateEpoch := flag.String("source-date-epoch", "", "required release SOURCE_DATE_EPOCH in decimal seconds")
	commit := flag.String("commit", "", "required lowercase release commit hash")
	tree := flag.String("tree", "", "required lowercase release source tree hash")
	builderGoVersion := flag.String("builder-go-version", "", "exact Go release builder version")
	flag.Parse()

	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "releasecheck: positional arguments are not accepted")
		os.Exit(2)
	}
	epoch, err := releasecheck.ParseSourceDateEpoch(*sourceDateEpoch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "releasecheck: %v\n", err)
		os.Exit(2)
	}
	input := releasecheck.CheckRequest{
		Dir: *dir, Version: *version, SourceDateEpoch: epoch,
		Commit: *commit, Tree: *tree, BuilderGoVersion: *builderGoVersion,
		ExpectedScorecard: readiness.EmbeddedJSON(),
	}
	if err := input.ValidateIdentity(); err != nil {
		fmt.Fprintf(os.Stderr, "releasecheck: %v\n", err)
		os.Exit(2)
	}
	if err := releasecheck.Check(input); err != nil {
		fmt.Fprintf(os.Stderr, "releasecheck: %v\n", err)
		os.Exit(1)
	}
}
