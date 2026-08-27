// Command vendorcheck verifies the complete offline vendor lock in an
// exported LeagueBridge source snapshot.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Yunushan/leaguebridge/internal/vendorintegrity"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("vendorcheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "exported repository root to verify")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "vendorcheck: positional arguments are not accepted")
		return 2
	}
	if err := vendorintegrity.Verify(*root); err != nil {
		fmt.Fprintf(stderr, "vendorcheck: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "vendorcheck: verified %d vendored files; production dependency %s %s; lock sha256:%s\n",
		vendorintegrity.ExpectedFileCount,
		vendorintegrity.ModulePath,
		vendorintegrity.ModuleVersion,
		vendorintegrity.ExpectedLockSHA256,
	)
	return 0
}
