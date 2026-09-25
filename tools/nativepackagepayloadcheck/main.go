// Command nativepackagepayloadcheck verifies actual native package metadata
// and payload bytes against a verified staging tree. It is score-free: it
// does not authenticate a publisher, publication, or native installation.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/productionpackage"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "nativepackagepayloadcheck: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	set := flag.NewFlagSet("nativepackagepayloadcheck", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	packagePath := set.String("package", "", "native package file")
	stagingDir := set.String("staging", "", "verified native package staging directory")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if strings.TrimSpace(*packagePath) == "" || strings.TrimSpace(*stagingDir) == "" {
		return errors.New("-package FILE and -staging DIR are required")
	}
	if err := productionpackage.VerifyStagedPayload(ctx, *packagePath, *stagingDir); err != nil {
		return fmt.Errorf("verify native package payload: %w", err)
	}
	_, err := fmt.Fprintf(stdout, "verified score-free native package payload %s against %s\n", *packagePath, *stagingDir)
	return err
}
