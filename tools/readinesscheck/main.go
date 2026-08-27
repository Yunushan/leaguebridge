// Command readinesscheck verifies the production readiness scorecard and all
// content-addressed repository evidence against an exported source snapshot.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Yunushan/leaguebridge/internal/readiness"
)

func main() {
	root := flag.String("root", ".", "exported repository root to verify")
	flag.Parse()
	if flag.NArg() != 0 {
		fatalf("positional arguments are not accepted")
	}
	if err := verify(*root); err != nil {
		fatalf("%v", err)
	}
}

func verify(root string) error {
	embedded, err := readiness.Embedded()
	if err != nil {
		return fmt.Errorf("parse embedded readiness scorecard: %w", err)
	}
	publicData, err := readRegularBounded(filepath.Join(root, "readiness", "scorecard.json"), readiness.MaximumScorecardSize)
	if err != nil {
		return fmt.Errorf("read public readiness scorecard: %w", err)
	}
	if !bytes.Equal(publicData, readiness.EmbeddedJSON()) {
		return errors.New("public readiness scorecard is not byte-identical to the embedded production scorecard")
	}
	if err := embedded.VerifyRepositoryEvidence(root); err != nil {
		return fmt.Errorf("verify content-addressed readiness evidence: %w", err)
	}
	return nil
}

func readRegularBounded(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("scorecard must be a regular, non-symlink file")
	}
	if before.Size() > maximum {
		return nil, fmt.Errorf("scorecard exceeds %d bytes", maximum)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maximum {
		return nil, fmt.Errorf("scorecard exceeds %d bytes", maximum)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	finalPath, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || finalPath.Mode()&os.ModeSymlink != 0 || !finalPath.Mode().IsRegular() ||
		!os.SameFile(before, after) || !os.SameFile(before, finalPath) || after.Size() != int64(len(body)) || finalPath.Size() != int64(len(body)) {
		return nil, errors.New("scorecard changed while reading")
	}
	return bytes.Clone(body), nil
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "readinesscheck: "+format+"\n", arguments...)
	os.Exit(1)
}
