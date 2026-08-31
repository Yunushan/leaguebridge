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
	"strings"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
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
	repositoryRoot, err := fileinput.OpenDirectoryRoot(root)
	if err != nil {
		return fmt.Errorf("open repository root: %w", err)
	}
	defer repositoryRoot.Close()
	publicData, err := readRegularBoundedFromRoot(repositoryRoot, filepath.Join("readiness", "scorecard.json"), readiness.MaximumScorecardSize)
	if err != nil {
		return fmt.Errorf("read public readiness scorecard: %w", err)
	}
	if !bytes.Equal(publicData, readiness.EmbeddedJSON()) {
		return errors.New("public readiness scorecard is not byte-identical to the embedded production scorecard")
	}
	if err := embedded.VerifyRepositoryEvidenceFromRoot(repositoryRoot); err != nil {
		return fmt.Errorf("verify content-addressed readiness evidence: %w", err)
	}
	return nil
}

func readRegularBounded(path string, maximum int64) ([]byte, error) {
	parent, err := fileinput.OpenDirectoryRoot(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("open parent directory: %w", err)
	}
	defer parent.Close()
	return readRegularBoundedFromRoot(parent, filepath.Base(path), maximum)
}

func readRegularBoundedFromRoot(root *os.Root, name string, maximum int64) ([]byte, error) {
	if root == nil {
		return nil, errors.New("repository root is nil")
	}
	if maximum < 0 {
		return nil, errors.New("maximum scorecard size is negative")
	}
	clean := filepath.Clean(name)
	if name == "" || filepath.IsAbs(name) || filepath.VolumeName(name) != "" || clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("scorecard path %q is unsafe", name)
	}
	components := strings.Split(clean, string(filepath.Separator))
	current := ""
	var before os.FileInfo
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, fmt.Errorf("scorecard path %q is unsafe", name)
		}
		if current == "" {
			current = component
		} else {
			current = filepath.Join(current, component)
		}
		info, err := root.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("scorecard must be beneath non-symlink directories")
		}
		if index < len(components)-1 {
			if !info.IsDir() {
				return nil, errors.New("scorecard parent is not a directory")
			}
			continue
		}
		before = info
		if !info.Mode().IsRegular() {
			return nil, errors.New("scorecard must be a regular, non-symlink file")
		}
		if info.Size() > maximum {
			return nil, fmt.Errorf("scorecard exceeds %d bytes", maximum)
		}
	}
	file, err := root.Open(clean)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	pathInfo, err := root.Lstat(clean)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, opened) || !os.SameFile(before, pathInfo) {
		return nil, errors.New("scorecard changed while reading")
	}
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
	finalPath, err := root.Lstat(clean)
	if err != nil || !after.Mode().IsRegular() || !finalPath.Mode().IsRegular() ||
		!os.SameFile(opened, after) || !os.SameFile(after, finalPath) ||
		after.Size() != int64(len(body)) || finalPath.Size() != int64(len(body)) {
		return nil, errors.New("scorecard changed while reading")
	}
	return bytes.Clone(body), nil
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "readinesscheck: "+format+"\n", arguments...)
	os.Exit(1)
}
