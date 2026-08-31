// Command canonicaltar creates the exact deterministic Unix release tarball.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
)

const (
	maxBinaryInput    = int64(128 << 20)
	maxMetadataInput  = int64(1 << 20)
	maxAuxiliaryInput = int64(8 << 20)
	minimumEpoch      = int64(315532800)
	maximumEpoch      = int64(4354819199)
)

type memberSpec struct {
	name string
	mode os.FileMode
}

var canonicalMembers = []memberSpec{
	{name: "LICENSE", mode: 0o644},
	{name: "PACKAGE-MANIFEST.json", mode: 0o644},
	{name: "README.md", mode: 0o644},
	{name: "SBOM.spdx.json", mode: 0o644},
	{name: "install.sh", mode: 0o755},
	{name: "leaguebridge", mode: 0o755},
	{name: "uninstall.sh", mode: 0o755},
}

func main() {
	root := flag.String("root", "", "directory containing the canonical Unix payload")
	output := flag.String("output", "", "exclusive output tar.gz path")
	epochRaw := flag.String("source-date-epoch", "", "release SOURCE_DATE_EPOCH")
	flag.Parse()
	if flag.NArg() != 0 {
		fatalf("positional arguments are not accepted")
	}
	epoch, err := parseEpoch(*epochRaw)
	if err != nil {
		fatalf("%v", err)
	}
	if err := createArchive(*root, *output, epoch); err != nil {
		fatalf("%v", err)
	}
}

func parseEpoch(raw string) (int64, error) {
	if raw == "" {
		return 0, errors.New("source-date-epoch is required")
	}
	for _, character := range raw {
		if character < '0' || character > '9' {
			return 0, errors.New("source-date-epoch must be decimal seconds")
		}
	}
	epoch, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || epoch < minimumEpoch || epoch > maximumEpoch {
		return 0, errors.New("source-date-epoch must be representable by the release formats (1980 through 2107)")
	}
	return epoch, nil
}

func createArchive(root, output string, epoch int64) (returnErr error) {
	if root == "" || output == "" {
		return errors.New("root and output are required")
	}
	inputRoot, err := fileinput.OpenDirectoryRoot(root)
	if err != nil {
		return fmt.Errorf("root must be a non-symlink directory: %w", err)
	}
	defer inputRoot.Close()
	outputAbsolute, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve output: %w", err)
	}
	if !strings.HasSuffix(filepath.Base(outputAbsolute), ".tar.gz") {
		return errors.New("output filename must end in .tar.gz")
	}
	outputParent, err := fileinput.OpenDirectoryRoot(filepath.Dir(outputAbsolute))
	if err != nil {
		return fmt.Errorf("inspect output parents: %w", err)
	}
	defer outputParent.Close()
	outputName := filepath.Base(outputAbsolute)
	if outputName == "" || outputName == "." || outputName == string(filepath.Separator) || filepath.VolumeName(outputName) != "" {
		return errors.New("output is not a regular child path")
	}
	if info, statErr := outputParent.Lstat(outputName); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("output must not be a symlink")
		}
		return errors.New("create output: file exists")
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect output: %w", statErr)
	}

	bodies := make(map[string][]byte, len(canonicalMembers))
	for _, member := range canonicalMembers {
		body, err := fileinput.ReadRegularBoundedFromRoot(inputRoot, member.name, memberSizeLimit(member.name))
		if err != nil {
			return fmt.Errorf("read %q: %w", member.name, err)
		}
		bodies[member.name] = body
	}

	outputFile, err := outputParent.OpenFile(outputName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	complete := false
	defer func() {
		if closeErr := outputFile.Close(); returnErr == nil && closeErr != nil {
			returnErr = fmt.Errorf("close output: %w", closeErr)
		}
		if !complete || returnErr != nil {
			_ = outputParent.Remove(outputName)
		}
	}()

	gzipWriter, err := gzip.NewWriterLevel(outputFile, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("create gzip stream: %w", err)
	}
	gzipWriter.Header = gzip.Header{OS: 255}
	tarWriter := tar.NewWriter(gzipWriter)
	modTime := time.Unix(epoch, 0).UTC()
	for _, member := range canonicalMembers {
		body := bodies[member.name]
		header := &tar.Header{
			Name:     member.name,
			Mode:     int64(member.mode),
			Size:     int64(len(body)),
			ModTime:  modTime,
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			return fmt.Errorf("create member %q: %w", member.name, err)
		}
		if _, err := io.Copy(tarWriter, bytes.NewReader(body)); err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			return fmt.Errorf("write member %q: %w", member.name, err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		return fmt.Errorf("close tar archive: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("close gzip stream: %w", err)
	}
	complete = true
	return nil
}

func memberSizeLimit(name string) int64 {
	switch name {
	case "leaguebridge":
		return maxBinaryInput
	case "PACKAGE-MANIFEST.json", "SBOM.spdx.json":
		return maxMetadataInput
	default:
		return maxAuxiliaryInput
	}
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "canonicaltar: "+format+"\n", arguments...)
	os.Exit(2)
}
