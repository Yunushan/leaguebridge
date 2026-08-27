// Command canonicalzip creates the exact deterministic Windows release ZIP.
package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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
	{name: "leaguebridge.exe", mode: 0o755},
}

func main() {
	root := flag.String("root", "", "directory containing the canonical Windows payload")
	output := flag.String("output", "", "exclusive output ZIP path")
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
		return 0, errors.New("source-date-epoch must be representable by ZIP timestamps (1980 through 2107)")
	}
	return epoch, nil
}

func createArchive(root, output string, epoch int64) (returnErr error) {
	if root == "" || output == "" {
		return errors.New("root and output are required")
	}
	if !strings.HasSuffix(filepath.Base(output), ".zip") {
		return errors.New("output filename must end in .zip")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return errors.New("root must be a non-symlink directory")
	}

	bodies := make(map[string][]byte, len(canonicalMembers))
	for _, member := range canonicalMembers {
		body, err := readRegularBounded(filepath.Join(root, member.name), memberSizeLimit(member.name))
		if err != nil {
			return fmt.Errorf("read %q: %w", member.name, err)
		}
		bodies[member.name] = body
	}

	outputFile, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	complete := false
	defer func() {
		if closeErr := outputFile.Close(); returnErr == nil && closeErr != nil {
			returnErr = fmt.Errorf("close output: %w", closeErr)
		}
		if !complete || returnErr != nil {
			_ = os.Remove(output)
		}
	}()

	archive := zip.NewWriter(outputFile)
	date, clock := msDOSDateTime(time.Unix(epoch, 0).UTC())
	for _, member := range canonicalMembers {
		header := &zip.FileHeader{
			Name:         member.name,
			Method:       zip.Deflate,
			ModifiedDate: date,
			ModifiedTime: clock,
		}
		header.SetMode(member.mode)
		writer, err := archive.CreateHeader(header)
		if err != nil {
			_ = archive.Close()
			return fmt.Errorf("create member %q: %w", member.name, err)
		}
		if _, err := io.Copy(writer, bytes.NewReader(bodies[member.name])); err != nil {
			_ = archive.Close()
			return fmt.Errorf("write member %q: %w", member.name, err)
		}
	}
	if err := archive.Close(); err != nil {
		return fmt.Errorf("close ZIP archive: %w", err)
	}
	complete = true
	return nil
}

func memberSizeLimit(name string) int64 {
	switch name {
	case "leaguebridge.exe":
		return maxBinaryInput
	case "PACKAGE-MANIFEST.json", "SBOM.spdx.json":
		return maxMetadataInput
	default:
		return maxAuxiliaryInput
	}
}

func readRegularBounded(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("not a regular, non-symlink file")
	}
	if before.Size() > maximum {
		return nil, fmt.Errorf("size %d exceeds limit %d", before.Size(), maximum)
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
		return nil, fmt.Errorf("content exceeds limit %d", maximum)
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
		return nil, errors.New("file changed while reading")
	}
	return body, nil
}

func msDOSDateTime(value time.Time) (uint16, uint16) {
	value = value.UTC()
	date := uint16(value.Day()) | uint16(value.Month())<<5 | uint16(value.Year()-1980)<<9
	clock := uint16(value.Second()/2) | uint16(value.Minute())<<5 | uint16(value.Hour())<<11
	return date, clock
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "canonicalzip: "+format+"\n", arguments...)
	os.Exit(2)
}
