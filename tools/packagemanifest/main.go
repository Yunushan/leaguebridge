// Command packagemanifest writes the canonical content-addressed inventory
// embedded in a LeagueBridge release archive.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
)

const (
	maxBinarySize    = int64(128 << 20)
	maxMetadataSize  = int64(1 << 20)
	maxAuxiliarySize = int64(8 << 20)
)

func main() {
	version := flag.String("version", "", "v-prefixed release version")
	goos := flag.String("os", "", "target operating system")
	goarch := flag.String("arch", "", "target architecture")
	epochRaw := flag.String("source-date-epoch", "", "release SOURCE_DATE_EPOCH")
	commit := flag.String("commit", "", "release source commit")
	tree := flag.String("tree", "", "release source tree")
	builderGoVersion := flag.String("builder-go-version", "", "exact Go toolchain used for the release")
	root := flag.String("root", "", "directory containing staged archive payload")
	output := flag.String("output", "", "output package manifest path")
	flag.Parse()

	if flag.NArg() != 0 {
		fatalf("positional arguments are not accepted")
	}
	if err := validateProductionBuilder(*builderGoVersion); err != nil {
		fatalf("%v", err)
	}
	epoch, err := strconv.ParseInt(*epochRaw, 10, 64)
	if err != nil || epoch < 0 {
		fatalf("source-date-epoch must be non-negative decimal seconds")
	}
	data, err := generate(*root, *output, *version, *goos, *goarch, epoch, *commit, *tree, *builderGoVersion)
	if err != nil {
		fatalf("%v", err)
	}
	if err := writeExclusive(*output, data); err != nil {
		fatalf("write package manifest: %v", err)
	}
}

func validateProductionBuilder(value string) error {
	if value != packageinfo.ProductionBuilderGoVersion {
		return fmt.Errorf("builder-go-version is %q; production package manifests require %q", value, packageinfo.ProductionBuilderGoVersion)
	}
	return nil
}

func generate(root, output, version, goos, goarch string, epoch int64, commit, tree, builderGoVersion string) ([]byte, error) {
	if root == "" || output == "" {
		return nil, errors.New("root and output are required")
	}
	rootAbsolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}
	outputAbsolute, err := filepath.Abs(output)
	if err != nil {
		return nil, fmt.Errorf("resolve output: %w", err)
	}
	if err := fileinput.RejectSymlinkedParents(rootAbsolute); err != nil {
		return nil, fmt.Errorf("inspect root parents: %w", err)
	}
	rootInfo, err := os.Lstat(rootAbsolute)
	if err != nil {
		return nil, fmt.Errorf("inspect root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return nil, errors.New("root must be a non-symlink directory")
	}
	if err := fileinput.RejectSymlinkedParents(outputAbsolute); err != nil {
		return nil, fmt.Errorf("inspect output parents: %w", err)
	}
	if filepath.Dir(outputAbsolute) != filepath.Clean(rootAbsolute) || filepath.Base(outputAbsolute) != packageinfo.ManifestName {
		return nil, fmt.Errorf("output must be %s directly beneath root", packageinfo.ManifestName)
	}

	names, err := packageinfo.ExpectedPayloadNames(goos, goarch)
	if err != nil {
		return nil, err
	}
	bodies := make(map[string][]byte, len(names))
	for _, name := range names {
		body, err := readRegularBounded(filepath.Join(rootAbsolute, name), payloadSizeLimit(name))
		if err != nil {
			return nil, fmt.Errorf("read payload %q: %w", name, err)
		}
		bodies[name] = body
	}
	manifest, err := packageinfo.Build(version, goos, goarch, epoch, commit, tree, builderGoVersion, bodies)
	if err != nil {
		return nil, err
	}
	return packageinfo.Marshal(manifest)
}

func payloadSizeLimit(name string) int64 {
	switch name {
	case "leaguebridge":
		return maxBinarySize
	case "SBOM.spdx.json":
		return maxMetadataSize
	default:
		return maxAuxiliarySize
	}
}

func readRegularBounded(path string, maximum int64) ([]byte, error) {
	if err := fileinput.RejectSymlinkedParents(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("not a regular, non-symlink file")
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("size %d exceeds limit %d", info.Size(), maximum)
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
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	finalInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || finalInfo.Mode()&os.ModeSymlink != 0 || !finalInfo.Mode().IsRegular() ||
		!os.SameFile(info, openedInfo) || !os.SameFile(info, finalInfo) || openedInfo.Size() != int64(len(body)) || finalInfo.Size() != int64(len(body)) {
		return nil, errors.New("payload changed while reading")
	}
	return body, nil
}

func writeExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "packagemanifest: "+format+"\n", arguments...)
	os.Exit(2)
}
