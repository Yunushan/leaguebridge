// Command releasecheck validates the complete layout and integrity of a
// LeagueBridge release directory before it can be published.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	runtimedebug "runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
	"github.com/Yunushan/leaguebridge/internal/readiness"
	"github.com/Yunushan/leaguebridge/internal/releaseversion"
	"github.com/Yunushan/leaguebridge/internal/target"
)

const (
	maxArchiveSize      = int64(512 << 20)
	maxBinarySize       = int64(128 << 20)
	maxSBOMSize         = int64(1 << 20)
	maxAuxiliarySize    = int64(8 << 20)
	maxUncompressedSize = int64(256 << 20)
	maxChecksumSize     = int64(64 << 10)

	mainModulePath             = "github.com/Yunushan/leaguebridge"
	mainPackagePath            = mainModulePath + "/cmd/leaguebridge"
	productionBuilderGoVersion = packageinfo.ProductionBuilderGoVersion
)

type artifact struct {
	name       string
	binaryName string
	goos       string
	goarch     string
}

type archivePayload struct {
	binary          []byte
	sbom            []byte
	packageManifest []byte
	members         map[string][]byte
}

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
	epoch, err := parseSourceDateEpoch(*sourceDateEpoch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "releasecheck: %v\n", err)
		os.Exit(2)
	}
	if err := validateCommit(*commit); err != nil {
		fmt.Fprintf(os.Stderr, "releasecheck: %v\n", err)
		os.Exit(2)
	}
	if err := validateTree(*tree); err != nil {
		fmt.Fprintf(os.Stderr, "releasecheck: %v\n", err)
		os.Exit(2)
	}
	if err := validateProductionBuilderGoVersion(*builderGoVersion); err != nil {
		fmt.Fprintf(os.Stderr, "releasecheck: %v\n", err)
		os.Exit(2)
	}
	if err := checkRelease(*dir, *version, epoch, *commit, *tree, *builderGoVersion); err != nil {
		fmt.Fprintf(os.Stderr, "releasecheck: %v\n", err)
		os.Exit(1)
	}
}

func validateProductionBuilderGoVersion(value string) error {
	if value != productionBuilderGoVersion {
		return fmt.Errorf("builder-go-version is %q; production releases require %q", value, productionBuilderGoVersion)
	}
	return nil
}

func parseSourceDateEpoch(raw string) (int64, error) {
	if raw == "" {
		return 0, errors.New("source-date-epoch is required")
	}
	for _, character := range raw {
		if character < '0' || character > '9' {
			return 0, errors.New("source-date-epoch must be non-negative decimal seconds")
		}
	}
	epoch, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, errors.New("source-date-epoch is outside the supported range")
	}
	year := time.Unix(epoch, 0).UTC().Year()
	if year < 1980 || year > 2107 {
		return 0, errors.New("source-date-epoch must be representable by the release archive timestamp range (years 1980 through 2107)")
	}
	return epoch, nil
}

func checkRelease(dir, version string, epoch int64, commit, tree, builderGoVersion string) error {
	artifacts, err := expectedArtifacts(version)
	if err != nil {
		return err
	}
	if err := validateCommit(commit); err != nil {
		return err
	}
	if err := validateTree(tree); err != nil {
		return err
	}

	expectedFiles := map[string]struct{}{"checksums.txt": {}}
	for _, item := range artifacts {
		expectedFiles[item.name] = struct{}{}
	}
	releaseRoot, err := fileinput.OpenDirectoryRoot(dir)
	if err != nil {
		return fmt.Errorf("release directory: %w", err)
	}
	defer releaseRoot.Close()
	if err := checkDirectoryFromRoot(releaseRoot, expectedFiles); err != nil {
		return err
	}
	if err := checkChecksumsFromRoot(releaseRoot, artifacts); err != nil {
		return err
	}

	for _, item := range artifacts {
		err = checkTarGzipFromRoot(releaseRoot, item.name, item, version, epoch, commit, tree, builderGoVersion)
		if err != nil {
			return fmt.Errorf("%s: %w", item.name, err)
		}
	}
	return nil
}

func validateCommit(commit string) error {
	if len(commit) != 40 && len(commit) != 64 {
		return errors.New("commit must be a 40- or 64-character lowercase hexadecimal object ID")
	}
	if !lowerHexLength(commit) {
		return errors.New("commit must be a 40- or 64-character lowercase hexadecimal object ID")
	}
	return nil
}

func validateTree(tree string) error {
	if len(tree) != 40 && len(tree) != 64 || !lowerHexLength(tree) {
		return errors.New("tree must be a 40- or 64-character lowercase hexadecimal object ID")
	}
	return nil
}

func expectedArtifacts(version string) ([]artifact, error) {
	if !releaseversion.Valid(version) {
		return nil, errors.New("version must be a valid v-prefixed Semantic Version")
	}
	base := "leaguebridge_" + strings.TrimPrefix(version, "v")
	artifacts := make([]artifact, 0, len(target.Ordered()))
	for _, candidate := range target.Ordered() {
		artifacts = append(artifacts, artifact{
			name:       base + "_" + candidate.GOOS + "_" + candidate.GOARCH + ".tar.gz",
			binaryName: "leaguebridge",
			goos:       candidate.GOOS,
			goarch:     candidate.GOARCH,
		})
	}
	return artifacts, nil
}

func checkDirectory(dir string, expected map[string]struct{}) error {
	if err := fileinput.RejectSymlinkedParents(dir); err != nil {
		return fmt.Errorf("release directory path: %w", err)
	}
	directoryInfo, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect release directory: %w", err)
	}
	if directoryInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("release directory must not be a symbolic link")
	}
	if !directoryInfo.IsDir() {
		return errors.New("release path is not a directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read release directory: %w", err)
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("unexpected release directory entry %q", name)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("release directory entry %q is a symbolic link", name)
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect %q: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("release directory entry %q is not a regular file", name)
		}
		seen[name] = struct{}{}
	}
	for name := range expected {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("missing release file %q", name)
		}
	}
	return nil
}

func checkDirectoryFromRoot(root *os.Root, expected map[string]struct{}) error {
	if root == nil {
		return errors.New("release directory root is nil")
	}
	directoryInfo, err := root.Lstat(".")
	if err != nil {
		return fmt.Errorf("inspect release directory: %w", err)
	}
	if directoryInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("release directory must not be a symbolic link")
	}
	if !directoryInfo.IsDir() {
		return errors.New("release path is not a directory")
	}
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open release directory: %w", err)
	}
	entries, err := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err != nil {
		return fmt.Errorf("read release directory: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close release directory: %w", closeErr)
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("unexpected release directory entry %q", name)
		}
		info, err := root.Lstat(name)
		if err != nil {
			return fmt.Errorf("inspect %q: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("release directory entry %q is a symbolic link", name)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("release directory entry %q is not a regular file", name)
		}
		seen[name] = struct{}{}
	}
	for name := range expected {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("missing release file %q", name)
		}
	}
	return nil
}

func checkChecksums(dir string, artifacts []artifact) error {
	manifestPath := filepath.Join(dir, "checksums.txt")
	data, err := readFileBounded(manifestPath, maxChecksumSize)
	if err != nil {
		return fmt.Errorf("read checksums.txt: %w", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return errors.New("checksums.txt must be non-empty and end with a newline")
	}
	if bytes.ContainsRune(data, '\r') {
		return errors.New("checksums.txt must use LF line endings")
	}

	expectedNames := make([]string, 0, len(artifacts))
	for _, item := range artifacts {
		expectedNames = append(expectedNames, item.name)
	}
	sort.Strings(expectedNames)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != len(expectedNames) {
		return fmt.Errorf("checksums.txt has %d entries; want %d", len(lines), len(expectedNames))
	}

	for index, line := range lines {
		if len(line) < 69 || line[64:68] != " *./" || !lowerHex(line[:64]) {
			return fmt.Errorf("checksums.txt line %d is not canonical binary-mode sha256sum output", index+1)
		}
		name := line[68:]
		if name != expectedNames[index] {
			return fmt.Errorf("checksums.txt line %d names %q; want canonical entry %q", index+1, name, expectedNames[index])
		}
		actual, err := fileSHA256(filepath.Join(dir, name), maxArchiveSize)
		if err != nil {
			return fmt.Errorf("hash %q: %w", name, err)
		}
		if actual != line[:64] {
			return fmt.Errorf("checksum mismatch for %q", name)
		}
	}
	return nil
}

func checkChecksumsFromRoot(root *os.Root, artifacts []artifact) error {
	data, err := readFileBoundedFromRoot(root, "checksums.txt", maxChecksumSize)
	if err != nil {
		return fmt.Errorf("read checksums.txt: %w", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return errors.New("checksums.txt must be non-empty and end with a newline")
	}
	if bytes.ContainsRune(data, '\r') {
		return errors.New("checksums.txt must use LF line endings")
	}

	expectedNames := make([]string, 0, len(artifacts))
	for _, item := range artifacts {
		expectedNames = append(expectedNames, item.name)
	}
	sort.Strings(expectedNames)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != len(expectedNames) {
		return fmt.Errorf("checksums.txt has %d entries; want %d", len(lines), len(expectedNames))
	}

	for index, line := range lines {
		if len(line) < 69 || line[64:68] != " *./" || !lowerHex(line[:64]) {
			return fmt.Errorf("checksums.txt line %d is not canonical binary-mode sha256sum output", index+1)
		}
		name := line[68:]
		if name != expectedNames[index] {
			return fmt.Errorf("checksums.txt line %d names %q; want canonical entry %q", index+1, name, expectedNames[index])
		}
		actual, err := fileSHA256FromRoot(root, name, maxArchiveSize)
		if err != nil {
			return fmt.Errorf("hash %q: %w", name, err)
		}
		if actual != line[:64] {
			return fmt.Errorf("checksum mismatch for %q", name)
		}
	}
	return nil
}

func lowerHex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	return lowerHexLength(value)
}

func lowerHexLength(value string) bool {
	for i := 0; i < len(value); i++ {
		if !((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')) {
			return false
		}
	}
	return true
}

func readFileBounded(path string, maximum int64) ([]byte, error) {
	if err := fileinput.RejectSymlinkedParents(path); err != nil {
		return nil, err
	}
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
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("size %d exceeds limit %d", info.Size(), maximum)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("content exceeds limit %d", maximum)
	}
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	finalPath, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || finalPath.Mode()&os.ModeSymlink != 0 || !finalPath.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(before, finalPath) || opened.Size() != int64(len(data)) || finalPath.Size() != int64(len(data)) {
		return nil, errors.New("file changed while reading")
	}
	return data, nil
}

func fileSHA256(path string, maximum int64) (string, error) {
	if err := fileinput.RejectSymlinkedParents(path); err != nil {
		return "", err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return "", errors.New("not a regular, non-symlink file")
	}
	if before.Size() > maximum {
		return "", fmt.Errorf("size %d exceeds limit %d", before.Size(), maximum)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	if info.Size() > maximum {
		return "", fmt.Errorf("size %d exceeds limit %d", info.Size(), maximum)
	}

	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, maximum+1))
	if err != nil {
		return "", err
	}
	if written > maximum {
		return "", fmt.Errorf("content exceeds limit %d", maximum)
	}
	opened, err := file.Stat()
	if err != nil {
		return "", err
	}
	finalPath, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !opened.Mode().IsRegular() || finalPath.Mode()&os.ModeSymlink != 0 || !finalPath.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(before, finalPath) || opened.Size() != written || finalPath.Size() != written {
		return "", errors.New("file changed while reading")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func validateReleaseRootFileName(name string) error {
	if strings.TrimSpace(name) == "" || name == "." || name == ".." || filepath.IsAbs(name) || filepath.VolumeName(name) != "" || filepath.Base(name) != name || filepath.Clean(name) != name || strings.ContainsAny(name, `/\`+"\x00\r\n") {
		return fmt.Errorf("release file name %q is unsafe", name)
	}
	return nil
}

func openReleaseFileFromRoot(root *os.Root, name string, maximum int64) (*os.File, os.FileInfo, error) {
	if root == nil {
		return nil, nil, errors.New("release directory root is nil")
	}
	if maximum < 0 {
		return nil, nil, errors.New("release file size limit is negative")
	}
	if err := validateReleaseRootFileName(name); err != nil {
		return nil, nil, err
	}
	before, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, nil, errors.New("not a regular, non-symlink file")
	}
	if before.Size() > maximum {
		return nil, nil, fmt.Errorf("size %d exceeds limit %d", before.Size(), maximum)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !opened.Mode().IsRegular() || opened.Size() > maximum || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, nil, errors.New("file changed while opening")
	}
	return file, before, nil
}

func readFileBoundedFromRoot(root *os.Root, name string, maximum int64) ([]byte, error) {
	file, before, err := openReleaseFileFromRoot(root, name, maximum)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("content exceeds limit %d", maximum)
	}
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	finalPath, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || finalPath.Mode()&os.ModeSymlink != 0 || !finalPath.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(before, finalPath) || opened.Size() != int64(len(data)) || finalPath.Size() != int64(len(data)) {
		return nil, errors.New("file changed while reading")
	}
	return data, nil
}

func fileSHA256FromRoot(root *os.Root, name string, maximum int64) (string, error) {
	file, before, err := openReleaseFileFromRoot(root, name, maximum)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, maximum+1))
	if err != nil {
		return "", err
	}
	if written > maximum {
		return "", fmt.Errorf("content exceeds limit %d", maximum)
	}
	opened, err := file.Stat()
	if err != nil {
		return "", err
	}
	finalPath, err := root.Lstat(name)
	if err != nil {
		return "", err
	}
	if !opened.Mode().IsRegular() || finalPath.Mode()&os.ModeSymlink != 0 || !finalPath.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(before, finalPath) || opened.Size() != written || finalPath.Size() != written {
		return "", errors.New("file changed while reading")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func checkTarGzip(path string, item artifact, version string, epoch int64, commit, tree, builderGoVersion string) error {
	payload, err := readTarGzip(path, item.binaryName, epoch)
	if err != nil {
		return err
	}
	return checkArchivePayload(payload, item, version, epoch, commit, tree, builderGoVersion)
}

func readTarGzip(path, binaryName string, epoch int64) (archivePayload, error) {
	data, err := readFileBounded(path, maxArchiveSize)
	if err != nil {
		return archivePayload{}, err
	}
	return readTarGzipData(data, binaryName, epoch)
}

func checkTarGzipFromRoot(root *os.Root, name string, item artifact, version string, epoch int64, commit, tree, builderGoVersion string) error {
	payload, err := readTarGzipFromRoot(root, name, item.binaryName, epoch)
	if err != nil {
		return err
	}
	return checkArchivePayload(payload, item, version, epoch, commit, tree, builderGoVersion)
}

func readTarGzipFromRoot(root *os.Root, name, binaryName string, epoch int64) (archivePayload, error) {
	data, err := readFileBoundedFromRoot(root, name, maxArchiveSize)
	if err != nil {
		return archivePayload{}, err
	}
	return readTarGzipData(data, binaryName, epoch)
}

func readTarGzipData(data []byte, binaryName string, epoch int64) (archivePayload, error) {
	source := bytes.NewReader(data)
	gzipReader, err := gzip.NewReader(source)
	if err != nil {
		return archivePayload{}, fmt.Errorf("open gzip stream: %w", err)
	}
	gzipReader.Multistream(false)
	if !gzipReader.ModTime.IsZero() || gzipReader.Name != "" || gzipReader.Comment != "" || len(gzipReader.Extra) != 0 || gzipReader.OS != 255 {
		gzipReader.Close()
		return archivePayload{}, errors.New("gzip header is not canonical")
	}

	limited := &io.LimitedReader{R: gzipReader, N: maxUncompressedSize + 1}
	archive := tar.NewReader(limited)
	expectedNames := expectedMemberNames(binaryName, true)
	seen := make(map[string]struct{}, len(expectedNames))
	payload := archivePayload{members: make(map[string][]byte, len(expectedNames))}
	var total int64
	for index := 0; ; index++ {
		header, nextErr := archive.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			gzipReader.Close()
			return archivePayload{}, fmt.Errorf("read tar member: %w", nextErr)
		}
		if err := checkMember(header.Name, header.FileInfo().Mode(), binaryName, true, seen); err != nil {
			gzipReader.Close()
			return archivePayload{}, err
		}
		if index >= len(expectedNames) || header.Name != expectedNames[index] {
			gzipReader.Close()
			want := "end of archive"
			if index < len(expectedNames) {
				want = expectedNames[index]
			}
			return archivePayload{}, fmt.Errorf("member %q is out of canonical order; want %q", header.Name, want)
		}
		if header.Typeflag != tar.TypeReg {
			gzipReader.Close()
			return archivePayload{}, fmt.Errorf("member %q is not a regular file", header.Name)
		}
		if header.Format != tar.FormatUSTAR || header.Uname != "" || header.Gname != "" || header.Linkname != "" || len(header.PAXRecords) != 0 || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() || header.Devmajor != 0 || header.Devminor != 0 {
			gzipReader.Close()
			return archivePayload{}, fmt.Errorf("member %q has non-canonical USTAR metadata", header.Name)
		}
		if header.Uid != 0 || header.Gid != 0 {
			gzipReader.Close()
			return archivePayload{}, fmt.Errorf("member %q has uid:gid %d:%d; want 0:0", header.Name, header.Uid, header.Gid)
		}
		if header.ModTime.Unix() != epoch || header.ModTime.Nanosecond() != 0 {
			gzipReader.Close()
			return archivePayload{}, fmt.Errorf("member %q has timestamp %s; want SOURCE_DATE_EPOCH %d", header.Name, header.ModTime.UTC().Format(time.RFC3339Nano), epoch)
		}
		limit := memberSizeLimit(header.Name, binaryName)
		if header.Size < 0 || header.Size > limit {
			gzipReader.Close()
			return archivePayload{}, fmt.Errorf("member %q size %d exceeds limit %d", header.Name, header.Size, limit)
		}
		total += header.Size
		if total > maxUncompressedSize {
			gzipReader.Close()
			return archivePayload{}, errors.New("archive members exceed uncompressed size limit")
		}
		member, readErr := io.ReadAll(io.LimitReader(archive, limit+1))
		if readErr != nil {
			gzipReader.Close()
			return archivePayload{}, fmt.Errorf("read member %q: %w", header.Name, readErr)
		}
		if int64(len(member)) != header.Size {
			gzipReader.Close()
			return archivePayload{}, fmt.Errorf("member %q size changed while reading", header.Name)
		}
		payload.members[header.Name] = member
		switch header.Name {
		case binaryName:
			payload.binary = member
		case "SBOM.spdx.json":
			payload.sbom = member
		case packageinfo.ManifestName:
			payload.packageManifest = member
		}
	}
	if err := checkCompleteMembers(seen, binaryName, true); err != nil {
		gzipReader.Close()
		return archivePayload{}, err
	}
	if _, err := io.Copy(zeroWriter{}, limited); err != nil {
		gzipReader.Close()
		return archivePayload{}, fmt.Errorf("non-canonical tar padding: %w", err)
	}
	if limited.N == 0 {
		gzipReader.Close()
		return archivePayload{}, errors.New("gzip payload exceeds uncompressed size limit")
	}
	if err := gzipReader.Close(); err != nil {
		return archivePayload{}, fmt.Errorf("close gzip stream: %w", err)
	}
	if source.Len() != 0 {
		return archivePayload{}, errors.New("gzip stream has trailing bytes or additional members")
	}
	canonical, err := canonicalTarGzipBytes(payload.members, binaryName, epoch)
	if err != nil {
		return archivePayload{}, fmt.Errorf("reconstruct canonical tar.gz: %w", err)
	}
	if !bytes.Equal(data, canonical) {
		return archivePayload{}, errors.New("tar.gz bytes do not match the canonical USTAR, gzip, and compression contract")
	}
	return payload, nil
}

func canonicalTarGzipBytes(members map[string][]byte, binaryName string, epoch int64) ([]byte, error) {
	var output bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&output, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	gzipWriter.Header = gzip.Header{OS: 255}
	tarWriter := tar.NewWriter(gzipWriter)
	modTime := time.Unix(epoch, 0).UTC()
	for _, name := range expectedMemberNames(binaryName, true) {
		mode, ok := expectedMemberMode(name, binaryName, true)
		if !ok {
			return nil, fmt.Errorf("no canonical mode for %q", name)
		}
		body := members[name]
		header := &tar.Header{
			Name:     name,
			Mode:     int64(mode),
			Size:     int64(len(body)),
			ModTime:  modTime,
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := tarWriter.Write(body); err != nil {
			return nil, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return nil, err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

type zeroWriter struct{}

func (zeroWriter) Write(data []byte) (int, error) {
	for _, value := range data {
		if value != 0 {
			return 0, errors.New("non-zero data follows the tar end marker")
		}
	}
	return len(data), nil
}

func expectedMemberNames(binaryName string, includeLifecycle bool) []string {
	names := []string{"LICENSE", packageinfo.ManifestName, "README.md", "SBOM.spdx.json", binaryName}
	if includeLifecycle {
		names = append(names, "install.sh", "uninstall.sh")
	}
	sort.Strings(names)
	return names
}

func checkMember(name string, mode os.FileMode, binaryName string, includeLifecycle bool, seen map[string]struct{}) error {
	wantMode, ok := expectedMemberMode(name, binaryName, includeLifecycle)
	if !ok {
		return fmt.Errorf("unexpected archive member %q", name)
	}
	if _, ok := seen[name]; ok {
		return fmt.Errorf("duplicate archive member %q", name)
	}
	seen[name] = struct{}{}
	if !mode.IsRegular() {
		return fmt.Errorf("member %q is not a regular file", name)
	}
	if mode != wantMode {
		return fmt.Errorf("member %q has mode %04o; want %04o", name, mode.Perm(), wantMode)
	}
	return nil
}

func expectedMemberMode(name, binaryName string, includeLifecycle bool) (os.FileMode, bool) {
	switch name {
	case "LICENSE", packageinfo.ManifestName, "README.md", "SBOM.spdx.json":
		return 0o644, true
	case binaryName:
		return 0o755, true
	case "install.sh", "uninstall.sh":
		return 0o755, includeLifecycle
	default:
		return 0, false
	}
}

func memberSizeLimit(name, binaryName string) int64 {
	switch name {
	case binaryName:
		return maxBinarySize
	case "SBOM.spdx.json", packageinfo.ManifestName:
		return maxSBOMSize
	default:
		return maxAuxiliarySize
	}
}

func checkCompleteMembers(seen map[string]struct{}, binaryName string, includeLifecycle bool) error {
	expected := expectedMemberNames(binaryName, includeLifecycle)
	if len(seen) != len(expected) {
		return fmt.Errorf("archive has %d regular members; want %d", len(seen), len(expected))
	}
	for _, name := range expected {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("archive is missing member %q", name)
		}
	}
	return nil
}

func checkArchivePayload(payload archivePayload, item artifact, version string, epoch int64, commit, tree, builderGoVersion string) error {
	if len(payload.binary) == 0 {
		return errors.New("release binary is empty")
	}
	if len(payload.sbom) == 0 {
		return errors.New("SBOM.spdx.json is empty")
	}
	if len(payload.packageManifest) == 0 {
		return errors.New("PACKAGE-MANIFEST.json is empty")
	}
	if err := checkReleaseBinary(payload.binary, item, version, epoch, commit, tree, builderGoVersion); err != nil {
		return fmt.Errorf("binary: %w", err)
	}
	digest := sha256.Sum256(payload.binary)
	if err := checkSBOM(payload.sbom, payload.binary, item, version, epoch, hex.EncodeToString(digest[:])); err != nil {
		return fmt.Errorf("SBOM.spdx.json: %w", err)
	}
	if err := checkPackageManifest(payload, item, version, epoch, commit, tree, builderGoVersion); err != nil {
		return fmt.Errorf("PACKAGE-MANIFEST.json: %w", err)
	}
	return nil
}

func checkPackageManifest(payload archivePayload, item artifact, version string, epoch int64, commit, tree, builderGoVersion string) error {
	bodies := make(map[string][]byte, len(payload.members)-1)
	for name, body := range payload.members {
		if name != packageinfo.ManifestName {
			bodies[name] = body
		}
	}
	manifest, err := packageinfo.Build(version, item.goos, item.goarch, epoch, commit, tree, builderGoVersion, bodies)
	if err != nil {
		return err
	}
	expected, err := packageinfo.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode expected manifest: %w", err)
	}
	if !bytes.Equal(payload.packageManifest, expected) {
		return errors.New("document does not exactly match the expected target, provenance, install map, modes, sizes, and payload SHA-256 values")
	}
	return nil
}

func checkReleaseBinary(binaryData []byte, item artifact, version string, epoch int64, commit, tree, builderGoVersion string) error {
	if !target.IsSupported(item.goos, item.goarch) {
		return fmt.Errorf("unsupported release target %s/%s", item.goos, item.goarch)
	}
	if err := checkBinaryContainer(binaryData, item); err != nil {
		return fmt.Errorf("container identity: %w", err)
	}
	info, err := buildinfo.Read(bytes.NewReader(binaryData))
	if err != nil {
		return fmt.Errorf("read Go build info: %w", err)
	}
	if info.Path != mainPackagePath {
		return fmt.Errorf("main package path is %q; want %q", info.Path, mainPackagePath)
	}
	if info.Main.Path != mainModulePath {
		return fmt.Errorf("main module path is %q; want %q", info.Main.Path, mainModulePath)
	}
	if info.Main.Replace != nil {
		return errors.New("main module unexpectedly has a replacement")
	}
	if _, err := canonicalProductionDependency(info.Deps); err != nil {
		return err
	}
	if info.GoVersion != builderGoVersion {
		return fmt.Errorf("Go builder version is %q; want %q", info.GoVersion, builderGoVersion)
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		if _, exists := settings[setting.Key]; exists {
			return fmt.Errorf("Go build setting %q occurs more than once", setting.Key)
		}
		settings[setting.Key] = setting.Value
	}
	wantSettings := map[string]string{
		"-buildmode":  "exe",
		"-compiler":   "gc",
		"-trimpath":   "true",
		"CGO_ENABLED": "0",
		"GOOS":        item.goos,
		"GOARCH":      item.goarch,
	}
	switch builderGoVersion {
	case productionBuilderGoVersion:
		wantSettings["DefaultGODEBUG"] = "containermaxprocs=0,cryptocustomrand=1,decoratemappings=0,tlssecpmlkem=0,tlssha1=1,tracebacklabels=0,updatemaxprocs=0,urlstrictcolons=0,x509sha256skid=0,x509sslcertoverrideplatform=0"
	case "go1.24.13":
		// Go 1.24.13 is permitted only for the minimum source-compatibility
		// test. Production entrypoints reject it before artifact validation.
	default:
		return fmt.Errorf("unsupported Go builder version %q", builderGoVersion)
	}
	switch item.goarch {
	case "amd64":
		wantSettings["GOAMD64"] = "v1"
	case "arm64":
		wantSettings["GOARM64"] = "v8.0"
	}
	for key, want := range wantSettings {
		got, ok := settings[key]
		if !ok {
			return fmt.Errorf("Go build setting %s is absent; want %q", key, want)
		}
		if got != want {
			return fmt.Errorf("Go build setting %s is %q; want %q", key, got, want)
		}
	}
	for key, got := range settings {
		if _, ok := wantSettings[key]; !ok {
			return fmt.Errorf("unexpected Go build setting %q=%q", key, got)
		}
	}
	if info.Main.Version != "(devel)" || info.Main.Sum != "" {
		return fmt.Errorf("main module identity is version %q with sum %q; snapshot builds require (devel) with no module sum", info.Main.Version, info.Main.Sum)
	}
	buildID, err := readGoBuildID(binaryData)
	if err != nil {
		return fmt.Errorf("read structured Go build ID: %w", err)
	}
	wantBuildID := expectedBuildID(version, item, epoch, commit, tree, builderGoVersion)
	if buildID != wantBuildID {
		return fmt.Errorf("structured Go build ID is %q; want release contract %q", buildID, wantBuildID)
	}
	if err := checkStrippedBinary(binaryData, item.goos); err != nil {
		return err
	}
	expectedIdentity := strings.Join([]string{"leaguebridge-release", version, item.goos, item.goarch}, ":")
	if occurrences := bytes.Count(binaryData, []byte(expectedIdentity)); occurrences != 1 {
		return fmt.Errorf("release identity %q occurs %d times; want exactly once", expectedIdentity, occurrences)
	}
	embeddedScorecard := readiness.EmbeddedJSON()
	if occurrences := bytes.Count(binaryData, embeddedScorecard); occurrences != 1 {
		return fmt.Errorf("exact embedded readiness scorecard occurs %d times; want exactly once", occurrences)
	}
	repositoryEvidenceVerification := readiness.ExpectedRepositoryEvidenceVerification()
	if occurrences := bytes.Count(binaryData, []byte(repositoryEvidenceVerification)); occurrences != 1 {
		return fmt.Errorf("build-time repository evidence verification occurs %d times; want exactly once", occurrences)
	}
	return nil
}

func checkBinaryContainer(binaryData []byte, item artifact) error {
	switch item.goos {
	case "linux", "freebsd", "openbsd", "netbsd", "dragonfly":
		if len(binaryData) < 6 || !bytes.Equal(binaryData[:4], []byte{0x7f, 'E', 'L', 'F'}) {
			return errors.New("ELF magic is missing")
		}
		if class := elf.Class(binaryData[4]); class != elf.ELFCLASS64 {
			return fmt.Errorf("ELF class is %s; want %s", class, elf.ELFCLASS64)
		}
		if dataEncoding := elf.Data(binaryData[5]); dataEncoding != elf.ELFDATA2LSB {
			return fmt.Errorf("ELF data encoding is %s; want %s", dataEncoding, elf.ELFDATA2LSB)
		}
		file, err := elf.NewFile(bytes.NewReader(binaryData))
		if err != nil {
			return fmt.Errorf("parse ELF executable: %w", err)
		}
		defer file.Close()
		if file.Type != elf.ET_EXEC {
			return fmt.Errorf("ELF type is %s; want %s", file.Type, elf.ET_EXEC)
		}
		wantOSABI := map[string]elf.OSABI{
			"linux":     elf.ELFOSABI_NONE,
			"freebsd":   elf.ELFOSABI_FREEBSD,
			"openbsd":   elf.ELFOSABI_OPENBSD,
			"netbsd":    elf.ELFOSABI_NETBSD,
			"dragonfly": elf.ELFOSABI_NONE,
		}[item.goos]
		if file.OSABI != wantOSABI {
			return fmt.Errorf("ELF OSABI is %s; want %s for %s", file.OSABI, wantOSABI, item.goos)
		}
		if file.ABIVersion != 0 {
			return fmt.Errorf("ELF ABI version is %d; want 0", file.ABIVersion)
		}
		wantMachine := map[string]elf.Machine{
			"amd64": elf.EM_X86_64,
			"arm64": elf.EM_AARCH64,
		}[item.goarch]
		if wantMachine == 0 {
			return fmt.Errorf("unsupported ELF release architecture %q", item.goarch)
		}
		if file.Machine != wantMachine {
			return fmt.Errorf("ELF machine is %s; want %s for %s", file.Machine, wantMachine, item.goarch)
		}
		return nil
	default:
		return fmt.Errorf("unsupported release operating system %q", item.goos)
	}
}

func expectedBuildID(version string, item artifact, epoch int64, commit, tree, builderGoVersion string) string {
	contract := strings.Join([]string{
		"leaguebridge-release-contract-v4",
		version,
		item.goos,
		item.goarch,
		strconv.FormatInt(epoch, 10),
		commit,
		tree,
		builderGoVersion,
		architectureTuning(item.goarch),
		packageinfo.ProductionDependencyIdentity,
	}, "|")
	digest := sha256.Sum256([]byte(contract))
	return "leaguebridge-build-v4-" + hex.EncodeToString(digest[:])
}

func architectureTuning(goarch string) string {
	switch goarch {
	case "amd64":
		return "goamd64=v1"
	case "arm64":
		return "goarm64=v8.0"
	default:
		return ""
	}
}

func readGoBuildID(binaryData []byte) (string, error) {
	if len(binaryData) >= 4 && bytes.Equal(binaryData[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return readELFGoBuildID(binaryData)
	}
	return readRawGoBuildID(binaryData), nil
}

func readELFGoBuildID(binaryData []byte) (string, error) {
	file, err := elf.NewFile(bytes.NewReader(binaryData))
	if err != nil {
		return "", err
	}
	defer file.Close()
	for _, program := range file.Progs {
		if program.Type != elf.PT_NOTE || program.Filesz < 16 || program.Filesz > uint64(maxSBOMSize) {
			continue
		}
		data := make([]byte, program.Filesz)
		if _, err := program.ReadAt(data, 0); err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		for len(data) >= 16 {
			nameSize := file.ByteOrder.Uint32(data[0:4])
			valueSize := file.ByteOrder.Uint32(data[4:8])
			noteType := file.ByteOrder.Uint32(data[8:12])
			alignedName := (uint64(nameSize) + 3) &^ 3
			alignedValue := (uint64(valueSize) + 3) &^ 3
			total := uint64(12) + alignedName + alignedValue
			if total > uint64(len(data)) || nameSize > uint32(len(data)-12) {
				return "", errors.New("malformed ELF note")
			}
			nameEnd := 12 + int(nameSize)
			valueStart := 12 + int(alignedName)
			valueEnd := valueStart + int(valueSize)
			if noteType == 4 && bytes.Equal(data[12:nameEnd], []byte("Go\x00\x00")) {
				return string(data[valueStart:valueEnd]), nil
			}
			data = data[total:]
		}
	}
	return "", errors.New("Go build ID note is missing")
}

func readRawGoBuildID(binaryData []byte) string {
	const readLimit = 32 << 10
	if len(binaryData) > readLimit {
		binaryData = binaryData[:readLimit]
	}
	prefix := []byte("\xff Go build ID: \"")
	suffix := []byte("\"\n \xff")
	start := bytes.Index(binaryData, prefix)
	if start < 0 {
		return ""
	}
	start += len(prefix)
	end := bytes.Index(binaryData[start:], suffix)
	if end < 0 {
		return ""
	}
	return string(binaryData[start : start+end])
}

func checkStrippedBinary(binaryData []byte, goos string) error {
	file, err := elf.NewFile(bytes.NewReader(binaryData))
	if err != nil {
		return fmt.Errorf("parse ELF executable: %w", err)
	}
	defer file.Close()
	if file.Section(".symtab") != nil {
		return errors.New("ELF executable retains a symbol table; canonical -s was not applied")
	}
	for _, section := range file.Sections {
		if strings.HasPrefix(section.Name, ".debug") {
			return fmt.Errorf("ELF executable retains DWARF section %q; canonical -w was not applied", section.Name)
		}
	}
	return nil
}

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	DocumentDescribes []string           `json:"documentDescribes"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	Name                  string            `json:"name"`
	SPDXID                string            `json:"SPDXID"`
	VersionInfo           string            `json:"versionInfo,omitempty"`
	PackageFileName       string            `json:"packageFileName,omitempty"`
	DownloadLocation      string            `json:"downloadLocation"`
	FilesAnalyzed         bool              `json:"filesAnalyzed"`
	PrimaryPackagePurpose string            `json:"primaryPackagePurpose,omitempty"`
	BuiltDate             string            `json:"builtDate,omitempty"`
	LicenseConcluded      string            `json:"licenseConcluded"`
	LicenseDeclared       string            `json:"licenseDeclared"`
	LicenseComments       string            `json:"licenseComments"`
	CopyrightText         string            `json:"copyrightText"`
	Checksums             []spdxChecksum    `json:"checksums,omitempty"`
	ExternalRefs          []spdxExternalRef `json:"externalRefs,omitempty"`
	Comment               string            `json:"comment,omitempty"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	Comment            string `json:"comment,omitempty"`
}

func checkSBOM(data, binaryData []byte, item artifact, version string, epoch int64, binaryHash string) error {
	expected, err := expectedSBOM(binaryData, item, version, epoch, binaryHash)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, expected) {
		return errors.New("document does not exactly match the build-info-derived SPDX component and relationship inventory")
	}
	return nil
}

func expectedSBOM(binaryData []byte, item artifact, version string, epoch int64, binaryHash string) ([]byte, error) {
	info, err := buildinfo.Read(bytes.NewReader(binaryData))
	if err != nil {
		return nil, fmt.Errorf("read Go build info for expected SBOM: %w", err)
	}
	if info.Main.Path != mainModulePath || info.Main.Replace != nil {
		return nil, errors.New("binary build information does not match the main-module release contract")
	}
	dependency, err := canonicalProductionDependency(info.Deps)
	if err != nil {
		return nil, fmt.Errorf("binary build information: %w", err)
	}
	const (
		artifactID  = "SPDXRef-Package-LeagueBridge"
		toolchainID = "SPDXRef-Package-GoToolchain"
		mainID      = "SPDXRef-Package-GoModule-Main"
		licenseNote = "License data was not analyzed from source files; NOASSERTION is intentional."
	)
	newPackage := func(name, id, packageVersion, purpose, comment string) spdxPackage {
		return spdxPackage{
			Name:                  name,
			SPDXID:                id,
			VersionInfo:           packageVersion,
			DownloadLocation:      "NOASSERTION",
			FilesAnalyzed:         false,
			PrimaryPackagePurpose: purpose,
			LicenseConcluded:      "NOASSERTION",
			LicenseDeclared:       "NOASSERTION",
			LicenseComments:       licenseNote,
			CopyrightText:         "NOASSERTION",
			Comment:               comment,
		}
	}
	name := strings.Join([]string{"leaguebridge", version, item.goos, item.goarch}, "-")
	created := time.Unix(epoch, 0).UTC().Format(time.RFC3339)
	artifactPackage := newPackage("leaguebridge", artifactID, version, "APPLICATION", "Release binary package; the SHA-256 checksum covers the exact executable bytes.")
	artifactPackage.PackageFileName = item.binaryName
	artifactPackage.BuiltDate = created
	artifactPackage.Checksums = []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: binaryHash}}
	artifactPackage.ExternalRefs = []spdxExternalRef{{
		ReferenceCategory: "PACKAGE-MANAGER",
		ReferenceType:     "purl",
		ReferenceLocator:  "pkg:generic/leaguebridge@" + escapePURL(version),
	}}
	dependencyID := productionDependencySPDXID(dependency)
	dependencyPackage := newPackage(
		dependency.Path,
		dependencyID,
		dependency.Version,
		"LIBRARY",
		"Compiled Go dependency module recorded in the release binary's embedded build information.",
	)
	dependencyPackage.LicenseDeclared = packageinfo.ProductionDependencyLicense
	dependencyPackage.LicenseComments = packageinfo.ProductionDependencyLicenseComment
	dependencyPackage.ExternalRefs = []spdxExternalRef{
		{
			ReferenceCategory: "PACKAGE-MANAGER",
			ReferenceType:     "purl",
			ReferenceLocator:  "pkg:golang/" + dependency.Path + "@" + escapePURL(dependency.Version),
		},
		{
			ReferenceCategory: "OTHER",
			ReferenceType:     "go-module-sum",
			ReferenceLocator:  dependency.Sum,
		},
	}
	document := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              name,
		DocumentNamespace: "https://github.com/Yunushan/leaguebridge/sbom/" + version + "/" + item.goos + "/" + item.goarch + "/" + binaryHash,
		DocumentDescribes: []string{artifactID},
		CreationInfo: spdxCreationInfo{
			Created:  created,
			Creators: []string{"Tool: leaguebridge/tools/sbom"},
		},
		Packages: []spdxPackage{
			artifactPackage,
			newPackage("Go toolchain", toolchainID, info.GoVersion, "APPLICATION", "Exact Go toolchain recorded in the release binary's embedded build information."),
			newPackage(info.Main.Path, mainID, info.Main.Version, "SOURCE", "Main Go module recorded in the release binary's embedded build information."),
			dependencyPackage,
		},
		Relationships: []spdxRelationship{
			{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: artifactID},
			{SPDXElementID: toolchainID, RelationshipType: "BUILD_TOOL_OF", RelatedSPDXElement: artifactID},
			{SPDXElementID: artifactID, RelationshipType: "GENERATED_FROM", RelatedSPDXElement: mainID},
			{SPDXElementID: mainID, RelationshipType: "DEPENDS_ON", RelatedSPDXElement: dependencyID},
		},
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode expected SPDX document: %w", err)
	}
	return append(data, '\n'), nil
}

// canonicalProductionDependency validates the complete compiled dependency
// boundary. The pinned Go 1.27 vendored build omits Sum, so a non-empty value
// is a contract mismatch. The upstream h1 is restored only after every
// observable vendored-build field matches.
func canonicalProductionDependency(dependencies []*runtimedebug.Module) (runtimedebug.Module, error) {
	if len(dependencies) != 1 {
		return runtimedebug.Module{}, fmt.Errorf(
			"release binary has %d compiled dependency modules; want exactly one approved module %s@%s",
			len(dependencies),
			packageinfo.ProductionDependencyPath,
			packageinfo.ProductionDependencyVersion,
		)
	}
	dependency := dependencies[0]
	if dependency == nil {
		return runtimedebug.Module{}, errors.New("release binary compiled dependency is nil")
	}
	if dependency.Replace != nil {
		return runtimedebug.Module{}, fmt.Errorf("compiled dependency %q unexpectedly has replacement metadata", dependency.Path)
	}
	if dependency.Path != packageinfo.ProductionDependencyPath {
		return runtimedebug.Module{}, fmt.Errorf("compiled dependency path is %q; want %q", dependency.Path, packageinfo.ProductionDependencyPath)
	}
	if dependency.Version != packageinfo.ProductionDependencyVersion {
		return runtimedebug.Module{}, fmt.Errorf("compiled dependency %q version is %q; want %q", dependency.Path, dependency.Version, packageinfo.ProductionDependencyVersion)
	}
	if dependency.Sum != "" {
		return runtimedebug.Module{}, fmt.Errorf("compiled dependency %q sum is %q; want the pinned Go 1.27 vendored-build empty value", dependency.Path, dependency.Sum)
	}
	canonical := *dependency
	canonical.Sum = packageinfo.ProductionDependencySum
	return canonical, nil
}

func productionDependencySPDXID(dependency runtimedebug.Module) string {
	identity := "dependency\x00" + dependency.Path + "\x00" + dependency.Version + "\x00" + dependency.Sum
	digest := sha256.Sum256([]byte(identity))
	return "SPDXRef-Package-GoModule-Dependency-" + hex.EncodeToString(digest[:])
}

func escapePURL(value string) string {
	return strings.ReplaceAll(url.PathEscape(value), "+", "%2B")
}
