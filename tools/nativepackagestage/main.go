// Command nativepackagestage prepares a portable Unix release archive for a
// separately governed native package builder.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/nativepackage"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
)

const (
	maxArchiveSize   = int64(256 << 20)
	maxBinarySize    = int64(128 << 20)
	maxMetadataSize  = int64(1 << 20)
	maxAuxiliarySize = int64(8 << 20)
)

var archiveMembers = map[string]struct{}{
	"LICENSE":                     {},
	"PACKAGE-MANIFEST.json":       {},
	"README.md":                   {},
	"SBOM.spdx.json":              {},
	"install.sh":                  {},
	"leaguebridge":                {},
	"linux-bsd-client-smoke.sh":   {},
	"linux-bsd-remote-session.sh": {},
	"uninstall.sh":                {},
}

var canonicalUnixArchiveOrder = []string{
	"LICENSE",
	"PACKAGE-MANIFEST.json",
	"README.md",
	"SBOM.spdx.json",
	"install.sh",
	"leaguebridge",
	"linux-bsd-client-smoke.sh",
	"linux-bsd-remote-session.sh",
	"uninstall.sh",
}

func main() {
	archivePath := flag.String("archive", "", "portable Unix release tar.gz to stage")
	familyRaw := flag.String("family", "", "native package family")
	output := flag.String("output", "", "new staging directory to create")
	flag.Parse()
	if flag.NArg() != 0 {
		fatalf("positional arguments are not accepted")
	}
	if *archivePath == "" || *familyRaw == "" || *output == "" {
		fatalf("archive, family, and output are required")
	}
	if err := stage(*archivePath, *output, nativepackage.Family(*familyRaw)); err != nil {
		fatalf("%v", err)
	}
	fmt.Fprintf(os.Stdout, "staged %s package inputs in %s\n", *familyRaw, *output)
}

type sourceArchive struct {
	manifest     packageinfo.Manifest
	manifestData []byte
	bodies       map[string][]byte
}

func stage(archivePath, output string, family nativepackage.Family) (returnErr error) {
	archiveAbsolute, err := filepath.Abs(archivePath)
	if err != nil {
		return fmt.Errorf("resolve archive path: %w", err)
	}
	archiveParent, err := fileinput.OpenDirectoryRoot(filepath.Dir(archiveAbsolute))
	if err != nil {
		return fmt.Errorf("open archive parent: %w", err)
	}
	defer archiveParent.Close()
	archiveData, err := fileinput.ReadRegularBoundedFromRoot(archiveParent, filepath.Base(archiveAbsolute), maxArchiveSize)
	if err != nil {
		return fmt.Errorf("read archive: %w", err)
	}
	source, err := readSourceArchive(archiveAbsolute, archiveData)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(archiveData)
	staging, err := nativepackage.Build(source.manifest, source.manifestData, hex.EncodeToString(digest[:]), family)
	if err != nil {
		return err
	}
	stagingData, err := nativepackage.Marshal(staging)
	if err != nil {
		return fmt.Errorf("marshal staging manifest: %w", err)
	}

	outputAbsolute, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve output: %w", err)
	}
	if err := fileinput.RejectSymlinkedParents(outputAbsolute); err != nil {
		return fmt.Errorf("output path: %w", err)
	}
	if info, statErr := os.Lstat(outputAbsolute); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("output must not be a symlink")
		}
		return errors.New("output already exists; staging never overwrites a directory")
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect output: %w", statErr)
	}
	parent := filepath.Dir(outputAbsolute)
	parentInfo, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("inspect output parent: %w", err)
	}
	if !parentInfo.IsDir() {
		return errors.New("output parent is not a directory")
	}
	parentRoot, err := fileinput.OpenDirectoryRoot(parent)
	if err != nil {
		return fmt.Errorf("open output parent: %w", err)
	}
	defer parentRoot.Close()
	outputName := filepath.Base(outputAbsolute)
	if outputName == "" || outputName == "." || outputName == string(filepath.Separator) {
		return errors.New("output is not a regular child path")
	}

	temporaryRoot, temporaryName, err := fileinput.CreateTempDirectory(parentRoot, ".leaguebridge-native-package-", 0o700)
	if err != nil {
		return fmt.Errorf("create private staging directory: %w", err)
	}
	defer func() {
		if temporaryRoot != nil {
			_ = temporaryRoot.Close()
		}
	}()
	complete := false
	defer func() {
		if !complete {
			_ = fileinput.RemoveAllInRoot(parentRoot, temporaryName)
		}
	}()

	if err := temporaryRoot.Mkdir("root", 0o755); err != nil {
		return fmt.Errorf("create package root: %w", err)
	}
	root, err := temporaryRoot.OpenRoot("root")
	if err != nil {
		return fmt.Errorf("open package root: %w", err)
	}
	defer func() {
		if root != nil {
			_ = root.Close()
		}
	}()
	for _, entry := range staging.Payload {
		body, ok := source.bodies[entry.SourcePath]
		if entry.SourcePath == "PACKAGE-MANIFEST.json" {
			body = source.manifestData
			ok = true
		}
		if !ok {
			return fmt.Errorf("source archive is missing staged member %q", entry.SourcePath)
		}
		if int64(len(body)) != entry.Size {
			return fmt.Errorf("staged member %q size changed", entry.SourcePath)
		}
		bodyDigest := sha256.Sum256(body)
		if hex.EncodeToString(bodyDigest[:]) != entry.SHA256 {
			return fmt.Errorf("staged member %q digest changed", entry.SourcePath)
		}
		destination, err := rootedRelativePath(entry.InstallPath)
		if err != nil {
			return fmt.Errorf("stage member %q: %w", entry.SourcePath, err)
		}
		if err := ensureDirectoryInRoot(root, filepath.Dir(destination)); err != nil {
			return fmt.Errorf("create directory for %q: %w", entry.SourcePath, err)
		}
		mode, err := parseMode(entry.Mode)
		if err != nil {
			return fmt.Errorf("stage member %q: %w", entry.SourcePath, err)
		}
		if err := writeExclusiveInRoot(root, destination, body, mode); err != nil {
			return fmt.Errorf("write staged member %q: %w", entry.SourcePath, err)
		}
	}
	if err := root.Close(); err != nil {
		return fmt.Errorf("close package root: %w", err)
	}
	root = nil
	if err := writeExclusiveInRoot(temporaryRoot, nativepackage.StagingManifestName, stagingData, 0o644); err != nil {
		return fmt.Errorf("write staging manifest: %w", err)
	}
	if _, err := nativepackage.VerifyStagingRoot(temporaryRoot); err != nil {
		return fmt.Errorf("verify staged tree before publication: %w", err)
	}
	if err := temporaryRoot.Close(); err != nil {
		return fmt.Errorf("close staging directory: %w", err)
	}
	temporaryRoot = nil
	if err := fileinput.RenameInRoot(parentRoot, temporaryName, outputName); err != nil {
		return fmt.Errorf("publish staging directory: %w", err)
	}
	complete = true
	return nil
}

func readSourceArchive(archivePath string, archiveData []byte) (sourceArchive, error) {
	compressed := bytes.NewReader(archiveData)
	gzipReader, err := gzip.NewReader(compressed)
	if err != nil {
		return sourceArchive{}, fmt.Errorf("open gzip stream: %w", err)
	}
	gzipReader.Multistream(false)
	if gzipReader.Header.OS != 255 || !gzipReader.Header.ModTime.IsZero() || gzipReader.Header.Name != "" || gzipReader.Header.Comment != "" || len(gzipReader.Header.Extra) != 0 {
		_ = gzipReader.Close()
		return sourceArchive{}, errors.New("gzip header is not canonical")
	}
	tarReader := tar.NewReader(gzipReader)
	bodies := make(map[string][]byte, len(archiveMembers))
	var archiveTime *time.Time
	var total int64
	nextMember := 0
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = gzipReader.Close()
			return sourceArchive{}, fmt.Errorf("read tar header: %w", err)
		}
		if _, ok := archiveMembers[header.Name]; !ok {
			_ = gzipReader.Close()
			return sourceArchive{}, fmt.Errorf("unexpected archive member %q", header.Name)
		}
		if _, duplicate := bodies[header.Name]; duplicate {
			_ = gzipReader.Close()
			return sourceArchive{}, fmt.Errorf("duplicate archive member %q", header.Name)
		}
		if nextMember >= len(canonicalUnixArchiveOrder) || header.Name != canonicalUnixArchiveOrder[nextMember] {
			_ = gzipReader.Close()
			return sourceArchive{}, fmt.Errorf("archive member %q is out of canonical order", header.Name)
		}
		nextMember++
		if header.Format != tar.FormatUSTAR || header.Typeflag != tar.TypeReg || header.Uid != 0 || header.Gid != 0 {
			_ = gzipReader.Close()
			return sourceArchive{}, fmt.Errorf("archive member %q has non-canonical file metadata", header.Name)
		}
		wantMode := int64(0o644)
		if header.Name == "install.sh" || header.Name == "linux-bsd-client-smoke.sh" || header.Name == "linux-bsd-remote-session.sh" || header.Name == "uninstall.sh" || header.Name == "leaguebridge" {
			wantMode = 0o755
		}
		if header.Mode != wantMode {
			_ = gzipReader.Close()
			return sourceArchive{}, fmt.Errorf("archive member %q has mode %04o; want %04o", header.Name, header.Mode, wantMode)
		}
		memberLimit := maxAuxiliarySize
		switch header.Name {
		case "PACKAGE-MANIFEST.json", "SBOM.spdx.json":
			memberLimit = maxMetadataSize
		case "leaguebridge":
			memberLimit = maxBinarySize
		}
		if header.Size < 0 || header.Size > memberLimit || total > maxArchiveSize-header.Size {
			_ = gzipReader.Close()
			return sourceArchive{}, fmt.Errorf("archive member %q exceeds staging limits", header.Name)
		}
		body, err := io.ReadAll(io.LimitReader(tarReader, memberLimit+1))
		if err != nil {
			_ = gzipReader.Close()
			return sourceArchive{}, fmt.Errorf("read archive member %q: %w", header.Name, err)
		}
		if int64(len(body)) != header.Size {
			_ = gzipReader.Close()
			return sourceArchive{}, fmt.Errorf("archive member %q size changed", header.Name)
		}
		if archiveTime == nil {
			value := header.ModTime
			archiveTime = &value
		} else if !header.ModTime.Equal(*archiveTime) {
			_ = gzipReader.Close()
			return sourceArchive{}, errors.New("archive members do not share one timestamp")
		}
		bodies[header.Name] = body
		total += header.Size
	}
	if nextMember != len(canonicalUnixArchiveOrder) {
		_ = gzipReader.Close()
		return sourceArchive{}, fmt.Errorf("archive has %d members; want %d", nextMember, len(canonicalUnixArchiveOrder))
	}
	if _, err := io.Copy(io.Discard, gzipReader); err != nil {
		_ = gzipReader.Close()
		return sourceArchive{}, fmt.Errorf("finish gzip stream: %w", err)
	}
	if err := gzipReader.Close(); err != nil {
		return sourceArchive{}, fmt.Errorf("close gzip stream: %w", err)
	}
	if compressed.Len() != 0 {
		return sourceArchive{}, errors.New("gzip stream has trailing bytes or additional members")
	}

	manifestData, ok := bodies["PACKAGE-MANIFEST.json"]
	if !ok {
		return sourceArchive{}, errors.New("archive is missing PACKAGE-MANIFEST.json")
	}
	var manifest packageinfo.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return sourceArchive{}, fmt.Errorf("decode package manifest: %w", err)
	}
	canonicalManifest, err := packageinfo.Marshal(manifest)
	if err != nil {
		return sourceArchive{}, fmt.Errorf("marshal package manifest: %w", err)
	}
	if !bytes.Equal(manifestData, canonicalManifest) {
		return sourceArchive{}, errors.New("package manifest is not canonical")
	}
	if filepath.Base(archivePath) != manifest.Artifact.Filename {
		return sourceArchive{}, fmt.Errorf("archive filename %q does not match package manifest %q", filepath.Base(archivePath), manifest.Artifact.Filename)
	}
	if archiveTime == nil || archiveTime.Unix() != manifest.Provenance.SourceDateEpoch || archiveTime.Nanosecond() != 0 {
		return sourceArchive{}, errors.New("archive timestamp does not match package manifest SOURCE_DATE_EPOCH")
	}
	names, err := packageinfo.ExpectedPayloadNames(manifest.Target.GOOS, manifest.Target.GOARCH)
	if err != nil {
		return sourceArchive{}, fmt.Errorf("validate source target: %w", err)
	}
	payloadBodies := make(map[string][]byte, len(names))
	for _, name := range names {
		body, ok := bodies[name]
		if !ok {
			return sourceArchive{}, fmt.Errorf("archive is missing %q", name)
		}
		payloadBodies[name] = body
	}
	expectedManifest, err := packageinfo.Build(
		manifest.Version,
		manifest.Target.GOOS,
		manifest.Target.GOARCH,
		manifest.Provenance.SourceDateEpoch,
		manifest.Provenance.SourceCommit,
		manifest.Provenance.SourceTree,
		manifest.Provenance.BuilderGoVersion,
		payloadBodies,
	)
	if err != nil {
		return sourceArchive{}, fmt.Errorf("validate source package manifest: %w", err)
	}
	expectedData, err := packageinfo.Marshal(expectedManifest)
	if err != nil {
		return sourceArchive{}, fmt.Errorf("marshal expected package manifest: %w", err)
	}
	if !bytes.Equal(manifestData, expectedData) {
		return sourceArchive{}, errors.New("package manifest does not match archive payload")
	}
	if len(bodies) != len(names)+1 {
		return sourceArchive{}, fmt.Errorf("archive has %d members; want %d", len(bodies), len(names)+1)
	}
	return sourceArchive{manifest: manifest, manifestData: manifestData, bodies: bodies}, nil
}

func rootedPath(root, installPath string) (string, error) {
	relative, err := rootedRelativePath(installPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, relative), nil
}

func rootedRelativePath(installPath string) (string, error) {
	if !strings.HasPrefix(installPath, "/") {
		return "", errors.New("install path must be absolute")
	}
	relative := strings.TrimPrefix(installPath, "/")
	clean := path.Clean(relative)
	if relative == "" || clean != relative || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", errors.New("install path contains unsafe components")
	}
	return filepath.FromSlash(clean), nil
}

func ensureDirectoryInRoot(root *os.Root, directory string) error {
	if root == nil {
		return errors.New("directory root is nil")
	}
	clean := filepath.Clean(directory)
	if directory == "" || filepath.IsAbs(directory) || clean != directory || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("root-relative directory %q is unsafe", directory)
	}
	if clean == "." {
		return nil
	}
	current := ""
	for _, component := range strings.Split(clean, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("root-relative directory %q is unsafe", directory)
		}
		if current == "" {
			current = component
		} else {
			current = filepath.Join(current, component)
		}
		info, err := root.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("root-relative directory %q is a symlink", current)
			}
			if !info.IsDir() {
				return fmt.Errorf("root-relative path %q is not a directory", current)
			}
			continue
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect root-relative directory %q: %w", current, err)
		}
		if err := root.Mkdir(current, 0o755); err != nil && !os.IsExist(err) {
			return fmt.Errorf("create root-relative directory %q: %w", current, err)
		}
		created, err := root.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect created root-relative directory %q: %w", current, err)
		}
		if created.Mode()&os.ModeSymlink != 0 || !created.IsDir() {
			return fmt.Errorf("created root-relative path %q is not a directory", current)
		}
	}
	return nil
}

func parseMode(raw string) (os.FileMode, error) {
	value, err := strconv.ParseUint(raw, 8, 32)
	if err != nil || (value != 0o644 && value != 0o755) {
		return 0, fmt.Errorf("mode %q is not 0644 or 0755", raw)
	}
	return os.FileMode(value), nil
}

func writeExclusiveInRoot(root *os.Root, name string, body []byte, mode os.FileMode) (returnErr error) {
	if root == nil {
		return errors.New("directory root is nil")
	}
	clean := filepath.Clean(name)
	if name == "" || filepath.IsAbs(name) || clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("root-relative file %q is unsafe", name)
	}
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); returnErr == nil && closeErr != nil {
			returnErr = closeErr
		}
		if returnErr != nil {
			_ = root.Remove(name)
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect root-relative file %q: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("created root-relative file is not regular")
	}
	written, err := file.Write(body)
	if err != nil {
		return err
	}
	if written != len(body) {
		return io.ErrShortWrite
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	return nil
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "nativepackagestage: "+format+"\n", arguments...)
	os.Exit(2)
}
