// Package vendorintegrity verifies the complete vendored dependency graph and
// separately enforces the identity of the production cryptographic dependency.
// The lock is intentionally independent of the Go module cache so it remains
// usable in an offline exported source snapshot.
package vendorintegrity

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
)

const (
	// ModulePath, ModuleVersion, and ModuleSum identify the sole production
	// runtime dependency. They alias the release-binary allowlist so the binary
	// and vendored-source policies cannot silently drift apart.
	ModulePath    = packageinfo.ProductionDependencyPath
	ModuleVersion = packageinfo.ProductionDependencyVersion
	ModuleSum     = packageinfo.ProductionDependencySum

	// ModuleGoModSum is the checksum-database hash of the upstream go.mod.
	ModuleGoModSum = "h1:xzAOLCNug/yB62zG1bQ8uziwrIqIuxhctzJT18Q77mc="
	// VendorModuleGoVersion is the exact Go version recorded by go mod vendor.
	VendorModuleGoVersion = "1.24.0"
	// ExpectedFileCount is the exact number of files in the complete vendor
	// tree, including dependency licenses and build/test tooling dependencies.
	ExpectedFileCount = 111

	// ExpectedLockSHA256 binds the upstream module identity and sums, vendoring
	// metadata, directory inventory, and every vendored path, size, and digest.
	// It is populated only after independently verifying the v1.2.0 vendor tree.
	ExpectedLockSHA256 = "71584e216ec9597086b57c9c40d033c0db4ea1b80325369f0f7c8803fa9e665f"

	maximumMetadataSize = int64(1 << 20)
	sha256HexLength     = sha256.Size * 2
	vendorRoot          = "vendor"
	vendorModuleRoot    = vendorRoot + "/filippo.io/edwards25519"
	lockDomain          = "LeagueBridge vendored module lock\x00v1"
	thirdPartyMarker    = "Third-party notice: " + ModulePath + " " + ModuleVersion + "\n\n"
)

type fileRecord struct {
	path   string
	size   int64
	sha256 string
}

var expectedPackages = []string{
	ModulePath,
	ModulePath + "/field",
}

// Verify checks the production dependency lock beneath snapshotRoot. It does
// not use the network or the module cache.
func Verify(snapshotRoot string) error {
	if strings.TrimSpace(snapshotRoot) == "" {
		return errors.New("snapshot root is empty")
	}
	if err := fileinput.RejectSymlinkedParents(snapshotRoot); err != nil {
		return fmt.Errorf("inspect snapshot root path: %w", err)
	}
	rootInfo, err := os.Lstat(snapshotRoot)
	if err != nil {
		return fmt.Errorf("inspect snapshot root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("snapshot root is a symbolic link")
	}
	if !rootInfo.IsDir() {
		return errors.New("snapshot root is not a directory")
	}

	root, err := os.OpenRoot(snapshotRoot)
	if err != nil {
		return fmt.Errorf("open snapshot root: %w", err)
	}
	defer root.Close()
	openedRootInfo, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect opened snapshot root: %w", err)
	}
	if !openedRootInfo.IsDir() || !os.SameFile(rootInfo, openedRootInfo) {
		return errors.New("snapshot root changed while opening")
	}

	for _, directory := range []string{vendorRoot, "vendor/filippo.io", vendorModuleRoot} {
		if err := verifyDirectory(root, directory); err != nil {
			return err
		}
	}

	goMod, err := readRegularBounded(root, "go.mod", maximumMetadataSize)
	if err != nil {
		return fmt.Errorf("read go.mod: %w", err)
	}
	if err := verifyGoMod(goMod); err != nil {
		return fmt.Errorf("verify go.mod: %w", err)
	}
	if err := verifyExactMetadata("go.mod", goMod); err != nil {
		return err
	}

	goSum, err := readRegularBounded(root, "go.sum", maximumMetadataSize)
	if err != nil {
		return fmt.Errorf("read go.sum: %w", err)
	}
	if err := verifyGoSum(goSum); err != nil {
		return fmt.Errorf("verify go.sum: %w", err)
	}
	if err := verifyExactMetadata("go.sum", goSum); err != nil {
		return err
	}

	modules, err := readRegularBounded(root, "vendor/modules.txt", maximumMetadataSize)
	if err != nil {
		return fmt.Errorf("read vendor/modules.txt: %w", err)
	}
	if err := verifyModulesMetadata(modules); err != nil {
		return fmt.Errorf("verify vendor/modules.txt: %w", err)
	}
	if err := verifyExactMetadata("vendor/modules.txt", modules); err != nil {
		return err
	}

	projectLicense, err := readRegularBounded(root, "LICENSE", maximumMetadataSize)
	if err != nil {
		return fmt.Errorf("read LICENSE: %w", err)
	}
	upstreamLicense, err := readRegularBounded(root, vendorModuleRoot+"/LICENSE", maximumMetadataSize)
	if err != nil {
		return fmt.Errorf("read upstream dependency LICENSE: %w", err)
	}
	if err := verifyBundledLicenseNotice(projectLicense, upstreamLicense); err != nil {
		return fmt.Errorf("verify LICENSE: %w", err)
	}

	records, err := verifyVendorTree(root)
	if err != nil {
		return err
	}
	digest := lockDigest(expectedMetadata, records)
	if digest != ExpectedLockSHA256 {
		return fmt.Errorf("aggregate vendor lock digest is %s; want %s", digest, ExpectedLockSHA256)
	}
	return nil
}

func verifyBundledLicenseNotice(projectLicense, upstreamLicense []byte) error {
	marker := []byte(thirdPartyMarker)
	if count := bytes.Count(projectLicense, marker); count != 1 {
		return fmt.Errorf("found %d exact third-party license markers; want 1", count)
	}
	start := bytes.Index(projectLicense, marker) + len(marker)
	if !bytes.Equal(projectLicense[start:], upstreamLicense) {
		return errors.New("bundled third-party license text does not exactly match the locked upstream LICENSE")
	}
	return nil
}

func verifyDirectory(root *os.Root, name string) error {
	platformName := filepath.FromSlash(name)
	before, err := root.Lstat(platformName)
	if err != nil {
		return fmt.Errorf("inspect directory %q: %w", name, err)
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("directory %q is a symbolic link", name)
	}
	if !before.IsDir() {
		return fmt.Errorf("path %q is not a directory", name)
	}
	opened, err := root.Open(platformName)
	if err != nil {
		return fmt.Errorf("open directory %q: %w", name, err)
	}
	defer opened.Close()
	after, err := opened.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened directory %q: %w", name, err)
	}
	if !after.IsDir() || !os.SameFile(before, after) {
		return fmt.Errorf("directory %q changed while opening", name)
	}
	return nil
}

func readRegularBounded(root *os.Root, name string, maximum int64) ([]byte, error) {
	platformName := filepath.FromSlash(name)
	before, err := root.Lstat(platformName)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%q is a symbolic link", name)
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", name)
	}
	if before.Size() > maximum {
		return nil, fmt.Errorf("%q exceeds %d bytes", name, maximum)
	}

	file, err := root.Open(platformName)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("%q changed while opening", name)
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maximum {
		return nil, fmt.Errorf("%q exceeds %d bytes", name, maximum)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(opened, after) || after.Size() != int64(len(body)) || !after.ModTime().Equal(opened.ModTime()) {
		return nil, fmt.Errorf("%q changed while reading", name)
	}
	return body, nil
}

func verifyGoMod(data []byte) error {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), int(maximumMetadataSize))
	block := ""
	requirements := 0
	for scanner.Scan() {
		raw := scanner.Text()
		code, comment, _ := strings.Cut(raw, "//")
		line := strings.TrimSpace(code)
		if line == "" {
			continue
		}
		if block != "" {
			if line == ")" {
				block = ""
				continue
			}
			fields := strings.Fields(line)
			switch block {
			case "require":
				if len(fields) > 0 && fields[0] == ModulePath {
					if err := validateRequirement(fields, comment); err != nil {
						return err
					}
					requirements++
				}
			case "replace", "exclude":
				if containsModuleToken(fields) {
					return fmt.Errorf("%s directive is not permitted for %s", block, ModulePath)
				}
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "require", "replace", "exclude":
			if len(fields) == 2 && fields[1] == "(" {
				block = fields[0]
				continue
			}
			if fields[0] == "require" && len(fields) > 1 && fields[1] == ModulePath {
				if err := validateRequirement(fields[1:], comment); err != nil {
					return err
				}
				requirements++
				continue
			}
			if fields[0] != "require" && containsModuleToken(fields[1:]) {
				return fmt.Errorf("%s directive is not permitted for %s", fields[0], ModulePath)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan go.mod: %w", err)
	}
	if block != "" {
		return fmt.Errorf("unterminated %s block", block)
	}
	if requirements != 1 {
		return fmt.Errorf("found %d direct requirements for %s; want exactly 1", requirements, ModulePath)
	}
	return nil
}

func validateRequirement(fields []string, comment string) error {
	if len(fields) != 2 {
		return fmt.Errorf("requirement for %s must contain exactly a path and version", ModulePath)
	}
	if fields[1] != ModuleVersion {
		return fmt.Errorf("requirement for %s is %s; want %s", ModulePath, fields[1], ModuleVersion)
	}
	for _, field := range strings.Fields(comment) {
		if field == "indirect" {
			return fmt.Errorf("requirement for %s must be direct", ModulePath)
		}
	}
	return nil
}

func containsModuleToken(fields []string) bool {
	for _, field := range fields {
		if field == ModulePath {
			return true
		}
	}
	return false
}

func verifyGoSum(data []byte) error {
	sourceMatches := 0
	goModMatches := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), int(maximumMetadataSize))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != ModulePath {
			continue
		}
		if len(fields) != 3 {
			return fmt.Errorf("malformed checksum line for %s", ModulePath)
		}
		switch fields[1] {
		case ModuleVersion:
			sourceMatches++
			if fields[2] != ModuleSum {
				return fmt.Errorf("module sum for %s %s is %s; want %s", ModulePath, ModuleVersion, fields[2], ModuleSum)
			}
		case ModuleVersion + "/go.mod":
			goModMatches++
			if fields[2] != ModuleGoModSum {
				return fmt.Errorf("go.mod sum for %s %s is %s; want %s", ModulePath, ModuleVersion, fields[2], ModuleGoModSum)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan go.sum: %w", err)
	}
	if sourceMatches != 1 {
		return fmt.Errorf("found %d source sums for %s %s; want exactly 1", sourceMatches, ModulePath, ModuleVersion)
	}
	if goModMatches != 1 {
		return fmt.Errorf("found %d go.mod sums for %s %s; want exactly 1", goModMatches, ModulePath, ModuleVersion)
	}
	return nil
}

func verifyModulesMetadata(data []byte) error {
	lines := strings.Split(string(data), "\n")
	start := -1
	matches := 0
	expectedHeader := "# " + ModulePath + " " + ModuleVersion
	for index, line := range lines {
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "# "))
		if len(fields) == 0 || fields[0] != ModulePath {
			continue
		}
		matches++
		if line != expectedHeader {
			return fmt.Errorf("module header is %q; want %q", line, expectedHeader)
		}
		start = index
	}
	if matches != 1 {
		return fmt.Errorf("found %d metadata stanzas for %s; want exactly 1", matches, ModulePath)
	}

	end := len(lines)
	for index := start + 1; index < len(lines); index++ {
		if strings.HasPrefix(lines[index], "# ") {
			end = index
			break
		}
	}
	actual := lines[start:end]
	expected := []string{
		expectedHeader,
		"## explicit; go " + VendorModuleGoVersion,
	}
	expected = append(expected, expectedPackages...)
	if len(actual) != len(expected) {
		return fmt.Errorf("metadata stanza for %s has %d lines; want %d", ModulePath, len(actual), len(expected))
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return fmt.Errorf("metadata stanza line %d is %q; want %q", index+1, actual[index], expected[index])
		}
	}
	return nil
}

func verifyExactMetadata(name string, data []byte) error {
	for _, record := range expectedMetadata {
		if record.path != name {
			continue
		}
		if int64(len(data)) != record.size {
			return fmt.Errorf("metadata file %q has size %d; want %d", name, len(data), record.size)
		}
		digestBytes := sha256.Sum256(data)
		digest := hex.EncodeToString(digestBytes[:])
		if digest != record.sha256 {
			return fmt.Errorf("metadata file %q has SHA-256 %s; want %s", name, digest, record.sha256)
		}
		return nil
	}
	return fmt.Errorf("metadata file %q is absent from the vendor lock", name)
}

func verifyVendorTree(root *os.Root) ([]fileRecord, error) {
	expectedFileByPath := make(map[string]fileRecord, len(expectedFiles))
	for _, record := range expectedFiles {
		expectedFileByPath[record.path] = record
	}
	expectedDirectorySet := make(map[string]struct{}, len(expectedDirectories))
	for _, directory := range expectedDirectories {
		expectedDirectorySet[directory] = struct{}{}
	}
	seenFiles := make(map[string]struct{}, len(expectedFiles))
	seenDirectories := make(map[string]struct{}, len(expectedDirectories))
	records := make([]fileRecord, 0, len(expectedFiles))

	var walk func(string, string) error
	walk = func(repositoryDirectory, moduleDirectory string) error {
		opened, before, err := openCheckedDirectory(root, repositoryDirectory)
		if err != nil {
			return err
		}
		entries, readErr := opened.ReadDir(-1)
		after, statErr := opened.Stat()
		closeErr := opened.Close()
		if readErr != nil {
			return fmt.Errorf("read vendor directory %q: %w", moduleDirectory, readErr)
		}
		if statErr != nil {
			return fmt.Errorf("reinspect vendor directory %q: %w", moduleDirectory, statErr)
		}
		if !after.IsDir() || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
			return fmt.Errorf("vendor directory %q changed while reading", moduleDirectory)
		}
		if closeErr != nil {
			return fmt.Errorf("close vendor directory %q: %w", moduleDirectory, closeErr)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			moduleName := path.Join(moduleDirectory, entry.Name())
			repositoryName := path.Join(repositoryDirectory, entry.Name())
			info, err := root.Lstat(filepath.FromSlash(repositoryName))
			if err != nil {
				return fmt.Errorf("inspect vendored path %q: %w", moduleName, err)
			}
			if err := rejectVendoredSymlink(moduleName, info.Mode()); err != nil {
				return err
			}
			if info.IsDir() {
				if _, isFile := expectedFileByPath[moduleName]; isFile {
					return fmt.Errorf("vendored path %q is a directory; want a regular file", moduleName)
				}
				if _, ok := expectedDirectorySet[moduleName]; !ok {
					return fmt.Errorf("unexpected vendored directory %q", moduleName)
				}
				seenDirectories[moduleName] = struct{}{}
				if err := walk(repositoryName, moduleName); err != nil {
					return err
				}
				continue
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("vendored path %q is not a regular file", moduleName)
			}
			if _, isDirectory := expectedDirectorySet[moduleName]; isDirectory {
				return fmt.Errorf("vendored path %q is a regular file; want a directory", moduleName)
			}
			expected, ok := expectedFileByPath[moduleName]
			if !ok {
				return fmt.Errorf("unexpected vendored file %q", moduleName)
			}
			body, err := readRegularBounded(root, repositoryName, expected.size)
			if err != nil {
				return fmt.Errorf("read vendored file %q: %w", moduleName, err)
			}
			if int64(len(body)) != expected.size {
				return fmt.Errorf("vendored file %q has size %d; want %d", moduleName, len(body), expected.size)
			}
			digestBytes := sha256.Sum256(body)
			digest := hex.EncodeToString(digestBytes[:])
			if digest != expected.sha256 {
				return fmt.Errorf("vendored file %q has SHA-256 %s; want %s", moduleName, digest, expected.sha256)
			}
			seenFiles[moduleName] = struct{}{}
			records = append(records, fileRecord{path: moduleName, size: int64(len(body)), sha256: digest})
		}
		return nil
	}
	if err := walk(vendorRoot, ""); err != nil {
		return nil, err
	}
	for _, directory := range expectedDirectories {
		if _, ok := seenDirectories[directory]; !ok {
			return nil, fmt.Errorf("missing vendored directory %q", directory)
		}
	}
	for _, record := range expectedFiles {
		if _, ok := seenFiles[record.path]; !ok {
			return nil, fmt.Errorf("missing vendored file %q", record.path)
		}
	}
	if len(records) != ExpectedFileCount {
		return nil, fmt.Errorf("verified %d vendored files; want %d", len(records), ExpectedFileCount)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].path < records[j].path })
	return records, nil
}

func rejectVendoredSymlink(name string, mode os.FileMode) error {
	if mode&os.ModeSymlink != 0 {
		return fmt.Errorf("vendored path %q is a symbolic link", name)
	}
	return nil
}

func openCheckedDirectory(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	platformName := filepath.FromSlash(name)
	before, err := root.Lstat(platformName)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect vendored directory %q: %w", name, err)
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("vendored directory %q is a symbolic link", name)
	}
	if !before.IsDir() {
		return nil, nil, fmt.Errorf("vendored path %q is not a directory", name)
	}
	opened, err := root.Open(platformName)
	if err != nil {
		return nil, nil, fmt.Errorf("open vendored directory %q: %w", name, err)
	}
	after, err := opened.Stat()
	if err != nil {
		opened.Close()
		return nil, nil, fmt.Errorf("inspect opened vendored directory %q: %w", name, err)
	}
	if !after.IsDir() || !os.SameFile(before, after) {
		opened.Close()
		return nil, nil, fmt.Errorf("vendored directory %q changed while opening", name)
	}
	return opened, after, nil
}

func lockDigest(metadata, records []fileRecord) string {
	hash := sha256.New()
	writeLockField(hash, "domain", lockDomain)
	writeLockField(hash, "module-path", ModulePath)
	writeLockField(hash, "module-version", ModuleVersion)
	writeLockField(hash, "module-sum", ModuleSum)
	writeLockField(hash, "module-go-mod-sum", ModuleGoModSum)
	writeLockField(hash, "vendor-module-go-version", VendorModuleGoVersion)
	writeLockField(hash, "vendor-root", vendorRoot)
	writeLockField(hash, "production-vendor-module-root", vendorModuleRoot)
	for _, packagePath := range expectedPackages {
		writeLockField(hash, "package", packagePath)
	}
	for _, directory := range expectedDirectories {
		writeLockField(hash, "directory", directory)
	}
	for _, record := range metadata {
		writeLockField(hash, "metadata-path", record.path)
		writeLockField(hash, "metadata-size", fmt.Sprintf("%d", record.size))
		writeLockField(hash, "metadata-sha256", record.sha256)
	}
	for _, record := range records {
		writeLockField(hash, "file-path", record.path)
		writeLockField(hash, "file-size", fmt.Sprintf("%d", record.size))
		writeLockField(hash, "file-sha256", record.sha256)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func writeLockField(destination io.Writer, label, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(label)))
	destination.Write(length[:])
	destination.Write([]byte(label))
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	destination.Write(length[:])
	destination.Write([]byte(value))
}
