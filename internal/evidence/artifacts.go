package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// ArtifactVerification is an opaque proof that every artifact declared by one
// exact record was re-hashed from a bounded, regular-file-only bundle.
type ArtifactVerification struct {
	recordDigest [sha256.Size]byte
	verified     bool
}

// Verified reports whether the value was produced by VerifyArtifactBundle.
func (verification ArtifactVerification) Verified() bool {
	return verification.verified
}

type declaredArtifact struct {
	context  string
	artifact Artifact
}

// VerifyArtifactBundle requires directory to contain exactly the globally
// unique artifact basenames declared by record. Every entry must be a regular,
// non-symlink file with the declared byte length and SHA-256.
func VerifyArtifactBundle(record Record, directory string) (ArtifactVerification, error) {
	return verifyArtifactBundle(record, directory, nil)
}

// verifyArtifactBundle's afterRootOpen hook exists solely so tests can replace
// the caller-visible directory after it has been pinned. Production callers
// always pass nil.
func verifyArtifactBundle(record Record, directory string, afterRootOpen func()) (verification ArtifactVerification, returnErr error) {
	if err := Validate(record); err != nil {
		return ArtifactVerification{}, fmt.Errorf("validate evidence record: %w", err)
	}
	if strings.TrimSpace(directory) == "" {
		return ArtifactVerification{}, errors.New("artifact bundle directory is required")
	}
	declared := declaredArtifacts(record)
	expected := make(map[string]Artifact, len(declared))
	for _, item := range declared {
		expected[item.artifact.Name] = item.artifact
	}

	root, directoryInfo, err := openArtifactDirectory(directory)
	if err != nil {
		return ArtifactVerification{}, err
	}
	defer func() {
		if err := root.Close(); err != nil && returnErr == nil {
			verification = ArtifactVerification{}
			returnErr = fmt.Errorf("close artifact bundle root: %w", err)
		}
	}()
	if afterRootOpen != nil {
		afterRootOpen()
	}

	names, err := verifyArtifactEntrySet(root, directoryInfo, expected)
	if err != nil {
		return ArtifactVerification{}, err
	}

	var verifiedBytes int64
	for _, name := range names {
		artifact := expected[name]
		if verifiedBytes > MaxArtifactBundleSize-artifact.SizeBytes {
			return ArtifactVerification{}, fmt.Errorf("verified artifacts exceed the %d-byte bundle limit", MaxArtifactBundleSize)
		}
		if err := verifyArtifactFile(root, artifact); err != nil {
			return ArtifactVerification{}, err
		}
		verifiedBytes += artifact.SizeBytes
	}

	// Re-enumeration catches entries added, removed, or replaced while member
	// files were being hashed. It remains rooted at the originally opened
	// directory even if the caller-visible name has since been replaced.
	if _, err := verifyArtifactEntrySet(root, directoryInfo, expected); err != nil {
		return ArtifactVerification{}, err
	}
	digest, err := artifactVerificationDigest(record)
	if err != nil {
		return ArtifactVerification{}, err
	}
	return ArtifactVerification{recordDigest: digest, verified: true}, nil
}

func openArtifactDirectory(path string) (*os.Root, os.FileInfo, error) {
	cleanPath := filepath.Clean(path)
	before, err := os.Lstat(cleanPath)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect artifact bundle directory: %w", err)
	}
	if !isPlainDirectory(before) {
		return nil, nil, fmt.Errorf("artifact bundle %s is not a non-symlink directory", path)
	}
	root, err := os.OpenRoot(cleanPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open artifact bundle directory root: %w", err)
	}
	opened, err := root.Lstat(".")
	if err != nil {
		_ = root.Close()
		return nil, nil, fmt.Errorf("inspect opened artifact bundle directory: %w", err)
	}
	if !isPlainDirectory(opened) || !sameIdentityAndSize(before, opened) {
		_ = root.Close()
		return nil, nil, fmt.Errorf("artifact bundle %s changed or is not a non-symlink directory", path)
	}
	after, err := os.Lstat(cleanPath)
	if err != nil {
		_ = root.Close()
		return nil, nil, fmt.Errorf("reinspect artifact bundle directory: %w", err)
	}
	if !isPlainDirectory(after) || !sameIdentityAndSize(opened, after) {
		_ = root.Close()
		return nil, nil, fmt.Errorf("artifact bundle %s changed or is not a non-symlink directory", path)
	}
	return root, opened, nil
}

func verifyArtifactEntrySet(root *os.Root, directoryInfo os.FileInfo, expected map[string]Artifact) ([]string, error) {
	entries, err := readArtifactDirectory(root, directoryInfo, len(expected)+1)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for index, entry := range entries {
		name := entry.Name()
		if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
			return nil, fmt.Errorf("artifact bundle entry %q is not an exact basename", name)
		}
		for previousIndex := 0; previousIndex < index; previousIndex++ {
			previous := entries[previousIndex].Name()
			if previous != name && strings.EqualFold(previous, name) {
				return nil, fmt.Errorf("artifact bundle entries %q and %q are case-colliding", previous, name)
			}
		}
	}

	seen := make(map[string]struct{}, len(entries))
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		info, err := root.Lstat(name)
		if err != nil {
			return nil, fmt.Errorf("inspect artifact %q: %w", name, err)
		}
		if !isPlainRegularFile(info) {
			return nil, fmt.Errorf("artifact bundle entry %q is not a regular non-symlink file", name)
		}
		if _, ok := expected[name]; !ok {
			return nil, fmt.Errorf("artifact bundle contains unexpected entry %q", name)
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}

	missing := make([]string, 0)
	for name := range expected {
		if _, ok := seen[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("artifact bundle is missing %q", missing[0])
	}
	return names, nil
}

func readArtifactDirectory(root *os.Root, directoryInfo os.FileInfo, limit int) ([]os.DirEntry, error) {
	before, err := root.Lstat(".")
	if err != nil {
		return nil, fmt.Errorf("inspect artifact bundle root: %w", err)
	}
	if !isPlainDirectory(before) || !sameIdentityAndSize(directoryInfo, before) {
		return nil, errors.New("artifact bundle root changed or is not a directory")
	}

	directory, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open artifact bundle root for enumeration: %w", err)
	}
	opened, statErr := directory.Stat()
	if statErr != nil {
		_ = directory.Close()
		return nil, fmt.Errorf("inspect opened artifact bundle root: %w", statErr)
	}
	if !isPlainDirectory(opened) || !sameIdentityAndSize(directoryInfo, opened) {
		_ = directory.Close()
		return nil, errors.New("opened artifact bundle root changed or is not a directory")
	}

	entries, readErr := directory.ReadDir(limit)
	handleAfter, handleStatErr := directory.Stat()
	rootAfter, rootStatErr := root.Lstat(".")
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, fmt.Errorf("read artifact bundle directory: %w", readErr)
	}
	if handleStatErr != nil {
		return nil, fmt.Errorf("reinspect opened artifact bundle root: %w", handleStatErr)
	}
	if rootStatErr != nil {
		return nil, fmt.Errorf("reinspect artifact bundle root: %w", rootStatErr)
	}
	if !isPlainDirectory(handleAfter) || !isPlainDirectory(rootAfter) ||
		!sameIdentityAndSize(directoryInfo, handleAfter) || !sameIdentityAndSize(directoryInfo, rootAfter) {
		return nil, errors.New("artifact bundle root changed while enumerating")
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close artifact bundle directory: %w", closeErr)
	}
	return entries, nil
}

func verifyArtifactFile(root *os.Root, artifact Artifact) (returnErr error) {
	before, err := root.Lstat(artifact.Name)
	if err != nil {
		return fmt.Errorf("inspect artifact %q: %w", artifact.Name, err)
	}
	if !isPlainRegularFile(before) {
		return fmt.Errorf("artifact bundle entry %q is not a regular non-symlink file", artifact.Name)
	}
	if before.Size() != artifact.SizeBytes {
		return fmt.Errorf("artifact %q size is %d bytes; want %d", artifact.Name, before.Size(), artifact.SizeBytes)
	}

	// O_NONBLOCK prevents a raced-in FIFO from hanging on Unix. Root.OpenFile
	// keeps resolution beneath the pinned root; the surrounding Lstat/Stat
	// identity checks reject links and entry replacement on every platform.
	file, err := root.OpenFile(artifact.Name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open artifact %q: %w", artifact.Name, err)
	}
	defer func() {
		if err := file.Close(); err != nil && returnErr == nil {
			returnErr = fmt.Errorf("close artifact %q: %w", artifact.Name, err)
		}
	}()
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened artifact %q: %w", artifact.Name, err)
	}
	if !isPlainRegularFile(opened) || !sameIdentityAndSize(before, opened) {
		return fmt.Errorf("artifact %q changed or is not a regular non-symlink file", artifact.Name)
	}
	if opened.Size() != artifact.SizeBytes {
		return fmt.Errorf("artifact %q size is %d bytes; want %d", artifact.Name, opened.Size(), artifact.SizeBytes)
	}

	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, artifact.SizeBytes+1))
	if err != nil {
		return fmt.Errorf("hash artifact %q: %w", artifact.Name, err)
	}
	if written != artifact.SizeBytes {
		return fmt.Errorf("artifact %q yielded %d bytes while hashing; want %d", artifact.Name, written, artifact.SizeBytes)
	}
	handleAfter, err := file.Stat()
	if err != nil {
		return fmt.Errorf("reinspect opened artifact %q: %w", artifact.Name, err)
	}
	nameAfter, err := root.Lstat(artifact.Name)
	if err != nil {
		return fmt.Errorf("reinspect artifact %q: %w", artifact.Name, err)
	}
	if !isPlainRegularFile(handleAfter) || !isPlainRegularFile(nameAfter) ||
		!sameIdentityAndSize(opened, handleAfter) || !sameIdentityAndSize(opened, nameAfter) ||
		handleAfter.Size() != artifact.SizeBytes {
		return fmt.Errorf("artifact %q changed identity, type, or size while hashing", artifact.Name)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != artifact.SHA256 {
		return fmt.Errorf("artifact %q SHA-256 is %s; want %s", artifact.Name, got, artifact.SHA256)
	}
	return nil
}

func isPlainDirectory(info os.FileInfo) bool {
	return info != nil && info.Mode().Type() == os.ModeDir
}

func isPlainRegularFile(info os.FileInfo) bool {
	return info != nil && info.Mode().Type() == 0
}

func sameIdentityAndSize(first, second os.FileInfo) bool {
	return first != nil && second != nil && first.Size() == second.Size() && os.SameFile(first, second)
}

func declaredArtifacts(record Record) []declaredArtifact {
	declared := make([]declaredArtifact, 0)
	for _, artifact := range record.Attestation.Artifacts {
		declared = append(declared, declaredArtifact{context: "attestation", artifact: artifact})
	}
	for _, check := range record.Checks {
		for _, artifact := range check.Artifacts {
			declared = append(declared, declaredArtifact{context: "check " + check.ID, artifact: artifact})
		}
	}
	return declared
}

func validateGlobalArtifactNames(record Record) error {
	seen := make(map[string]string)
	var total int64
	for _, item := range declaredArtifacts(record) {
		portableName := strings.ToLower(item.artifact.Name)
		if previous, duplicate := seen[portableName]; duplicate {
			return fmt.Errorf("artifact name %q in %s collides with %s; names must be globally unique", item.artifact.Name, item.context, previous)
		}
		seen[portableName] = item.context
		if total > MaxArtifactBundleSize-item.artifact.SizeBytes {
			return fmt.Errorf("declared artifacts exceed the %d-byte bundle limit", MaxArtifactBundleSize)
		}
		total += item.artifact.SizeBytes
	}
	return nil
}

func artifactVerificationDigest(record Record) ([sha256.Size]byte, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("bind artifact verification to record: %w", err)
	}
	return sha256.Sum256(data), nil
}

func matchesArtifactVerification(record Record, verification ArtifactVerification) (bool, error) {
	if !verification.verified {
		return false, nil
	}
	digest, err := artifactVerificationDigest(record)
	if err != nil {
		return false, err
	}
	return digest == verification.recordDigest, nil
}
