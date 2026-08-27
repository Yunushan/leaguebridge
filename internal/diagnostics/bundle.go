package diagnostics

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxBundleSize = 2 * 1024 * 1024

var (
	// ErrBundleExists indicates that WriteBundle refused to replace any
	// filesystem object already present at the destination.
	ErrBundleExists = errors.New("support bundle already exists")
	errBundleTooBig = errors.New("support bundle exceeds size limit")
)

const bundleReadme = `LeagueBridge support bundle

This archive was generated locally for troubleshooting. It contains only:

- report.json: structured, bounded diagnostic results
- README.txt: this explanation

LeagueBridge does not add configuration files, raw logs, credentials, cookies,
usernames, hostnames, home directories, or network addresses to this bundle.
Diagnostic text is redacted as a defense in depth. Review report.json before
sharing the archive.
`

var deterministicZipTime = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

// WriteBundle creates a mode-0600 zip archive without replacing an existing
// path. Data is generated and validated in memory, written to a same-directory
// temporary file, synced, then published with an exclusive atomic hard link.
// On Windows the file inherits its directory DACL because os.Chmod cannot make
// that ACL owner-only. If any step fails, no partial destination is left behind.
func WriteBundle(destination string, report Report) error {
	return writeBundle(destination, report, os.Link)
}

type publishFunc func(oldPath, newPath string) error

func writeBundle(destination string, report Report, publish publishFunc) error {
	target, err := validateDestination(destination)
	if err != nil {
		return err
	}
	data, err := buildBundle(report)
	if err != nil {
		return err
	}

	temporary, err := os.CreateTemp(filepath.Dir(target), ".leaguebridge-support-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary support bundle: %w", err)
	}
	temporaryPath := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			_ = temporary.Close()
		}
		_ = os.Remove(temporaryPath)
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set temporary support bundle permissions: %w", err)
	}
	n, err := temporary.Write(data)
	if err != nil {
		return fmt.Errorf("write temporary support bundle: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("write temporary support bundle: %w", io.ErrShortWrite)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary support bundle: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary support bundle: %w", err)
	}
	closed = true

	if err := publish(temporaryPath, target); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrBundleExists
		}
		return fmt.Errorf("publish support bundle with an exclusive hard link (destination filesystem must support same-directory hard links; write locally and copy after inspection if needed): %w", err)
	}
	// Publication is complete once the exclusive hard link succeeds. Do not
	// report a failed bundle if cleanup is denied; the deferred removal gets one
	// more best-effort attempt and any remnant is private (0600) and identical to
	// the published bytes.
	if err := os.Remove(temporaryPath); err == nil || errors.Is(err, fs.ErrNotExist) {
		temporaryPath = ""
	}
	return nil
}

func validateDestination(destination string) (string, error) {
	if strings.TrimSpace(destination) == "" {
		return "", errors.New("support bundle destination is required")
	}
	target, err := filepath.Abs(destination)
	if err != nil {
		return "", fmt.Errorf("resolve support bundle destination: %w", err)
	}
	directory := filepath.Dir(target)
	info, err := os.Stat(directory)
	if err != nil {
		return "", fmt.Errorf("inspect support bundle directory: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("support bundle parent is not a directory")
	}
	if _, err := os.Lstat(target); err == nil {
		return "", ErrBundleExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("inspect support bundle destination: %w", err)
	}
	return target, nil
}

func buildBundle(report Report) ([]byte, error) {
	reportJSON, err := Marshal(report)
	if err != nil {
		return nil, err
	}
	if len(reportJSON)+len(bundleReadme) > MaxBundleSize {
		return nil, errBundleTooBig
	}

	buffer := &boundedBuffer{max: MaxBundleSize}
	archive := zip.NewWriter(buffer)
	if err := writeBundleEntry(archive, "README.txt", []byte(bundleReadme)); err != nil {
		_ = archive.Close()
		return nil, err
	}
	if err := writeBundleEntry(archive, "report.json", reportJSON); err != nil {
		_ = archive.Close()
		return nil, err
	}
	if err := archive.Close(); err != nil {
		return nil, fmt.Errorf("finalize support bundle: %w", err)
	}
	return append([]byte(nil), buffer.Bytes()...), nil
}

func writeBundleEntry(archive *zip.Writer, name string, contents []byte) error {
	if !validArchiveName(name) {
		return errors.New("unsafe support bundle entry name")
	}
	header := &zip.FileHeader{
		Name:     name,
		Method:   zip.Deflate,
		Modified: deterministicZipTime,
	}
	header.SetMode(0o600)
	entry, err := archive.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create support bundle entry: %w", err)
	}
	if _, err := entry.Write(contents); err != nil {
		return fmt.Errorf("write support bundle entry: %w", err)
	}
	return nil
}

func validArchiveName(name string) bool {
	if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, `\\:`) {
		return false
	}
	if path.IsAbs(name) || path.Clean(name) != name || strings.Contains(name, "/") {
		return false
	}
	return name != "." && name != ".."
}

type boundedBuffer struct {
	bytes.Buffer
	max int
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	if len(data) > b.max-b.Len() {
		return 0, errBundleTooBig
	}
	return b.Buffer.Write(data)
}
