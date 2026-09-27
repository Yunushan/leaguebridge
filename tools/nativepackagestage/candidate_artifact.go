package main

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/productionpackage"
)

const (
	maximumCandidateArtifact = int64(11*(256<<20) + (1 << 20))
	maximumArtifactMembers   = 64
	maximumRecordMember      = int64(64 << 10)
	maximumPackageMember     = int64(256 << 20)
)

// extractStableCandidateArtifact accepts only the twelve retained workflow
// files. The untrusted tar is snapshotted, validated without extraction, then
// extracted into a private directory. No tar metadata can create a link,
// device, alternate path, or permission chosen by the archive.
func extractStableCandidateArtifact(ctx context.Context, version, artifactPath string) (string, func(), error) {
	if ctx == nil {
		return "", nil, errors.New("verification context is required")
	}
	files, directories, err := candidateArtifactInventory(version)
	if err != nil {
		return "", nil, err
	}
	source, err := fileinput.OpenRegular(artifactPath)
	if err != nil {
		return "", nil, fmt.Errorf("open regular candidate artifact: %w", err)
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumCandidateArtifact {
		return "", nil, errors.New("candidate artifact size is outside its bound")
	}
	privateRoot, err := os.MkdirTemp("", "leaguebridge-candidate-artifact-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(privateRoot) }
	snapshotPath := filepath.Join(privateRoot, "artifact.tar")
	snapshot, err := os.OpenFile(snapshotPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	_, copyErr := copyNContext(ctx, snapshot, source, info.Size())
	closeErr := snapshot.Close()
	if copyErr != nil || closeErr != nil {
		cleanup()
		return "", nil, errors.New("copy bounded candidate artifact into private snapshot")
	}
	members, err := inspectCandidateTarHeaders(ctx, snapshotPath, files, directories)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	extracted := filepath.Join(privateRoot, "extracted")
	if err := os.Mkdir(extracted, 0o700); err != nil {
		cleanup()
		return "", nil, err
	}
	if err := extractCandidateTarFiles(ctx, snapshotPath, extracted, files, directories, members); err != nil {
		cleanup()
		return "", nil, err
	}
	return extracted, cleanup, nil
}

func candidateArtifactInventory(version string) (map[string]int64, map[string]bool, error) {
	files := map[string]int64{"CANDIDATE-SET.json": maximumRecordMember}
	directories := map[string]bool{"merged-packages": true, "merged-packages/native-package-output": true}
	for _, cell := range productionpackage.ExpectedCells() {
		name, err := productionpackage.ExpectedPackageFilename(version, cell.Family, cell.GOOS, cell.GOARCH)
		if err != nil {
			return nil, nil, err
		}
		family := "merged-packages/native-package-output/" + string(cell.Family)
		architecture := family + "/" + cell.GOARCH
		directories[family] = true
		directories[architecture] = true
		member := architecture + "/" + name
		if _, duplicate := files[member]; duplicate {
			return nil, nil, errors.New("candidate artifact has duplicate expected filenames")
		}
		files[member] = maximumPackageMember
	}
	if len(files) != 12 {
		return nil, nil, errors.New("candidate artifact does not have twelve fixed files")
	}
	return files, directories, nil
}

type candidateTarMember struct {
	name      string
	size      int64
	directory bool
}

func inspectCandidateTarHeaders(ctx context.Context, snapshot string, files map[string]int64, directories map[string]bool) ([]candidateTarMember, error) {
	reader, err := os.Open(snapshot)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	seen := make(map[string]bool, len(files)+len(directories))
	members := make([]candidateTarMember, 0, len(files)+len(directories))
	longName := ""
	maximumLongName := 0
	for name := range files {
		if name != "CANDIDATE-SET.json" && len(name) > maximumLongName {
			maximumLongName = len(name)
		}
	}
	var block [512]byte
	for headerCount := 0; ; headerCount++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if headerCount > maximumArtifactMembers {
			return nil, errors.New("candidate tar has too many members")
		}
		if _, err := io.ReadFull(reader, block[:]); err != nil {
			return nil, fmt.Errorf("candidate tar header is truncated: %w", err)
		}
		if bytes.Equal(block[:], make([]byte, len(block))) {
			if longName != "" {
				return nil, errors.New("candidate tar has a dangling GNU long-name header")
			}
			// GNU tar pads to a record boundary. Only zero bytes may remain.
			var tail [32 << 10]byte
			for {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				count, err := reader.Read(tail[:])
				if bytes.Count(tail[:count], []byte{0}) != count {
					return nil, errors.New("candidate tar has data after its end marker")
				}
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return nil, err
				}
			}
			break
		}
		nameField := block[:100]
		if end := bytes.IndexByte(nameField, 0); end >= 0 {
			nameField = nameField[:end]
		}
		name := string(nameField)
		typeFlag := block[156]
		sizeField := strings.Trim(string(block[124:136]), " \x00")
		size, err := strconv.ParseInt(sizeField, 8, 64)
		if err != nil || size < 0 {
			return nil, fmt.Errorf("candidate tar member %q has invalid size", name)
		}
		if typeFlag == tar.TypeGNULongName {
			if longName != "" || name != "././@LongLink" || size <= 101 || size > int64(maximumLongName+1) {
				return nil, errors.New("candidate tar has an invalid GNU long-name header")
			}
			payload := make([]byte, size)
			if _, err := io.ReadFull(reader, payload); err != nil {
				return nil, fmt.Errorf("candidate tar GNU long-name payload is truncated: %w", err)
			}
			if payload[len(payload)-1] != 0 || bytes.IndexByte(payload, 0) != len(payload)-1 {
				return nil, errors.New("candidate tar GNU long-name payload is not one terminated path")
			}
			longName = string(payload[:len(payload)-1])
			if len(longName) <= 100 || longName == "CANDIDATE-SET.json" || files[longName] == 0 || seen[longName] {
				return nil, fmt.Errorf("candidate tar GNU long name is not one expected package file %q", longName)
			}
			if _, err := copyNContext(ctx, io.Discard, reader, (size+511)/512*512-size); err != nil {
				return nil, fmt.Errorf("candidate tar GNU long-name padding is truncated: %w", err)
			}
			continue
		}
		if longName != "" {
			if (typeFlag != tar.TypeReg && typeFlag != tar.TypeRegA) || name != longName[:100] {
				return nil, fmt.Errorf("candidate tar GNU long name does not match its regular file header %q", name)
			}
			name, longName = longName, ""
		} else if typeFlag == tar.TypeDir && strings.HasSuffix(name, "/") {
			name = strings.TrimSuffix(name, "/")
		}
		if name == "" || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || path.Clean(name) != name || seen[name] {
			return nil, fmt.Errorf("candidate tar has unsafe or duplicate member %q", name)
		}
		seen[name] = true
		switch typeFlag {
		case tar.TypeReg, tar.TypeRegA:
			maximum, expected := files[name]
			if !expected || size <= 0 || size > maximum {
				return nil, fmt.Errorf("candidate tar has unexpected or oversized regular member %q", name)
			}
		case tar.TypeDir:
			if !directories[name] || size != 0 {
				return nil, fmt.Errorf("candidate tar has unexpected directory %q", name)
			}
		default:
			return nil, fmt.Errorf("candidate tar has prohibited entry type %q for %q", typeFlag, name)
		}
		members = append(members, candidateTarMember{name: name, size: size, directory: typeFlag == tar.TypeDir})
		padded := (size + 511) / 512 * 512
		if _, err := copyNContext(ctx, io.Discard, reader, padded); err != nil {
			return nil, fmt.Errorf("candidate tar member %q is truncated: %w", name, err)
		}
	}
	for name := range files {
		if !seen[name] {
			return nil, fmt.Errorf("candidate tar is missing required file %q", name)
		}
	}
	return members, nil
}

func extractCandidateTarFiles(ctx context.Context, snapshot, destination string, files map[string]int64, directories map[string]bool, members []candidateTarMember) error {
	reader, err := os.Open(snapshot)
	if err != nil {
		return err
	}
	defer reader.Close()
	archive := tar.NewReader(reader)
	index := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			if index != len(members) {
				return errors.New("candidate tar parser omitted validated members")
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("parse validated candidate tar: %w", err)
		}
		if index >= len(members) {
			return errors.New("candidate tar parser produced extra members")
		}
		name := header.Name
		if header.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		member := members[index]
		index++
		if name != member.name || header.Size != member.size || (header.Typeflag == tar.TypeDir) != member.directory {
			return errors.New("candidate tar parser disagrees with validated member")
		}
		if name == "" || path.Clean(name) != name {
			return errors.New("candidate tar parser produced an unsafe path")
		}
		target := filepath.Join(destination, filepath.FromSlash(name))
		if header.Typeflag == tar.TypeDir && directories[name] {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		maximum, expected := files[name]
		if !expected || (header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) || header.Size <= 0 || header.Size > maximum {
			return fmt.Errorf("candidate tar parser produced an unexpected member %q", name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := copyNContext(ctx, output, archive, header.Size)
		closeErr := output.Close()
		if copyErr != nil || closeErr != nil {
			return fmt.Errorf("extract candidate tar member %q: %v", name, copyErr)
		}
	}
}

func copyNContext(ctx context.Context, destination io.Writer, source io.Reader, size int64) (int64, error) {
	var written int64
	var buffer [64 << 10]byte
	for written < size {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		remaining := size - written
		chunk := int64(len(buffer))
		if remaining < chunk {
			chunk = remaining
		}
		count, err := io.ReadFull(source, buffer[:chunk])
		if err != nil {
			return written, err
		}
		copied, err := destination.Write(buffer[:count])
		written += int64(copied)
		if err != nil {
			return written, err
		}
		if copied != count {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}
