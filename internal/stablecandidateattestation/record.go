package stablecandidateattestation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/productionpackage"
	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
)

// This is the canonical CANDIDATE-SET.json contract written by
// nativepackagestage candidate-set. It is deliberately reconstructed from the
// opaque release and independently inspected packages, never parsed as a
// source of expected identity.
type candidateSetRecord struct {
	SchemaVersion   int                `json:"schema_version"`
	RecordType      string             `json:"record_type"`
	ValidationScope string             `json:"validation_scope"`
	Release         releaseIdentity    `json:"release"`
	Cells           []candidateSetCell `json:"cells"`
}

type releaseIdentity struct {
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	Tree            string `json:"tree"`
	ReleaseID       int64  `json:"release_id"`
	ScorecardSHA256 string `json:"scorecard_sha256"`
}

type candidateSetCell struct {
	Family                string `json:"family"`
	GOOS                  string `json:"goos"`
	GOARCH                string `json:"goarch"`
	PackageFilename       string `json:"package_filename"`
	PackageSHA256         string `json:"package_sha256"`
	ArchiveSHA256         string `json:"archive_sha256"`
	ExecutableSHA256      string `json:"executable_sha256"`
	StagingManifestSHA256 string `json:"staging_manifest_sha256"`
}

func canonicalRecord(release releaseassessment.VerifiedRelease, summaries []productionpackage.Summary) ([]byte, error) {
	assessment, err := release.Assessment()
	if err != nil {
		return nil, err
	}
	scorecardSHA, err := release.ScorecardSHA256()
	if err != nil {
		return nil, err
	}
	cells := productionpackage.ExpectedCells()
	if len(cells) != 11 || len(summaries) != len(cells) {
		return nil, errors.New("complete eleven-cell candidate set is required")
	}
	record := candidateSetRecord{
		SchemaVersion: 1, RecordType: "leaguebridge.native-package-candidate-set.v1",
		ValidationScope: "candidate-payload-integrity-only",
		Release: releaseIdentity{
			Version: assessment.Version, Commit: assessment.Commit, Tree: assessment.Tree,
			ReleaseID: assessment.ReleaseID, ScorecardSHA256: scorecardSHA,
		},
		Cells: make([]candidateSetCell, 0, len(cells)),
	}
	for index, summary := range summaries {
		cell := cells[index]
		if summary.Version != assessment.Version || summary.Commit != assessment.Commit ||
			summary.Tree != assessment.Tree || summary.ReleaseID != assessment.ReleaseID ||
			summary.Family != cell.Family || summary.GOOS != cell.GOOS || summary.GOARCH != cell.GOARCH {
			return nil, fmt.Errorf("candidate cell %d differs from the authenticated release or fixed inventory", index)
		}
		expectedName, err := productionpackage.ExpectedPackageFilename(assessment.Version, cell.Family, cell.GOOS, cell.GOARCH)
		if err != nil || summary.PackageFilename != expectedName {
			return nil, fmt.Errorf("candidate cell %d has an invalid package filename", index)
		}
		for _, digest := range []string{summary.PackageSHA256, summary.ArchiveSHA256, summary.ExecutableSHA256, summary.StagingManifestSHA256} {
			if !sha256Pattern.MatchString(digest) {
				return nil, fmt.Errorf("candidate cell %d has an invalid digest", index)
			}
		}
		record.Cells = append(record.Cells, candidateSetCell{
			Family: string(summary.Family), GOOS: summary.GOOS, GOARCH: summary.GOARCH,
			PackageFilename: summary.PackageFilename, PackageSHA256: summary.PackageSHA256,
			ArchiveSHA256: summary.ArchiveSHA256, ExecutableSHA256: summary.ExecutableSHA256,
			StagingManifestSHA256: summary.StagingManifestSHA256,
		})
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func checkRecord(ctx context.Context, path string, expected []byte) (string, error) {
	if filepath.Base(path) != "CANDIDATE-SET.json" || len(expected) == 0 {
		return "", errors.New("candidate-set record path or canonical bytes are invalid")
	}
	data, err := readRegularBounded(ctx, path, 16<<10)
	if err != nil {
		return "", fmt.Errorf("read candidate-set record: %w", err)
	}
	if !bytes.Equal(data, expected) {
		return "", errors.New("candidate-set record is not the canonical verified release and payload inventory")
	}
	return digestBytes(data), nil
}

func readRegularBounded(ctx context.Context, path string, maximum int64) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("verification context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := fileinput.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maximum {
		return nil, errors.New("regular file size is outside its bound")
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: file}, maximum+1))
	if err != nil || int64(len(data)) != before.Size() {
		return nil, errors.New("regular file changed while reading")
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	pathAfter, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !pathAfter.Mode().IsRegular() ||
		!os.SameFile(before, after) || !os.SameFile(before, pathAfter) ||
		after.Size() != int64(len(data)) || pathAfter.Size() != int64(len(data)) {
		return nil, errors.New("regular file path changed while reading")
	}
	return data, ctx.Err()
}

func hashRegular(ctx context.Context, path string, maximum int64) (string, error) {
	if ctx == nil {
		return "", errors.New("verification context is required")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	file, err := fileinput.OpenRegular(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maximum {
		return "", errors.New("regular package size is outside its bound")
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(contextReader{ctx: ctx, reader: file}, maximum+1))
	if err != nil || count != before.Size() {
		return "", errors.New("regular package changed while hashing")
	}
	after, err := file.Stat()
	if err != nil {
		return "", err
	}
	pathAfter, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !pathAfter.Mode().IsRegular() ||
		!os.SameFile(before, after) || !os.SameFile(before, pathAfter) ||
		after.Size() != count || pathAfter.Size() != count {
		return "", errors.New("regular package path changed while hashing")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
}

func digestBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func compareSummaries(before, after []productionpackage.Summary) error {
	if !reflect.DeepEqual(before, after) {
		return errors.New("eleven package payload summaries changed during attestation verification")
	}
	return nil
}
