package releaseassessment

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
)

// Stage only bytes already matched to live GitHub asset digests into a newly
// private directory. Both independent verifiers receive this same private
// input, so a writer of the caller's release directory cannot swap A/B/A across
// archive-semantic and signature checks. This copy is temporary, never a receipt.
func stageRelease(ctx context.Context, directory string, assets []asset) (string, func(), error) {
	source, err := fileinput.OpenDirectoryRoot(directory)
	if err != nil {
		return "", nil, stageFailure(ctx, "open release staging source", err)
	}
	defer source.Close()
	staging, err := os.MkdirTemp("", "leaguebridge-release-assessment-")
	if err != nil {
		return "", nil, stageFailure(ctx, "create private release staging", err)
	}
	cleanup := func() { _ = os.RemoveAll(staging) }
	ok := false
	defer func() {
		if !ok {
			cleanup()
		}
	}()
	for _, item := range assets {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		data, err := fileinput.ReadRegularBoundedFromRoot(source, item.Name, maximumFileSize(item.Name))
		if err != nil {
			return "", nil, stageFailure(ctx, "copy published asset bytes", err)
		}
		if int64(len(data)) != item.Size || "sha256:"+digestBytes(data) != item.Digest {
			return "", nil, errors.New("published asset changed before private verification staging")
		}
		file, err := os.OpenFile(filepath.Join(staging, item.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return "", nil, stageFailure(ctx, "create private staged asset", err)
		}
		_, writeErr := file.Write(data)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return "", nil, errors.New("private staged asset write failed")
		}
	}
	if _, err := snapshotRelease(ctx, staging, assets); err != nil {
		return "", nil, err
	}
	ok = true
	return staging, cleanup, nil
}
