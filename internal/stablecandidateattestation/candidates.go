package stablecandidateattestation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/productionpackage"
	"github.com/Yunushan/leaguebridge/internal/releaseassessment"
)

// The aggregate workflow retains package bytes and CANDIDATE-SET.json, but
// candidate-set generates its per-cell candidate JSON in a temporary directory
// that it deletes. Reconstruct that metadata from the authenticated release
// and current local bytes before invoking the independently checking payload
// verifier. No caller-supplied candidate JSON is accepted as evidence.
func reconstructCandidates(ctx context.Context, release releaseassessment.VerifiedRelease, packages []PackageInput) ([]productionpackage.CandidatePaths, func(), error) {
	if ctx == nil {
		return nil, nil, errors.New("verification context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if len(packages) != len(productionpackage.ExpectedCells()) {
		return nil, nil, errors.New("exactly eleven package inputs are required")
	}
	directory, err := os.MkdirTemp("", "leaguebridge-stable-candidates-")
	if err != nil {
		return nil, nil, fmt.Errorf("create private candidate directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	root, err := fileinput.OpenDirectoryRoot(directory)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("open private candidate directory: %w", err)
	}
	inputs := make([]productionpackage.CandidatePaths, 0, len(packages))
	for index, paths := range packages {
		if err := ctx.Err(); err != nil {
			_ = root.Close()
			cleanup()
			return nil, nil, err
		}
		name := fmt.Sprintf("%02d.json", index)
		data, err := productionpackage.Build(ctx, release, paths.ArchivePath, paths.StagingDir, paths.PackagePath)
		if err != nil {
			_ = root.Close()
			cleanup()
			return nil, nil, fmt.Errorf("derive candidate metadata %d: %w", index, err)
		}
		if len(data) == 0 || len(data) > 16<<10 {
			_ = root.Close()
			cleanup()
			return nil, nil, fmt.Errorf("derived candidate metadata %d exceeds its bound", index)
		}
		if err := writePrivateCandidate(root, name, data); err != nil {
			_ = root.Close()
			cleanup()
			return nil, nil, fmt.Errorf("write private candidate metadata %d: %w", index, err)
		}
		inputs = append(inputs, productionpackage.CandidatePaths{
			CandidatePath: filepath.Join(directory, name),
			ArchivePath:   paths.ArchivePath, StagingDir: paths.StagingDir, PackagePath: paths.PackagePath,
		})
	}
	if err := root.Close(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("close private candidate directory: %w", err)
	}
	return inputs, cleanup, nil
}

func writePrivateCandidate(root *os.Root, name string, data []byte) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if count, err := file.Write(data); err != nil || count != len(data) {
		_ = file.Close()
		return errors.New("write complete candidate metadata")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	created, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	current, err := root.Lstat(name)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(created, current) ||
		current.Size() != int64(len(data)) || current.Mode().Perm() != 0o600 {
		return errors.New("private candidate metadata changed after writing")
	}
	return nil
}
