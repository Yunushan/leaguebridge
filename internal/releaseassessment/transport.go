package releaseassessment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/target"
)

const maximumResponse = 12 << 20

type apiClient func(context.Context, string, any) error

func githubAPI(gh string) apiClient {
	return func(ctx context.Context, endpoint string, result any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(requestCtx, gh, "api", "--hostname", "github.com", "--method", "GET", "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2026-03-10", endpoint)
		cmd.WaitDelay = 2 * time.Second
		output := &boundedOutput{}
		cmd.Stdout, cmd.Stderr = output, io.Discard
		if err := cmd.Run(); err != nil {
			if contextError := requestCtx.Err(); contextError != nil {
				return contextError
			}
			return errors.New("GitHub API request failed")
		}
		decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
		if err := decoder.Decode(result); err != nil {
			return errors.New("GitHub API response is invalid")
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return errors.New("GitHub API response has trailing data")
		}
		return nil
	}
}

// Do not embed bytes.Buffer: its promoted ReadFrom lets io.Copy bypass Write
// when os/exec drains a stdout pipe, defeating the response bound.
type boundedOutput struct{ buffer bytes.Buffer }

func (buffer *boundedOutput) Bytes() []byte { return buffer.buffer.Bytes() }
func (buffer *boundedOutput) Len() int      { return buffer.buffer.Len() }

func (buffer *boundedOutput) Write(data []byte) (int, error) {
	if len(data) > maximumResponse-buffer.Len() {
		return 0, errors.New("GitHub API response exceeds its bound")
	}
	return buffer.buffer.Write(data)
}

type localFile struct {
	Digest string
	Size   int64
}

func maximumFileSize(name string) int64 {
	if name == "checksums.txt" {
		return 64 << 10
	}
	return 256 << 20
}

func snapshotRelease(ctx context.Context, directoryPath string, assets []asset) (map[string]localFile, error) {
	root, err := fileinput.OpenDirectoryRoot(directoryPath)
	if err != nil {
		return nil, stageFailure(ctx, "open release directory", err)
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return nil, stageFailure(ctx, "read release directory", err)
	}
	names, readErr := directory.Readdirnames(11)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, errors.New("release directory cannot be inventoried")
	}
	if closeErr != nil || len(names) != 10 {
		return nil, errors.New("local release directory must contain exactly the ten published assets")
	}
	wanted := make(map[string]bool)
	for _, item := range assets {
		wanted[item.Name] = true
	}
	for _, name := range names {
		if !wanted[name] {
			return nil, errors.New("local release directory contains an unexpected entry")
		}
	}
	result := make(map[string]localFile)
	for _, item := range assets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := fileinput.ReadRegularBoundedFromRoot(root, item.Name, maximumFileSize(item.Name))
		if err != nil {
			return nil, stageFailure(ctx, "read published asset bytes", err)
		}
		state := localFile{digestBytes(data), int64(len(data))}
		if state.Size != item.Size || "sha256:"+state.Digest != item.Digest {
			return nil, errors.New("local release asset bytes do not match the published GitHub asset digest and size")
		}
		result["release:"+item.Name] = state
	}
	return result, nil
}

func snapshotEvidence(ctx context.Context, input Request, assets []asset) (map[string]localFile, error) {
	result, err := snapshotRelease(ctx, input.ReleaseDir, assets)
	if err != nil {
		return nil, err
	}
	paths := append([]string{input.RaceVetSubject}, input.CrossBuildSubjects...)
	for _, item := range target.Ordered() {
		paths = append(paths, "ci-build/leaguebridge-"+item.GOOS+"-"+item.GOARCH)
	}
	for index, name := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		maximum := int64(64 << 10)
		if index >= 10 {
			maximum = 256 << 20
		}
		data, err := readLocalFile(name, maximum)
		if err != nil {
			return nil, stageFailure(ctx, "read CI subject bytes", err)
		}
		result["ci:"+name] = localFile{digestBytes(data), int64(len(data))}
	}
	return result, nil
}

func readLocalFile(name string, maximum int64) ([]byte, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("local evidence path is empty")
	}
	abs, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	root, err := fileinput.OpenDirectoryRoot(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return fileinput.ReadRegularBoundedFromRoot(root, filepath.Base(abs), maximum)
}
