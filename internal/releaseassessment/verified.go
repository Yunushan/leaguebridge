package releaseassessment

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/ciattestation"
	"github.com/Yunushan/leaguebridge/internal/cireleasegate"
	"github.com/Yunushan/leaguebridge/internal/releasecheck"
)

// verifiedMetadata is captured only after every live release check succeeds.
// It keeps the authenticated policy and asset identities for composition with
// future production-evidence verifiers, without making a saved Result proof.
type verifiedMetadata struct {
	scorecardSHA256  string
	assets           []asset
	published        publication
	evidence         map[string]localFile
	archiveInventory releasecheck.ExecutableInventory
}

// PublishedAsset is one release file authenticated by the live verifier.
type PublishedAsset struct {
	Name      string
	SHA256    string
	SizeBytes int64
}

// AuthenticatedExecutable binds one target's released executable to the
// verified release identity and published archive bytes. It is descriptive;
// only the opaque VerifiedRelease can be used as an authentication capability.
type AuthenticatedExecutable struct {
	Version          string
	Commit           string
	Tree             string
	ReleaseID        int64
	GOOS             string
	GOARCH           string
	ArchiveFilename  string
	ArchiveSHA256    string
	ExecutableSHA256 string
}

// VerifiedRelease can only be constructed by live verification in type-safe
// callers. Its zero value cannot authenticate evidence or earn points.
type VerifiedRelease struct {
	result          Result
	scorecardSHA256 string
	assets          []PublishedAsset
	executables     []AuthenticatedExecutable
	published       publication
	evidence        map[string]localFile
	request         Request
	valid           bool
}

// VerifyForProduction performs the existing complete live assessment and
// returns an opaque release identity for a future full assessor. It awards no
// native, vendor, audit, or package points.
func VerifyForProduction(ctx context.Context, input Request) (VerifiedRelease, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	return verifyForProduction(ctx, input, dependencies{
		api: githubAPI(input.GHPath), gate: cireleasegate.Verify,
		signatures: ciattestation.VerifySetContext, archives: releasecheck.CheckWithExecutableInventory, now: time.Now,
	})
}

func verifyForProduction(ctx context.Context, input Request, deps dependencies) (VerifiedRelease, error) {
	input.CrossBuildSubjects = append([]string(nil), input.CrossBuildSubjects...)
	var captured verifiedMetadata
	deps.capture = &captured
	result, err := verify(ctx, input, deps)
	if err != nil {
		return VerifiedRelease{}, err
	}
	if !sha256Pattern.MatchString(captured.scorecardSHA256) || len(captured.assets) != 10 || len(captured.evidence) != 29 {
		return VerifiedRelease{}, errors.New("live verifier did not capture the complete release identity")
	}
	assets := make([]PublishedAsset, 0, len(captured.assets))
	for _, item := range captured.assets {
		digest := strings.TrimPrefix(item.Digest, "sha256:")
		if !sha256Pattern.MatchString(digest) || item.Size <= 0 {
			return VerifiedRelease{}, errors.New("live verifier captured an invalid published asset")
		}
		assets = append(assets, PublishedAsset{item.Name, digest, item.Size})
	}
	executables, err := authenticateExecutableInventory(result, assets, captured.archiveInventory)
	if err != nil {
		return VerifiedRelease{}, fmt.Errorf("live verifier captured an invalid executable inventory: %w", err)
	}
	return VerifiedRelease{result: result, scorecardSHA256: captured.scorecardSHA256,
		assets: assets, executables: executables, published: captured.published, evidence: captured.evidence,
		request: input, valid: true}, nil
}

func authenticateExecutableInventory(result Result, assets []PublishedAsset, inventory releasecheck.ExecutableInventory) ([]AuthenticatedExecutable, error) {
	targets := [...]struct{ goos, goarch string }{
		{"linux", "amd64"}, {"linux", "arm64"},
		{"freebsd", "amd64"}, {"freebsd", "arm64"},
		{"openbsd", "amd64"}, {"openbsd", "arm64"},
		{"netbsd", "amd64"}, {"netbsd", "arm64"},
		{"dragonfly", "amd64"},
	}
	if len(inventory.Entries) != len(targets) || len(assets) != 10 {
		return nil, errors.New("release executable inventory does not cover nine targets")
	}
	assetByName := make(map[string]PublishedAsset, len(assets))
	for _, asset := range assets {
		if _, duplicate := assetByName[asset.Name]; duplicate {
			return nil, errors.New("release inventory repeats an archive")
		}
		assetByName[asset.Name] = asset
	}
	ordered := make([]AuthenticatedExecutable, 0, len(targets))
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		archiveName := "leaguebridge_" + strings.TrimPrefix(result.Version, "v") + "_" + target.goos + "_" + target.goarch + ".tar.gz"
		asset, exists := assetByName[archiveName]
		if !exists || !sha256Pattern.MatchString(asset.SHA256) || asset.SizeBytes <= 0 {
			return nil, fmt.Errorf("authenticated archive %q is missing", archiveName)
		}
		found := false
		for _, entry := range inventory.Entries {
			if entry.GOOS != target.goos || entry.GOARCH != target.goarch {
				continue
			}
			key := entry.GOOS + "/" + entry.GOARCH
			if seen[key] || entry.ArchiveName != archiveName || entry.ExecutableName != "leaguebridge" ||
				entry.ArchiveSHA256 != asset.SHA256 || !sha256Pattern.MatchString(entry.ExecutableSHA256) {
				return nil, fmt.Errorf("release executable inventory differs from published archive %q", archiveName)
			}
			seen[key], found = true, true
			ordered = append(ordered, AuthenticatedExecutable{
				Version: result.Version, Commit: result.Commit, Tree: result.Tree, ReleaseID: result.ReleaseID,
				GOOS: target.goos, GOARCH: target.goarch, ArchiveFilename: archiveName,
				ArchiveSHA256: asset.SHA256, ExecutableSHA256: entry.ExecutableSHA256,
			})
		}
		if !found {
			return nil, fmt.Errorf("release executable inventory is missing %s/%s", target.goos, target.goarch)
		}
	}
	if len(seen) != len(targets) {
		return nil, errors.New("release executable inventory has unsupported or duplicate targets")
	}
	return ordered, nil
}

// Assessment returns a copy of the verified release result. The returned
// value is descriptive only; it cannot be passed back as authentication.
func (verified VerifiedRelease) Assessment() (Result, error) {
	if !verified.valid {
		return Result{}, errors.New("release has not been verified")
	}
	result := verified.result
	result.Criteria = append([]Criterion(nil), result.Criteria...)
	return result, nil
}

// ScorecardSHA256 returns the authenticated released scorecard digest.
func (verified VerifiedRelease) ScorecardSHA256() (string, error) {
	if !verified.valid {
		return "", errors.New("release has not been verified")
	}
	return verified.scorecardSHA256, nil
}

// PublishedAssets returns a copy of the exact authenticated ten-file release
// inventory. Callers cannot alter the identity retained for the final recheck.
func (verified VerifiedRelease) PublishedAssets() ([]PublishedAsset, error) {
	if !verified.valid {
		return nil, errors.New("release has not been verified")
	}
	return append([]PublishedAsset(nil), verified.assets...), nil
}

// ExecutableFor returns the authenticated binary/archive binding for one
// released target. A caller cannot use this descriptive copy in place of the
// opaque release capability when awarding production points.
func (verified VerifiedRelease) ExecutableFor(goos, goarch string) (AuthenticatedExecutable, error) {
	if !verified.valid {
		return AuthenticatedExecutable{}, errors.New("release has not been verified")
	}
	for _, executable := range verified.executables {
		if executable.GOOS == goos && executable.GOARCH == goarch {
			return executable, nil
		}
	}
	return AuthenticatedExecutable{}, fmt.Errorf("released executable target %s/%s is unavailable", goos, goarch)
}

// Recheck repeats the full live assessment using the original request after
// additional evidence checks. A changed source, run, score, policy, asset, or
// local file invalidates the composed assessment.
func (verified VerifiedRelease) Recheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	return verified.recheck(ctx, dependencies{
		api: githubAPI(verified.request.GHPath), gate: cireleasegate.Verify,
		signatures: ciattestation.VerifySetContext, archives: releasecheck.CheckWithExecutableInventory, now: time.Now,
	})
}

func (verified VerifiedRelease) recheck(ctx context.Context, deps dependencies) error {
	if !verified.valid {
		return errors.New("release has not been verified")
	}
	next, err := verifyForProduction(ctx, verified.request, deps)
	if err != nil {
		return err
	}
	if next.result.ObservedAt.Before(verified.result.ObservedAt) {
		return errors.New("live release observation moved backward")
	}
	initial, final := verified.result, next.result
	initial.ObservedAt, final.ObservedAt = time.Time{}, time.Time{}
	if !reflect.DeepEqual(initial, final) || verified.scorecardSHA256 != next.scorecardSHA256 ||
		!reflect.DeepEqual(verified.assets, next.assets) || !reflect.DeepEqual(verified.executables, next.executables) ||
		!reflect.DeepEqual(verified.published, next.published) ||
		!reflect.DeepEqual(verified.evidence, next.evidence) {
		return errors.New("live release identity changed during production assessment")
	}
	return nil
}
