package releaseassessment

import (
	"context"
	"errors"
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
	scorecardSHA256 string
	assets          []asset
	published       publication
	evidence        map[string]localFile
}

// PublishedAsset is one release file authenticated by the live verifier.
type PublishedAsset struct {
	Name      string
	SHA256    string
	SizeBytes int64
}

// VerifiedRelease can only be constructed by live verification in type-safe
// callers. Its zero value cannot authenticate evidence or earn points.
type VerifiedRelease struct {
	result          Result
	scorecardSHA256 string
	assets          []PublishedAsset
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
		signatures: ciattestation.VerifySetContext, archives: releasecheck.Check, now: time.Now,
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
	return VerifiedRelease{result: result, scorecardSHA256: captured.scorecardSHA256,
		assets: assets, published: captured.published, evidence: captured.evidence,
		request: input, valid: true}, nil
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

// Recheck repeats the full live assessment using the original request after
// additional evidence checks. A changed source, run, score, policy, asset, or
// local file invalidates the composed assessment.
func (verified VerifiedRelease) Recheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	return verified.recheck(ctx, dependencies{
		api: githubAPI(verified.request.GHPath), gate: cireleasegate.Verify,
		signatures: ciattestation.VerifySetContext, archives: releasecheck.Check, now: time.Now,
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
		!reflect.DeepEqual(verified.assets, next.assets) || !reflect.DeepEqual(verified.published, next.published) ||
		!reflect.DeepEqual(verified.evidence, next.evidence) {
		return errors.New("live release identity changed during production assessment")
	}
	return nil
}
