package productionnative

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/reviewercrypto"
)

// VerifyObservation checks one signed observation against a verifier-selected
// target, authenticated release binding, challenge, artifacts, and policy.
// Its result is score-free. An actual production assessor must independently
// establish physical witness provenance and package publication before using
// these authenticated assertions as evidence.
func VerifyObservation(ctx context.Context, envelopeData []byte, artifacts []ArtifactInput, expected ExpectedObservation, policy TrustPolicy) (VerifiedObservation, error) {
	return VerifyObservationAt(ctx, envelopeData, artifacts, expected, policy, time.Now())
}

// VerifyObservationAt is the deterministic-time form of VerifyObservation.
func VerifyObservationAt(ctx context.Context, envelopeData []byte, artifacts []ArtifactInput, expected ExpectedObservation, policy TrustPolicy, now time.Time) (VerifiedObservation, error) {
	if ctx == nil || now.IsZero() {
		return VerifiedObservation{}, errors.New("verification context and time are required")
	}
	if err := ctx.Err(); err != nil {
		return VerifiedObservation{}, err
	}
	if err := validateExpected(expected); err != nil {
		return VerifiedObservation{}, err
	}
	if !policy.valid {
		return VerifiedObservation{}, errors.New("validated application trust policy is required")
	}
	if err := validateTrustPolicy(policy.policy); err != nil {
		return VerifiedObservation{}, fmt.Errorf("validate application trust policy: %w", err)
	}
	parsedEnvelope, payloadData, payload, err := parseEnvelope(envelopeData)
	if err != nil {
		return VerifiedObservation{}, err
	}
	if payload.PolicyID != policy.policy.ID || payload.Kind != expected.Kind || payload.Cell != expected.Cell ||
		payload.Release != expected.Release || payload.PackageSHA256 != expected.PackageSHA256 ||
		payload.Challenge != expected.Challenge || payload.HostRoute != expected.HostRoute {
		return VerifiedObservation{}, errors.New("signed payload differs from verifier-selected policy, target, release, package, route, or challenge")
	}
	created, _ := canonicalTime("created_at", payload.CreatedAt)
	expires, _ := canonicalTime("expires_at", payload.ExpiresAt)
	now = now.UTC()
	if created.After(now) || !now.Before(expires) {
		return VerifiedObservation{}, errors.New("observation is future-dated or expired")
	}
	if policy.policy.Status != policyActive {
		return VerifiedObservation{}, errors.New("production native trust policy is unprovisioned")
	}
	policyStart, _ := canonicalTime("policy valid_from", policy.policy.ValidFrom)
	policyEnd, _ := canonicalTime("policy expires_at", policy.policy.ExpiresAt)
	if now.Before(policyStart) || !now.Before(policyEnd) || created.Before(policyStart) || expires.After(policyEnd) {
		return VerifiedObservation{}, errors.New("observation or verification time is outside policy validity")
	}
	snapshots, err := verifyArtifacts(ctx, artifacts, payload.Artifacts)
	if err != nil {
		return VerifiedObservation{}, err
	}
	if err := verifySignatures(parsedEnvelope.Signatures, payloadData, payload, policy.policy, now); err != nil {
		return VerifiedObservation{}, err
	}
	if err := recheckArtifacts(ctx, snapshots); err != nil {
		return VerifiedObservation{}, fmt.Errorf("raw artifact changed after signature verification: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return VerifiedObservation{}, err
	}
	return VerifiedObservation{
		valid: true, kind: payload.Kind, cell: payload.Cell, release: payload.Release,
		packageSHA256: payload.PackageSHA256, policyID: payload.PolicyID,
		policyDigest: policyDigest(policy.policy), observationID: payload.ObservationID,
		runID: payload.RunID, machineID: payload.MachineID, challenge: payload.Challenge,
		payloadSHA256: sha256Hex(payloadData), createdAt: created, expiresAt: expires, verifiedAt: now,
		artifactInputs: append([]ArtifactInput(nil), artifacts...),
		artifacts:      append([]artifact(nil), payload.Artifacts...),
	}, nil
}

func validateExpected(expected ExpectedObservation) error {
	if !supportedCell(expected.Kind, expected.Cell) {
		return errors.New("expected cell is outside the fixed inventory")
	}
	if err := validateReleaseBinding(expected.Release, expected.Cell); err != nil {
		return fmt.Errorf("expected authenticated release: %w", err)
	}
	if !challengePattern.MatchString(expected.Challenge) {
		return errors.New("caller-selected challenge is invalid")
	}
	if expected.Kind == KindNativeIntegration {
		if expected.HostRoute != "physical-windows-remote" && expected.HostRoute != "physical-macos-remote" {
			return errors.New("expected physical game host route is invalid")
		}
	} else if expected.HostRoute != "" {
		return errors.New("non-integration expected cell cannot select a game host route")
	}
	if expected.Kind == KindPackageLifecycle {
		if !digestPattern.MatchString(expected.PackageSHA256) {
			return errors.New("expected authenticated published package digest is required")
		}
	} else if expected.PackageSHA256 != "" {
		return errors.New("non-lifecycle expected cell cannot select a package digest")
	}
	return nil
}

type artifactSnapshot struct {
	input ArtifactInput
	item  artifact
	info  os.FileInfo
}

func verifyArtifacts(ctx context.Context, inputs []ArtifactInput, declared []artifact) ([]artifactSnapshot, error) {
	if len(inputs) != len(declared) {
		return nil, errors.New("raw artifact input count does not match signed payload")
	}
	inputs = append([]ArtifactInput(nil), inputs...)
	result := make([]artifactSnapshot, 0, len(inputs))
	seenDigests := map[string]bool{}
	var total int64
	for i, input := range inputs {
		item := declared[i]
		if input.Kind != item.Kind || !filepath.IsAbs(input.Path) {
			return nil, fmt.Errorf("raw artifact %d kind or path differs from signed payload", i)
		}
		hash, size, info, err := hashArtifact(ctx, input.Path)
		if err != nil {
			return nil, fmt.Errorf("read raw artifact %q: %w", input.Kind, err)
		}
		if size != item.SizeBytes || hash != item.SHA256 {
			return nil, fmt.Errorf("raw artifact %q bytes differ from signed digest", input.Kind)
		}
		if seenDigests[hash] {
			return nil, errors.New("different artifact kinds cannot reuse identical raw bytes")
		}
		for _, prior := range result {
			if os.SameFile(prior.info, info) {
				return nil, errors.New("different artifact kinds cannot reuse one raw file")
			}
		}
		seenDigests[hash] = true
		total += size
		if total > MaxArtifactSet {
			return nil, errors.New("raw artifact set exceeds total size bound")
		}
		result = append(result, artifactSnapshot{input, item, info})
	}
	return result, nil
}

func recheckArtifacts(ctx context.Context, snapshots []artifactSnapshot) error {
	for _, snapshot := range snapshots {
		hash, size, info, err := hashArtifact(ctx, snapshot.input.Path)
		if err != nil {
			return err
		}
		if !os.SameFile(snapshot.info, info) || size != snapshot.item.SizeBytes || hash != snapshot.item.SHA256 {
			return fmt.Errorf("artifact %q changed", snapshot.item.Kind)
		}
	}
	return nil
}

func hashArtifact(ctx context.Context, path string) (string, int64, os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return "", 0, nil, err
	}
	file, err := fileinput.OpenRegular(path)
	if err != nil {
		return "", 0, nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > MaxArtifactSize {
		return "", 0, nil, errors.New("artifact must be a nonempty bounded regular file")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(contextReader{ctx, file}, MaxArtifactSize+1))
	if err != nil {
		return "", 0, nil, err
	}
	if size != before.Size() {
		return "", 0, nil, errors.New("artifact size changed while hashing")
	}
	after, err := file.Stat()
	if err != nil {
		return "", 0, nil, err
	}
	pathAfter, err := os.Lstat(path)
	if err != nil || fileinput.RejectSymlinkedParents(path) != nil ||
		!after.Mode().IsRegular() || !pathAfter.Mode().IsRegular() ||
		!os.SameFile(before, after) || !os.SameFile(before, pathAfter) ||
		after.Size() != size || pathAfter.Size() != size ||
		!before.ModTime().Equal(after.ModTime()) {
		return "", 0, nil, errors.New("artifact changed while hashing")
	}
	if err := ctx.Err(); err != nil {
		return "", 0, nil, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, before, nil
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

func verifySignatures(signatures []signature, payloadData []byte, payload observation, policy trustPolicy, now time.Time) error {
	if len(signatures) != 2 {
		return errors.New("exact observer and reviewer signatures are required")
	}
	keys := make(map[string]trustedKey, len(policy.Keys))
	for _, key := range policy.Keys {
		keys[key.KeyID] = key
	}
	created, _ := canonicalTime("created_at", payload.CreatedAt)
	expires, _ := canonicalTime("expires_at", payload.ExpiresAt)
	previousSignedAt := time.Time{}
	var previousPrincipal, previousOrganization string
	for i, item := range signatures {
		key, found := keys[item.KeyID]
		if !found || key.Revoked {
			return fmt.Errorf("signature %d uses untrusted or revoked key", i)
		}
		role := roleObserver
		if i == 1 {
			role = roleReviewer
		}
		if key.Role != role || !containsScope(key.Scopes, scopeKey(payload.Kind, payload.Cell)) {
			return fmt.Errorf("signature %d key is outside role or target scope", i)
		}
		if i == 1 && (key.PrincipalID == previousPrincipal || key.OrganizationID == previousOrganization) {
			return errors.New("reviewer must have distinct principal and organization")
		}
		signedAt, _ := canonicalTime("signed_at", item.SignedAt)
		keyStart, _ := canonicalTime("key not_before", key.NotBefore)
		keyEnd, _ := canonicalTime("key not_after", key.NotAfter)
		if keyStart.After(created) || keyEnd.Before(expires) ||
			signedAt.Before(keyStart) || !signedAt.Before(keyEnd) ||
			signedAt.Before(created) || !signedAt.Before(expires) || signedAt.After(now) {
			return fmt.Errorf("signature %d is outside observation or key validity", i)
		}
		if i == 1 && !signedAt.After(previousSignedAt) {
			return errors.New("independent review signature must follow observer signature")
		}
		publicKey, _ := lowerHex("public_key", key.PublicKey, ed25519.PublicKeySize)
		signatureBytes, _ := lowerHex("signature", item.Signature, ed25519.SignatureSize)
		preimage := reviewercrypto.SignaturePreimage(signatureDomain, PayloadType, item.KeyID, item.SignedAt, payloadData)
		if !ed25519.Verify(ed25519.PublicKey(publicKey), preimage, signatureBytes) {
			return fmt.Errorf("signature %d does not authenticate exact payload bytes", i)
		}
		previousSignedAt = signedAt
		previousPrincipal, previousOrganization = key.PrincipalID, key.OrganizationID
	}
	return nil
}

func sha256Hex(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}

// VerifyCompleteSet authenticates only exact cell coverage and retained raw
// bytes for one kind and one release. It cannot turn an observation into
// production readiness credit without independently governed source proofs.
func VerifyCompleteSet(ctx context.Context, kind Kind, observations []VerifiedObservation, policy TrustPolicy) (VerifiedSet, error) {
	return VerifyCompleteSetAt(ctx, kind, observations, policy, time.Now())
}

func VerifyCompleteSetAt(ctx context.Context, kind Kind, observations []VerifiedObservation, policy TrustPolicy, now time.Time) (VerifiedSet, error) {
	if ctx == nil || now.IsZero() || !policy.valid {
		return VerifiedSet{}, errors.New("context, time, and validated policy are required")
	}
	if err := ctx.Err(); err != nil {
		return VerifiedSet{}, err
	}
	if err := validateTrustPolicy(policy.policy); err != nil || policy.policy.Status != policyActive {
		return VerifiedSet{}, errors.New("complete set requires a provisioned validated policy")
	}
	policyStart, _ := canonicalTime("policy valid_from", policy.policy.ValidFrom)
	policyEnd, _ := canonicalTime("policy expires_at", policy.policy.ExpiresAt)
	now = now.UTC()
	if now.Before(policyStart) || !now.Before(policyEnd) {
		return VerifiedSet{}, errors.New("policy is not valid at set verification time")
	}
	cells := ExpectedCells(kind)
	if len(cells) == 0 || len(observations) != len(cells) {
		return VerifiedSet{}, errors.New("observation set does not have the exact fixed cell count")
	}
	ordered := make([]VerifiedObservation, len(cells))
	seenCells := map[Cell]bool{}
	seenObservations := map[string]bool{}
	seenRuns := map[string]bool{}
	seenChallenges := map[string]bool{}
	releaseByTarget := map[string]ReleaseBinding{}
	seenPackages := map[string]bool{}
	first := observations[0]
	for i, item := range observations {
		if !item.valid || item.kind != kind || item.policyID != policy.policy.ID || item.policyDigest != policyDigest(policy.policy) ||
			item.createdAt.After(now) || now.Before(item.verifiedAt) || !now.Before(item.expiresAt) {
			return VerifiedSet{}, fmt.Errorf("observation %d is invalid, expired, earlier than its authenticated verification, or belongs to another policy", i)
		}
		if item.release.Version != first.release.Version || item.release.Commit != first.release.Commit ||
			item.release.Tree != first.release.Tree || item.release.ReleaseID != first.release.ReleaseID {
			return VerifiedSet{}, errors.New("observation set mixes releases")
		}
		if seenCells[item.cell] || seenObservations[item.observationID] || seenRuns[item.runID] || seenChallenges[item.challenge] {
			return VerifiedSet{}, errors.New("observation set repeats a cell, observation, run, or challenge")
		}
		target := item.cell.GOOS + "/" + item.cell.GOARCH
		if prior, found := releaseByTarget[target]; found && prior != item.release {
			return VerifiedSet{}, errors.New("package families for one target disagree on authenticated archive or executable")
		}
		releaseByTarget[target] = item.release
		if kind == KindPackageLifecycle {
			if seenPackages[item.packageSHA256] {
				return VerifiedSet{}, errors.New("lifecycle set repeats one published package digest across cells")
			}
			seenPackages[item.packageSHA256] = true
		}
		seenCells[item.cell], seenObservations[item.observationID], seenRuns[item.runID], seenChallenges[item.challenge] = true, true, true, true
		cellIndex := -1
		for j, cell := range cells {
			if item.cell == cell {
				cellIndex = j
				break
			}
		}
		if cellIndex < 0 {
			return VerifiedSet{}, errors.New("observation set contains an unsupported cell")
		}
		current, err := verifyArtifacts(ctx, item.artifactInputs, item.artifacts)
		if err != nil {
			return VerifiedSet{}, fmt.Errorf("recheck observation %d artifacts: %w", i, err)
		}
		if err := recheckArtifacts(ctx, current); err != nil {
			return VerifiedSet{}, fmt.Errorf("recheck observation %d artifacts: %w", i, err)
		}
		ordered[cellIndex] = item
	}
	if len(seenCells) != len(cells) {
		return VerifiedSet{}, errors.New("observation set is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return VerifiedSet{}, err
	}
	return VerifiedSet{valid: true, kind: kind, releaseVersion: first.release.Version,
		releaseCommit: first.release.Commit, releaseTree: first.release.Tree,
		releaseID: first.release.ReleaseID, policyID: policy.policy.ID,
		observations: ordered}, nil
}
