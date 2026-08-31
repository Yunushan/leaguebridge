package evidencev2

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/evidence"
)

// PrepareRequest contains the exact schema-v1 bytes and artifact verification
// tokens from one physical-host validation run. The request deliberately does
// not contain private keys or signature material: reviewers sign the returned
// payload through their separately governed process.
type PrepareRequest struct {
	HostData      []byte
	ClientData    []byte
	SessionData   []byte
	Expected      ExpectedCell
	Verifications evidence.ArtifactVerificationSet
	SetID         string
	PolicyID      string
}

// PreparePayloadAt verifies a complete artifact-backed v1 record set and
// emits the exact score-free v2 payload bytes that external reviewers can sign.
// It never signs, authenticates, or promotes the result. The returned bytes
// are intentionally the bytes that must be base64url-encoded into an envelope;
// callers must not parse and re-serialize them before signing.
func PreparePayloadAt(request PrepareRequest, now time.Time) ([]byte, error) {
	if now.IsZero() {
		return nil, errors.New("preparation time is required")
	}
	if strings.TrimSpace(request.PolicyID) == "" {
		return nil, errors.New("policy ID is required")
	}
	host, err := evidence.Parse(request.HostData)
	if err != nil {
		return nil, fmt.Errorf("parse host evidence: %w", err)
	}
	client, err := evidence.Parse(request.ClientData)
	if err != nil {
		return nil, fmt.Errorf("parse client evidence: %w", err)
	}
	session, err := evidence.Parse(request.SessionData)
	if err != nil {
		return nil, fmt.Errorf("parse session evidence: %w", err)
	}
	hostDigest := sha256Hex(request.HostData)
	clientDigest := sha256Hex(request.ClientData)
	sessionDigest := sha256Hex(request.SessionData)
	evaluation, err := evidence.EvaluateVerifiedSetAt(
		host,
		client,
		session,
		hostDigest,
		clientDigest,
		request.Verifications,
		now,
	)
	if err != nil {
		return nil, fmt.Errorf("evaluate artifact-verified evidence set: %w", err)
	}
	if evaluation.State != evidence.StateComplete {
		return nil, fmt.Errorf("artifact-verified evidence set is %s: %s", evaluation.State, strings.Join(evaluation.Reasons, "; "))
	}

	createdAt, err := canonicalRecordInstant("session created_at", session.CreatedAt)
	if err != nil {
		return nil, err
	}
	expiresAt, err := canonicalRecordInstant("session expires_at", session.ExpiresAt)
	if err != nil {
		return nil, err
	}
	setID := strings.TrimSpace(request.SetID)
	if setID == "" {
		setID, err = newSetID()
		if err != nil {
			return nil, err
		}
	}
	if !setIDPattern.MatchString(setID) {
		return nil, fmt.Errorf("invalid set_id %q", setID)
	}

	prepared := payload{
		Schema:              PayloadSchemaID,
		SchemaVersion:       PayloadVersion,
		SetID:               setID,
		ValidationRunID:     host.ValidationRunID,
		RouteID:             host.RouteID,
		TestProfileID:       host.TestProfileID,
		PolicyID:            request.PolicyID,
		CreatedAt:           createdAt,
		ExpiresAt:           expiresAt,
		ManifestAsOf:        host.ManifestAsOf,
		ManifestSHA256:      host.ManifestSHA256,
		HostPlatform:        host.Subject.Platform,
		HostArchitecture:    host.Subject.Architecture,
		ClientPlatform:      client.Subject.Platform,
		ClientArchitecture:  client.Subject.Architecture,
		HostRecordSHA256:    hostDigest,
		ClientRecordSHA256:  clientDigest,
		SessionRecordSHA256: sessionDigest,
	}
	data, err := json.MarshalIndent(prepared, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode validation-evidence v2 payload: %w", err)
	}
	data = append(data, '\n')
	if len(data) > MaxPayloadSize {
		return nil, fmt.Errorf("prepared validation-evidence v2 payload exceeds %d bytes", MaxPayloadSize)
	}
	parsed, err := parsePayload(data)
	if err != nil {
		return nil, fmt.Errorf("validate prepared validation-evidence v2 payload: %w", err)
	}
	if err := verifyExpectedCell(request.Expected, parsed); err != nil {
		return nil, err
	}
	if err := verifyRecordBindings(parsed, host, client, session); err != nil {
		return nil, err
	}
	return data, nil
}

func canonicalRecordInstant(name, value string) (string, error) {
	parsed, err := parseRecordTimestamp(name, value)
	if err != nil {
		return "", err
	}
	if parsed.Nanosecond() != 0 {
		return "", fmt.Errorf("%s must have whole-second precision before v2 preparation", name)
	}
	return parsed.UTC().Format(time.RFC3339), nil
}

func newSetID() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate validation-evidence v2 set id: %w", err)
	}
	return "set-" + hex.EncodeToString(random), nil
}
