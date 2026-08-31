package evidencev2

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/evidence"
)

const signatureDomain = "LeagueBridge/validation-evidence-set/v2\x00"

// VerifySet verifies an authenticated evidence set at the current time.
func VerifySet(envelopeData, hostData, clientData, sessionData []byte, expected ExpectedCell, verifications evidence.ArtifactVerificationSet, policy TrustPolicy) (VerifiedSet, error) {
	return VerifySetAt(envelopeData, hostData, clientData, sessionData, expected, verifications, policy, time.Now())
}

// VerifySetAt verifies the exact v1 record bytes, their opaque artifact
// verifications, every supplied Ed25519 signature, and the required two-role,
// two-principal, two-organization quorum under policy.
func VerifySetAt(envelopeData, hostData, clientData, sessionData []byte, expected ExpectedCell, verifications evidence.ArtifactVerificationSet, policy TrustPolicy, now time.Time) (VerifiedSet, error) {
	if now.IsZero() {
		return VerifiedSet{}, errors.New("verification time is required")
	}
	now = now.UTC()
	if !policy.valid {
		return VerifiedSet{}, errors.New("a validated application trust policy is required")
	}
	if err := validateTrustPolicy(policy.policy); err != nil {
		return VerifiedSet{}, fmt.Errorf("validate application trust policy: %w", err)
	}
	envelope, payloadBytes, payload, err := parseEnvelope(envelopeData)
	if err != nil {
		return VerifiedSet{}, err
	}
	if payload.PolicyID != policy.policy.PolicyID {
		return VerifiedSet{}, fmt.Errorf("payload policy_id %q does not match injected policy %q", payload.PolicyID, policy.policy.PolicyID)
	}
	if err := verifyExpectedCell(expected, payload); err != nil {
		return VerifiedSet{}, err
	}
	createdAt, _ := parseCanonicalTimestamp("created_at", payload.CreatedAt)
	expiresAt, _ := parseCanonicalTimestamp("expires_at", payload.ExpiresAt)
	if createdAt.After(now) {
		return VerifiedSet{}, errors.New("validation-evidence v2 payload creation time is in the future")
	}
	if !now.Before(expiresAt) {
		return VerifiedSet{}, errors.New("validation-evidence v2 payload has expired")
	}

	host, err := evidence.Parse(hostData)
	if err != nil {
		return VerifiedSet{}, fmt.Errorf("parse host evidence: %w", err)
	}
	client, err := evidence.Parse(clientData)
	if err != nil {
		return VerifiedSet{}, fmt.Errorf("parse client evidence: %w", err)
	}
	session, err := evidence.Parse(sessionData)
	if err != nil {
		return VerifiedSet{}, fmt.Errorf("parse session evidence: %w", err)
	}
	hostDigest := sha256Hex(hostData)
	clientDigest := sha256Hex(clientData)
	sessionDigest := sha256Hex(sessionData)
	for _, binding := range []struct {
		name string
		got  string
		want string
	}{
		{"host_record_sha256", payload.HostRecordSHA256, hostDigest},
		{"client_record_sha256", payload.ClientRecordSHA256, clientDigest},
		{"session_record_sha256", payload.SessionRecordSHA256, sessionDigest},
	} {
		if binding.got != binding.want {
			return VerifiedSet{}, fmt.Errorf("payload %s does not match the exact supplied record bytes", binding.name)
		}
	}
	if err := verifyRecordBindings(payload, host, client, session); err != nil {
		return VerifiedSet{}, err
	}

	evaluation, err := evidence.EvaluateVerifiedSetAt(host, client, session, hostDigest, clientDigest, verifications, now)
	if err != nil {
		return VerifiedSet{}, fmt.Errorf("evaluate artifact-verified evidence set: %w", err)
	}
	if evaluation.State != evidence.StateComplete {
		return VerifiedSet{}, fmt.Errorf("artifact-verified evidence set is %s: %s", evaluation.State, strings.Join(evaluation.Reasons, "; "))
	}
	if policy.policy.Status != policyProvisioned {
		return VerifiedSet{}, fmt.Errorf("trust policy %q is unprovisioned; records and artifacts are valid but authenticated promotion is unavailable", policy.policy.PolicyID)
	}
	policyStart, _ := parseCanonicalTimestamp("trust-policy valid_from", policy.policy.ValidFrom)
	policyEnd, _ := parseCanonicalTimestamp("trust-policy expires_at", policy.policy.ExpiresAt)
	if now.Before(policyStart) {
		return VerifiedSet{}, errors.New("trust policy is not yet valid")
	}
	if !now.Before(policyEnd) {
		return VerifiedSet{}, errors.New("trust policy has expired")
	}
	if createdAt.Before(policyStart) || expiresAt.After(policyEnd) {
		return VerifiedSet{}, errors.New("payload validity must be contained within trust-policy validity")
	}

	keys := make(map[string]trustedKey, len(policy.policy.Keys))
	for _, key := range policy.policy.Keys {
		keys[key.KeyID] = key
	}
	signers := make([]trustedKey, 0, len(envelope.Signatures))
	keyIDs := make([]string, 0, len(envelope.Signatures))
	principalIDs := make([]string, 0, len(envelope.Signatures))
	organizationIDs := make([]string, 0, len(envelope.Signatures))
	for index, item := range envelope.Signatures {
		key, trusted := keys[item.KeyID]
		if !trusted {
			return VerifiedSet{}, fmt.Errorf("signature %d uses untrusted key_id %q", index, item.KeyID)
		}
		if key.Revoked {
			return VerifiedSet{}, fmt.Errorf("signature %d uses revoked key_id %q", index, item.KeyID)
		}
		if !containsSorted(key.RouteIDs, payload.RouteID) || !containsSorted(key.ClientPlatforms, payload.ClientPlatform) || !containsSorted(key.Architectures, payload.ClientArchitecture) || !containsSorted(key.TestProfileIDs, payload.TestProfileID) {
			return VerifiedSet{}, fmt.Errorf("signature %d key_id %q is outside its route, client, architecture, or profile scope", index, item.KeyID)
		}
		signedAt, _ := parseCanonicalTimestamp(fmt.Sprintf("signature %d signed_at", index), item.SignedAt)
		keyStart, _ := parseCanonicalTimestamp("not_before", key.NotBefore)
		keyEnd, _ := parseCanonicalTimestamp("not_after", key.NotAfter)
		if keyStart.After(createdAt) || keyEnd.Before(expiresAt) {
			return VerifiedSet{}, fmt.Errorf("signature %d key_id %q validity does not cover the complete payload lifetime", index, item.KeyID)
		}
		if signedAt.Before(keyStart) || !signedAt.Before(keyEnd) {
			return VerifiedSet{}, fmt.Errorf("signature %d was made outside key %q validity", index, item.KeyID)
		}
		if signedAt.Before(policyStart) || !signedAt.Before(policyEnd) {
			return VerifiedSet{}, fmt.Errorf("signature %d was made outside trust-policy validity", index)
		}
		if signedAt.Before(createdAt) || !signedAt.Before(expiresAt) {
			return VerifiedSet{}, fmt.Errorf("signature %d signed_at must be within payload validity", index)
		}
		if signedAt.After(now) {
			return VerifiedSet{}, fmt.Errorf("signature %d signed_at is in the future", index)
		}
		if err := signatureFollowsRecordReviews(index, signedAt, host, client, session); err != nil {
			return VerifiedSet{}, err
		}
		publicKey, _ := decodeLowerHex("public_key", key.PublicKey, ed25519.PublicKeySize)
		signatureBytes, _ := decodeLowerHex("signature", item.Signature, ed25519.SignatureSize)
		preimage := signaturePreimage(envelope.PayloadType, item.KeyID, item.SignedAt, payloadBytes)
		if !ed25519.Verify(ed25519.PublicKey(publicKey), preimage, signatureBytes) {
			return VerifiedSet{}, fmt.Errorf("signature %d for key_id %q is invalid", index, item.KeyID)
		}
		signers = append(signers, key)
		keyIDs = append(keyIDs, key.KeyID)
		principalIDs = append(principalIDs, key.PrincipalID)
		organizationIDs = append(organizationIDs, key.OrganizationID)
	}
	if len(signers) < policy.policy.MinSignatures {
		return VerifiedSet{}, errors.New("valid signature count is below the trust-policy minimum")
	}
	if !hasIndependentQuorum(signers) {
		return VerifiedSet{}, errors.New("signatures do not provide lab-observer and independent-reviewer principals from distinct organizations")
	}

	payloadDigest := sha256Hex(payloadBytes)
	return VerifiedSet{
		valid:                 true,
		setID:                 payload.SetID,
		validationRunID:       payload.ValidationRunID,
		routeID:               payload.RouteID,
		testProfileID:         payload.TestProfileID,
		policyID:              payload.PolicyID,
		hostPlatform:          payload.HostPlatform,
		hostArchitecture:      payload.HostArchitecture,
		clientPlatform:        payload.ClientPlatform,
		clientArchitecture:    payload.ClientArchitecture,
		manifestAsOf:          payload.ManifestAsOf,
		manifestSHA256:        payload.ManifestSHA256,
		hostRecordSHA256:      payload.HostRecordSHA256,
		clientRecordSHA256:    payload.ClientRecordSHA256,
		sessionRecordSHA256:   payload.SessionRecordSHA256,
		payloadSHA256:         payloadDigest,
		createdAt:             createdAt,
		expiresAt:             expiresAt,
		signerKeyIDs:          keyIDs,
		signerPrincipalIDs:    principalIDs,
		signerOrganizationIDs: organizationIDs,
	}, nil
}

func verifyExpectedCell(expected ExpectedCell, payload payload) error {
	if expected.RouteID == "" || expected.ClientPlatform == "" || expected.ClientArchitecture == "" {
		return errors.New("expected route, client platform, and client architecture are required")
	}
	if expected.RouteID != payload.RouteID || expected.ClientPlatform != payload.ClientPlatform || expected.ClientArchitecture != payload.ClientArchitecture {
		return fmt.Errorf("payload cell %s/%s/%s does not match caller-expected cell %s/%s/%s", payload.RouteID, payload.ClientPlatform, payload.ClientArchitecture, expected.RouteID, expected.ClientPlatform, expected.ClientArchitecture)
	}
	return nil
}

func verifyRecordBindings(payload payload, host, client, session evidence.Record) error {
	for _, record := range []struct {
		name  string
		value evidence.Record
	}{
		{"host", host},
		{"client", client},
		{"session", session},
	} {
		if record.value.ValidationRunID != payload.ValidationRunID {
			return fmt.Errorf("%s record validation_run_id does not match payload", record.name)
		}
		if record.value.RouteID != payload.RouteID {
			return fmt.Errorf("%s record route_id does not match payload", record.name)
		}
		if record.value.TestProfileID != payload.TestProfileID {
			return fmt.Errorf("%s record test_profile_id does not match payload", record.name)
		}
		if record.value.ManifestAsOf != payload.ManifestAsOf || record.value.ManifestSHA256 != payload.ManifestSHA256 {
			return fmt.Errorf("%s record compatibility manifest binding does not match payload", record.name)
		}
	}
	if host.Subject.Platform != payload.HostPlatform || host.Subject.Architecture != payload.HostArchitecture {
		return errors.New("host record platform cell does not match payload")
	}
	if client.Subject.Platform != payload.ClientPlatform || client.Subject.Architecture != payload.ClientArchitecture {
		return errors.New("client record platform cell does not match payload")
	}
	if session.Subject.Platform != payload.ClientPlatform || session.Subject.Architecture != payload.ClientArchitecture {
		return errors.New("session record platform cell does not match payload")
	}
	payloadCreatedAt, err := parseCanonicalTimestamp("payload created_at", payload.CreatedAt)
	if err != nil {
		return err
	}
	payloadExpiresAt, err := parseCanonicalTimestamp("payload expires_at", payload.ExpiresAt)
	if err != nil {
		return err
	}
	sessionCreatedAt, err := parseRecordTimestamp("session created_at", session.CreatedAt)
	if err != nil {
		return err
	}
	sessionExpiresAt, err := parseRecordTimestamp("session expires_at", session.ExpiresAt)
	if err != nil {
		return err
	}
	if !sessionCreatedAt.Equal(payloadCreatedAt) || !sessionExpiresAt.Equal(payloadExpiresAt) {
		return errors.New("payload validity timestamps must match the session record instants")
	}
	return nil
}

func signatureFollowsRecordReviews(index int, signedAt time.Time, records ...evidence.Record) error {
	for _, record := range records {
		reviewedAt, err := parseRecordTimestamp(string(record.RecordType)+" attestation.reviewed_at", record.Attestation.ReviewedAt)
		if err != nil {
			return fmt.Errorf("signature %d cannot bind a record without an RFC3339 review timestamp: %w", index, err)
		}
		if signedAt.Before(reviewedAt) {
			return fmt.Errorf("signature %d predates the %s record review", index, record.RecordType)
		}
	}
	return nil
}

// Schema-v1 records permit every RFC3339 representation. The v2 envelope and
// payload use canonical whole-second UTC timestamps, but compare record times
// as instants so an exactly hash-bound v1 record does not need to be rewritten.
func parseRecordTimestamp(name, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339", name)
	}
	return parsed, nil
}

func hasIndependentQuorum(signers []trustedKey) bool {
	for _, lab := range signers {
		if lab.Role != roleLabObserver {
			continue
		}
		for _, independent := range signers {
			if independent.Role != roleIndependentReviewer {
				continue
			}
			if lab.KeyID != independent.KeyID && lab.PrincipalID != independent.PrincipalID && lab.OrganizationID != independent.OrganizationID {
				return true
			}
		}
	}
	return false
}

func signaturePreimage(payloadType, keyID, signedAt string, payloadBytes []byte) []byte {
	preimage := make([]byte, 0, len(signatureDomain)+32+len(payloadType)+len(keyID)+len(signedAt)+len(payloadBytes))
	preimage = append(preimage, signatureDomain...)
	preimage = appendLengthPrefixed(preimage, []byte(payloadType))
	preimage = appendLengthPrefixed(preimage, []byte(keyID))
	preimage = appendLengthPrefixed(preimage, []byte(signedAt))
	preimage = appendLengthPrefixed(preimage, payloadBytes)
	return preimage
}

func appendLengthPrefixed(destination, value []byte) []byte {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	destination = append(destination, length[:]...)
	return append(destination, value...)
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
