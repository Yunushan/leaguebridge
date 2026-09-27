package productionnative

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/reviewercrypto"
)

const maximumPolicyKeys = 16

type trustPolicy struct {
	ID        string
	Status    string
	ValidFrom string
	ExpiresAt string
	Keys      []trustedKey
}

type trustedKey struct {
	KeyID          string
	PublicKey      string
	PrincipalID    string
	OrganizationID string
	Role           string
	Scopes         []string
	NotBefore      string
	NotAfter       string
	Revoked        bool
}

var (
	idPattern            = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)
	objectIDPattern      = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	digestPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	observationIDPattern = regexp.MustCompile(`^observation-[0-9a-f]{32}$`)
	runIDPattern         = regexp.MustCompile(`^run-[0-9a-f]{32}$`)
	machineIDPattern     = regexp.MustCompile(`^machine-[0-9a-f]{32}$`)
	challengePattern     = regexp.MustCompile(`^challenge-[0-9a-f]{64}$`)
)

// ProductionTrustPolicy is deliberately unprovisioned. Real observer and
// reviewer keys require an independently reviewed application code change;
// neither user evidence nor JSON files can supply them here.
func ProductionTrustPolicy() TrustPolicy {
	policy, err := newTrustPolicy(trustPolicy{ID: policyID, Status: policyUnknown})
	if err != nil {
		return TrustPolicy{}
	}
	return policy
}

func newTrustPolicy(raw trustPolicy) (TrustPolicy, error) {
	if err := validateTrustPolicy(raw); err != nil {
		return TrustPolicy{}, err
	}
	cloned := raw
	cloned.Keys = make([]trustedKey, len(raw.Keys))
	for i, key := range raw.Keys {
		cloned.Keys[i] = key
		cloned.Keys[i].Scopes = append([]string(nil), key.Scopes...)
	}
	return TrustPolicy{policy: cloned, valid: true}, nil
}

func validateTrustPolicy(policy trustPolicy) error {
	if policy.ID != policyID {
		return fmt.Errorf("production native policy_id must be %q", policyID)
	}
	switch policy.Status {
	case policyUnknown:
		if policy.ValidFrom != "" || policy.ExpiresAt != "" || len(policy.Keys) != 0 {
			return errors.New("unprovisioned policy must contain no validity interval or keys")
		}
		return nil
	case policyActive:
	default:
		return errors.New("unknown production native policy status")
	}
	if len(policy.Keys) < 2 || len(policy.Keys) > maximumPolicyKeys {
		return fmt.Errorf("provisioned policy requires 2 to %d keys", maximumPolicyKeys)
	}
	start, err := canonicalTime("policy valid_from", policy.ValidFrom)
	if err != nil {
		return err
	}
	end, err := canonicalTime("policy expires_at", policy.ExpiresAt)
	if err != nil {
		return err
	}
	if !end.After(start) || end.Sub(start) > 366*24*time.Hour {
		return errors.New("policy validity must be positive and no longer than 366 days")
	}
	last := ""
	roles := map[string]bool{}
	principalRoles := map[string]bool{}
	for i, key := range policy.Keys {
		if i > 0 && key.KeyID <= last {
			return errors.New("policy keys must have unique, sorted key_id values")
		}
		last = key.KeyID
		if err := validateTrustedKey(key, start, end); err != nil {
			return fmt.Errorf("policy key %q: %w", key.KeyID, err)
		}
		principalRole := key.PrincipalID + "\x00" + key.Role
		if principalRoles[principalRole] {
			return errors.New("policy repeats a principal in the same role")
		}
		principalRoles[principalRole] = true
		if !key.Revoked {
			roles[key.Role] = true
		}
	}
	if !roles[roleObserver] || !roles[roleReviewer] {
		return errors.New("policy requires active observer and reviewer keys")
	}
	return nil
}

func validateTrustedKey(key trustedKey, policyStart, policyEnd time.Time) error {
	publicKey, err := lowerHex("public_key", key.PublicKey, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	if err := reviewercrypto.ValidateEd25519PublicKey(publicKey); err != nil {
		return err
	}
	if key.KeyID != deriveKeyID(publicKey) {
		return errors.New("key_id does not match public_key")
	}
	if !boundedID(key.PrincipalID) || !boundedID(key.OrganizationID) {
		return errors.New("principal_id and organization_id must be bounded lowercase identifiers")
	}
	if key.Role != roleObserver && key.Role != roleReviewer {
		return errors.New("key role must be lab-observer or independent-reviewer")
	}
	if len(key.Scopes) == 0 || len(key.Scopes) > 27 || !sort.StringsAreSorted(key.Scopes) {
		return errors.New("key scopes must be a nonempty sorted fixed-cell list")
	}
	previous := ""
	for _, scope := range key.Scopes {
		if scope == previous || !supportedScope(scope) {
			return fmt.Errorf("key has duplicate or unsupported scope %q", scope)
		}
		previous = scope
	}
	start, err := canonicalTime("key not_before", key.NotBefore)
	if err != nil {
		return err
	}
	end, err := canonicalTime("key not_after", key.NotAfter)
	if err != nil {
		return err
	}
	if !end.After(start) || start.Before(policyStart) || end.After(policyEnd) {
		return errors.New("key validity must be positive and inside policy validity")
	}
	return nil
}

func deriveKeyID(publicKey []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(keyIDDomain))
	_, _ = hash.Write(publicKey)
	return "lbn1-" + hex.EncodeToString(hash.Sum(nil))
}

func policyDigest(policy trustPolicy) string {
	data, _ := json.Marshal(policy)
	return sha256Hex(data)
}

func scopeKey(kind Kind, cell Cell) string {
	return string(kind) + ":" + cell.Family + ":" + cell.GOOS + "/" + cell.GOARCH
}

func supportedScope(scope string) bool {
	for _, kind := range []Kind{KindNativeIntegration, KindPhysicalBSD, KindPackageLifecycle} {
		for _, cell := range ExpectedCells(kind) {
			if scope == scopeKey(kind, cell) {
				return true
			}
		}
	}
	return false
}

func supportedCell(kind Kind, cell Cell) bool {
	for _, expected := range ExpectedCells(kind) {
		if expected == cell {
			return true
		}
	}
	return false
}

func boundedID(value string) bool {
	return len(value) > 0 && len(value) <= 128 && idPattern.MatchString(value)
}

func containsScope(scopes []string, scope string) bool {
	i := sort.SearchStrings(scopes, scope)
	return i < len(scopes) && scopes[i] == scope
}

func lowerHex(name, value string, size int) ([]byte, error) {
	if len(value) != 2*size || value != strings.ToLower(value) {
		return nil, fmt.Errorf("%s must be %d lowercase hexadecimal characters", name, 2*size)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not hexadecimal: %w", name, err)
	}
	return decoded, nil
}

func canonicalTime(name, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Nanosecond() != 0 || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("%s must be whole-second UTC RFC3339", name)
	}
	return parsed, nil
}
