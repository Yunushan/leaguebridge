package evidencev2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"filippo.io/edwards25519"
)

const (
	productionPolicyID = "leaguebridge-production-reviewers-v1"
	keyIDDomain        = "LeagueBridge/reviewer-key/v1\x00"
)

type trustPolicy struct {
	Schema                       string       `json:"$schema"`
	SchemaVersion                int          `json:"schema_version"`
	PolicyID                     string       `json:"policy_id"`
	Status                       string       `json:"status"`
	ValidFrom                    string       `json:"valid_from"`
	ExpiresAt                    string       `json:"expires_at"`
	RequiredRoles                []string     `json:"required_roles"`
	MinSignatures                int          `json:"min_signatures"`
	RequireDistinctPrincipals    bool         `json:"require_distinct_principals"`
	RequireDistinctOrganizations bool         `json:"require_distinct_organizations"`
	Keys                         []trustedKey `json:"keys"`
}

type trustedKey struct {
	KeyID           string   `json:"key_id"`
	Algorithm       string   `json:"algorithm"`
	PublicKey       string   `json:"public_key"`
	PrincipalID     string   `json:"principal_id"`
	OrganizationID  string   `json:"organization_id"`
	Role            string   `json:"role"`
	RouteIDs        []string `json:"route_ids"`
	ClientPlatforms []string `json:"client_platforms"`
	Architectures   []string `json:"architectures"`
	TestProfileIDs  []string `json:"test_profile_ids"`
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	Revoked         bool     `json:"revoked"`
}

var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)

// ProductionTrustPolicy returns the application-owned production policy. The
// current policy is deliberately unprovisioned: real reviewer public keys must
// be established through the separate governance process before promotion is
// possible.
func ProductionTrustPolicy() TrustPolicy {
	policy, err := newTrustPolicy(trustPolicy{
		Schema:                       TrustPolicySchemaID,
		SchemaVersion:                PolicyVersion,
		PolicyID:                     productionPolicyID,
		Status:                       policyUnprovisioned,
		RequiredRoles:                []string{roleLabObserver, roleIndependentReviewer},
		MinSignatures:                MinSignatures,
		RequireDistinctPrincipals:    true,
		RequireDistinctOrganizations: true,
		Keys:                         []trustedKey{},
	})
	if err != nil {
		return TrustPolicy{}
	}
	return policy
}

func newTrustPolicy(raw trustPolicy) (TrustPolicy, error) {
	if err := validateTrustPolicy(raw); err != nil {
		return TrustPolicy{}, err
	}
	return TrustPolicy{policy: cloneTrustPolicy(raw), valid: true}, nil
}

func validateTrustPolicy(policy trustPolicy) error {
	if policy.Schema != TrustPolicySchemaID {
		return fmt.Errorf("unknown trust-policy $schema %q", policy.Schema)
	}
	if policy.SchemaVersion != PolicyVersion {
		return fmt.Errorf("unsupported trust-policy schema_version %d", policy.SchemaVersion)
	}
	if !validSlug(policy.PolicyID, 128) {
		return errors.New("trust-policy policy_id must be a bounded lowercase identifier")
	}
	if len(policy.RequiredRoles) != 2 || policy.RequiredRoles[0] != roleLabObserver || policy.RequiredRoles[1] != roleIndependentReviewer {
		return errors.New("trust-policy required_roles must be exactly lab-observer then independent-reviewer")
	}
	if policy.MinSignatures != MinSignatures {
		return fmt.Errorf("trust-policy min_signatures must be %d", MinSignatures)
	}
	if !policy.RequireDistinctPrincipals || !policy.RequireDistinctOrganizations {
		return errors.New("trust-policy must require distinct principals and organizations")
	}

	switch policy.Status {
	case policyUnprovisioned:
		if policy.ValidFrom != "" || policy.ExpiresAt != "" || len(policy.Keys) != 0 {
			return errors.New("unprovisioned trust policy must have empty validity timestamps and keys")
		}
		return nil
	case policyProvisioned:
	default:
		return fmt.Errorf("invalid trust-policy status %q", policy.Status)
	}
	if len(policy.Keys) < MinSignatures || len(policy.Keys) > MaxPolicyKeys {
		return fmt.Errorf("provisioned trust policy must contain between %d and %d keys", MinSignatures, MaxPolicyKeys)
	}
	validFrom, err := parseCanonicalTimestamp("trust-policy valid_from", policy.ValidFrom)
	if err != nil {
		return err
	}
	expiresAt, err := parseCanonicalTimestamp("trust-policy expires_at", policy.ExpiresAt)
	if err != nil {
		return err
	}
	if !expiresAt.After(validFrom) {
		return errors.New("trust-policy expires_at must follow valid_from")
	}

	roleCounts := map[string]int{}
	previousID := ""
	seenPrincipalRole := make(map[string]struct{})
	for index, key := range policy.Keys {
		if index > 0 && key.KeyID <= previousID {
			return errors.New("trust-policy keys must be strictly sorted by unique key_id")
		}
		previousID = key.KeyID
		if err := validateTrustedKey(key, validFrom, expiresAt); err != nil {
			return fmt.Errorf("trust-policy key %q: %w", key.KeyID, err)
		}
		principalRole := key.PrincipalID + "\x00" + key.Role
		if _, duplicate := seenPrincipalRole[principalRole]; duplicate {
			return fmt.Errorf("trust-policy repeats principal %q for role %q", key.PrincipalID, key.Role)
		}
		seenPrincipalRole[principalRole] = struct{}{}
		roleCounts[key.Role]++
	}
	for _, role := range policy.RequiredRoles {
		if roleCounts[role] == 0 {
			return fmt.Errorf("trust-policy has no key for required role %q", role)
		}
	}
	return nil
}

func validateTrustedKey(key trustedKey, policyStart, policyEnd time.Time) error {
	if key.Algorithm != Algorithm {
		return fmt.Errorf("algorithm must be %q", Algorithm)
	}
	publicKey, err := decodeLowerHex("public_key", key.PublicKey, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	if err := validateReviewerPublicKey(publicKey); err != nil {
		return err
	}
	if want := deriveKeyID(publicKey); key.KeyID != want {
		return fmt.Errorf("key_id %q does not match the derived public-key ID %q", key.KeyID, want)
	}
	if !validSlug(key.PrincipalID, 128) {
		return errors.New("principal_id must be a bounded lowercase identifier")
	}
	if !validSlug(key.OrganizationID, 128) {
		return errors.New("organization_id must be a bounded lowercase identifier")
	}
	if key.Role != roleLabObserver && key.Role != roleIndependentReviewer {
		return fmt.Errorf("unsupported role %q", key.Role)
	}
	if err := validateSortedScope("route_ids", key.RouteIDs, map[string]bool{
		RoutePhysicalWindowsRemote: true,
		"physical-macos-remote":    true,
	}); err != nil {
		return err
	}
	if err := validateSortedScope("client_platforms", key.ClientPlatforms, supportedClientPlatforms); err != nil {
		return err
	}
	if err := validateSortedScope("architectures", key.Architectures, map[string]bool{"amd64": true, "arm64": true}); err != nil {
		return err
	}
	if len(key.TestProfileIDs) != 1 || key.TestProfileIDs[0] != TestProfileRemotePlayV1 {
		return fmt.Errorf("test_profile_ids must be exactly [%s]", TestProfileRemotePlayV1)
	}
	notBefore, err := parseCanonicalTimestamp("not_before", key.NotBefore)
	if err != nil {
		return err
	}
	notAfter, err := parseCanonicalTimestamp("not_after", key.NotAfter)
	if err != nil {
		return err
	}
	if !notAfter.After(notBefore) {
		return errors.New("not_after must follow not_before")
	}
	if notBefore.Before(policyStart) || notAfter.After(policyEnd) {
		return errors.New("key validity must be contained within trust-policy validity")
	}
	return nil
}

// validateReviewerPublicKey rejects encodings that crypto/ed25519 deliberately
// accepts for ecosystem compatibility but that are unsafe reviewer identities.
// In particular, a low-order key can admit signatures without knowledge of a
// private scalar, and a point with a torsion component is not a prime-subgroup
// identity even when its encoding is unique at the byte level.
func validateReviewerPublicKey(publicKey []byte) error {
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return errors.New("public_key must encode a valid Edwards25519 point")
	}
	if !bytes.Equal(point.Bytes(), publicKey) {
		return errors.New("public_key must use the canonical Edwards25519 encoding")
	}
	if point.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("public_key must not be the Edwards25519 identity")
	}

	// Decompose A = P + T into its prime-order and torsion components without
	// implementing curve arithmetic locally. Multiplication by eight removes T;
	// multiplying that result by 8^-1 modulo the prime subgroup order recovers P.
	// The original point is in the prime-order subgroup exactly when A == P.
	eightEncoding := make([]byte, ed25519.PublicKeySize)
	eightEncoding[0] = 8
	eight, err := new(edwards25519.Scalar).SetCanonicalBytes(eightEncoding)
	if err != nil {
		return errors.New("initialize Edwards25519 subgroup validation")
	}
	inverseEight := new(edwards25519.Scalar).Invert(eight)
	primeComponent := new(edwards25519.Point).ScalarMult(
		inverseEight,
		new(edwards25519.Point).MultByCofactor(point),
	)
	if point.Equal(primeComponent) != 1 {
		return errors.New("public_key must be in the prime-order Edwards25519 subgroup")
	}
	return nil
}

func validateSortedScope(name string, values []string, allowed map[string]bool) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must not be empty", name)
	}
	if !sort.StringsAreSorted(values) {
		return fmt.Errorf("%s must be sorted", name)
	}
	previous := ""
	for _, value := range values {
		if !allowed[value] {
			return fmt.Errorf("%s contains unsupported value %q", name, value)
		}
		if value == previous {
			return fmt.Errorf("%s contains duplicate value %q", name, value)
		}
		previous = value
	}
	return nil
}

func deriveKeyID(publicKey []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(keyIDDomain))
	_, _ = digest.Write(publicKey)
	return "lbk1-" + hex.EncodeToString(digest.Sum(nil))
}

func cloneTrustPolicy(policy trustPolicy) trustPolicy {
	cloned := policy
	cloned.RequiredRoles = cloneStrings(policy.RequiredRoles)
	cloned.Keys = make([]trustedKey, len(policy.Keys))
	for index, key := range policy.Keys {
		cloned.Keys[index] = key
		cloned.Keys[index].RouteIDs = cloneStrings(key.RouteIDs)
		cloned.Keys[index].ClientPlatforms = cloneStrings(key.ClientPlatforms)
		cloned.Keys[index].Architectures = cloneStrings(key.Architectures)
		cloned.Keys[index].TestProfileIDs = cloneStrings(key.TestProfileIDs)
	}
	return cloned
}

func validSlug(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && slugPattern.MatchString(value)
}

func containsSorted(values []string, want string) bool {
	index := sort.SearchStrings(values, want)
	return index < len(values) && values[index] == want
}

func decodeLowerHex(name, value string, size int) ([]byte, error) {
	if len(value) != size*2 || value != strings.ToLower(value) {
		return nil, fmt.Errorf("%s must be %d lowercase hexadecimal characters", name, size*2)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be lowercase hexadecimal: %w", name, err)
	}
	return decoded, nil
}
