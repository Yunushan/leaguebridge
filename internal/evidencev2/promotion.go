package evidencev2

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/target"
)

const (
	// ReadinessPromotionSchemaID identifies the derived v4 remote-readiness
	// result. It is an output contract, not a trust root: callers must obtain
	// the input VerifiedSet from VerifySetAt with the application-owned policy.
	ReadinessPromotionSchemaID = "https://leaguebridge.dev/schemas/readiness-promotion-v4.schema.json"
	ReadinessPromotionVersion  = 4
	ReadinessPromotionType     = "validation-evidence-v2"
	ReadinessPromotionState    = "validated"
	ReadinessPromotionBoundary = "readiness-schema-v4"
	ReadinessGateWeight        = 25
)

var promotionDigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ReadinessGate is a derived remote-handoff gate. It cannot be constructed by
// parsing a user-supplied scorecard; PromoteRemoteSetAt creates the fixed
// ordered set only from an opaque, successfully authenticated VerifiedSet.
type ReadinessGate struct {
	ID     string `json:"id"`
	Weight int    `json:"weight"`
	Passed bool   `json:"passed"`
}

// ReadinessPromotion is the score-bearing v4 result for one route/client cell.
// The result is meaningful only when produced by PromoteRemoteSetAt from a
// VerifiedSet. Its fields are deliberately bound to the v2 proof identity so a
// later consumer cannot select a different route or client cell.
type ReadinessPromotion struct {
	Schema                string          `json:"$schema"`
	SchemaVersion         int             `json:"schema_version"`
	EvidenceType          string          `json:"evidence_type"`
	PromotionBoundary     string          `json:"promotion_boundary"`
	SetID                 string          `json:"set_id"`
	ValidationRunID       string          `json:"validation_run_id"`
	RouteID               string          `json:"route_id"`
	TestProfileID         string          `json:"test_profile_id"`
	PolicyID              string          `json:"policy_id"`
	CreatedAt             string          `json:"created_at"`
	ExpiresAt             string          `json:"expires_at"`
	ManifestAsOf          string          `json:"manifest_as_of"`
	ManifestSHA256        string          `json:"manifest_sha256"`
	HostPlatform          string          `json:"host_platform"`
	HostArchitecture      string          `json:"host_architecture"`
	ClientPlatform        string          `json:"client_platform"`
	ClientArchitecture    string          `json:"client_architecture"`
	HostRecordSHA256      string          `json:"host_record_sha256"`
	ClientRecordSHA256    string          `json:"client_record_sha256"`
	SessionRecordSHA256   string          `json:"session_record_sha256"`
	PayloadSHA256         string          `json:"payload_sha256"`
	Score                 int             `json:"score"`
	State                 string          `json:"state"`
	PromotionSafe         bool            `json:"promotion_safe"`
	Gates                 []ReadinessGate `json:"gates"`
	SignerKeyIDs          []string        `json:"signer_key_ids"`
	SignerPrincipalIDs    []string        `json:"signer_principal_ids"`
	SignerOrganizationIDs []string        `json:"signer_organization_ids"`
}

var readinessGateIDs = [...]string{
	"physical-host",
	"client-runtime",
	"session-quality",
	"gameplay-interaction",
}

// PromoteRemoteSetAt derives a readiness-schema-v4 result from an already
// authenticated evidence-v2 proof. VerifySetAt remains the only constructor
// of a valid proof; an invalid, expired, unsupported, or incomplete proof is
// rejected here as a second boundary check.
func PromoteRemoteSetAt(set VerifiedSet, now time.Time) (ReadinessPromotion, error) {
	if !set.Valid() {
		return ReadinessPromotion{}, errors.New("a valid authenticated evidence v2 set is required")
	}
	if now.IsZero() {
		return ReadinessPromotion{}, errors.New("promotion evaluation time is required")
	}
	now = now.UTC()
	if set.createdAt.IsZero() || set.expiresAt.IsZero() {
		return ReadinessPromotion{}, errors.New("authenticated evidence v2 set has no validity interval")
	}
	if now.Before(set.createdAt) {
		return ReadinessPromotion{}, errors.New("authenticated evidence v2 set is not yet valid")
	}
	if !now.Before(set.expiresAt) {
		return ReadinessPromotion{}, errors.New("authenticated evidence v2 set has expired")
	}
	if set.testProfileID != TestProfileRemotePlayV1 {
		return ReadinessPromotion{}, fmt.Errorf("unsupported authenticated evidence profile %q", set.testProfileID)
	}
	if !validPromotionCell(set) {
		return ReadinessPromotion{}, fmt.Errorf("authenticated evidence v2 set has unsupported route cell %s/%s/%s", set.routeID, set.clientPlatform, set.clientArchitecture)
	}
	if !promotionDigestPattern.MatchString(set.manifestSHA256) ||
		!promotionDigestPattern.MatchString(set.hostRecordSHA256) ||
		!promotionDigestPattern.MatchString(set.clientRecordSHA256) ||
		!promotionDigestPattern.MatchString(set.sessionRecordSHA256) ||
		!promotionDigestPattern.MatchString(set.payloadSHA256) {
		return ReadinessPromotion{}, errors.New("authenticated evidence v2 set has an invalid digest binding")
	}
	if len(set.signerKeyIDs) < MinSignatures || len(set.signerKeyIDs) != len(set.signerPrincipalIDs) || len(set.signerKeyIDs) != len(set.signerOrganizationIDs) {
		return ReadinessPromotion{}, errors.New("authenticated evidence v2 set has incomplete signer metadata")
	}
	if strings.TrimSpace(set.policyID) == "" || strings.TrimSpace(set.setID) == "" || strings.TrimSpace(set.validationRunID) == "" {
		return ReadinessPromotion{}, errors.New("authenticated evidence v2 set has incomplete identity bindings")
	}

	gates := make([]ReadinessGate, 0, len(readinessGateIDs))
	for _, id := range readinessGateIDs {
		gates = append(gates, ReadinessGate{ID: id, Weight: ReadinessGateWeight, Passed: true})
	}
	return ReadinessPromotion{
		Schema:                ReadinessPromotionSchemaID,
		SchemaVersion:         ReadinessPromotionVersion,
		EvidenceType:          ReadinessPromotionType,
		PromotionBoundary:     ReadinessPromotionBoundary,
		SetID:                 set.setID,
		ValidationRunID:       set.validationRunID,
		RouteID:               set.routeID,
		TestProfileID:         set.testProfileID,
		PolicyID:              set.policyID,
		CreatedAt:             set.createdAt.UTC().Format(time.RFC3339),
		ExpiresAt:             set.expiresAt.UTC().Format(time.RFC3339),
		ManifestAsOf:          set.manifestAsOf,
		ManifestSHA256:        set.manifestSHA256,
		HostPlatform:          set.hostPlatform,
		HostArchitecture:      set.hostArchitecture,
		ClientPlatform:        set.clientPlatform,
		ClientArchitecture:    set.clientArchitecture,
		HostRecordSHA256:      set.hostRecordSHA256,
		ClientRecordSHA256:    set.clientRecordSHA256,
		SessionRecordSHA256:   set.sessionRecordSHA256,
		PayloadSHA256:         set.payloadSHA256,
		Score:                 len(gates) * ReadinessGateWeight,
		State:                 ReadinessPromotionState,
		PromotionSafe:         true,
		Gates:                 gates,
		SignerKeyIDs:          cloneStrings(set.signerKeyIDs),
		SignerPrincipalIDs:    cloneStrings(set.signerPrincipalIDs),
		SignerOrganizationIDs: cloneStrings(set.signerOrganizationIDs),
	}, nil
}

func validPromotionCell(set VerifiedSet) bool {
	if !target.IsSupportedEvidencePlatform(set.clientPlatform, set.clientArchitecture) {
		return false
	}
	switch set.routeID {
	case RoutePhysicalWindowsRemote:
		return set.hostPlatform == "windows" && set.hostArchitecture == "amd64"
	case RoutePhysicalMacOSRemote:
		return set.hostPlatform == "macos" && (set.hostArchitecture == "amd64" || set.hostArchitecture == "arm64")
	default:
		return false
	}
}
