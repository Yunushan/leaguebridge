// Package evidencev2 authenticates complete validation-evidence v1 record sets
// with a bounded, detached Ed25519 envelope. Trust roots are injected by the
// application; neither the payload nor its envelope can introduce a key.
package evidencev2

import "time"

const (
	EnvelopeSchemaID    = "https://leaguebridge.dev/schemas/evidence-signature-envelope.schema.json"
	PayloadSchemaID     = "https://leaguebridge.dev/schemas/validation-evidence-v2.schema.json"
	TrustPolicySchemaID = "https://leaguebridge.dev/schemas/evidence-trust-policy.schema.json"

	EnvelopeVersion = 1
	PayloadVersion  = 2
	PolicyVersion   = 1

	PayloadType     = "leaguebridge.validation-evidence-set.v2"
	PayloadEncoding = "base64url-nopad"
	Algorithm       = "ed25519"

	RoutePhysicalWindowsRemote = "physical-windows-remote"
	TestProfileRemotePlayV1    = "remote-play-v1"

	MaxEnvelopeSize = 256 << 10
	MaxPayloadSize  = 64 << 10
	MinSignatures   = 2
	MaxSignatures   = 8
	MaxPolicyKeys   = 8
)

const (
	roleLabObserver         = "lab-observer"
	roleIndependentReviewer = "independent-reviewer"
	policyUnprovisioned     = "unprovisioned"
	policyProvisioned       = "provisioned"
)

type signatureEnvelope struct {
	Schema          string      `json:"$schema"`
	EnvelopeVersion int         `json:"envelope_version"`
	PayloadType     string      `json:"payload_type"`
	PayloadEncoding string      `json:"payload_encoding"`
	Payload         string      `json:"payload"`
	Signatures      []signature `json:"signatures"`
}

type signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	SignedAt  string `json:"signed_at"`
	Signature string `json:"signature"`
}

type payload struct {
	Schema              string `json:"$schema"`
	SchemaVersion       int    `json:"schema_version"`
	SetID               string `json:"set_id"`
	ValidationRunID     string `json:"validation_run_id"`
	RouteID             string `json:"route_id"`
	TestProfileID       string `json:"test_profile_id"`
	PolicyID            string `json:"policy_id"`
	CreatedAt           string `json:"created_at"`
	ExpiresAt           string `json:"expires_at"`
	ManifestAsOf        string `json:"manifest_as_of"`
	ManifestSHA256      string `json:"manifest_sha256"`
	HostPlatform        string `json:"host_platform"`
	HostArchitecture    string `json:"host_architecture"`
	ClientPlatform      string `json:"client_platform"`
	ClientArchitecture  string `json:"client_architecture"`
	HostRecordSHA256    string `json:"host_record_sha256"`
	ClientRecordSHA256  string `json:"client_record_sha256"`
	SessionRecordSHA256 string `json:"session_record_sha256"`
}

// ExpectedCell is the caller-owned readiness cell against which signed input
// is checked. It prevents an otherwise valid payload from selecting its own
// promotion target.
type ExpectedCell struct {
	RouteID            string
	ClientPlatform     string
	ClientArchitecture string
}

// TrustPolicy is an opaque, application-injected reviewer policy. Evidence
// inputs cannot construct or modify one.
type TrustPolicy struct {
	policy trustPolicy
	valid  bool
}

// ID reports the bound policy identifier. A zero value returns an empty ID.
func (policy TrustPolicy) ID() string {
	if !policy.valid {
		return ""
	}
	return policy.policy.PolicyID
}

// Provisioned reports whether the application policy declares provisioned
// state. Runtime verification still enforces scope, validity, revocation, and
// quorum for the exact evidence set.
func (policy TrustPolicy) Provisioned() bool {
	return policy.valid && policy.policy.Status == policyProvisioned
}

// VerifiedSet is an opaque proof that the exact record bytes, artifact tokens,
// payload bindings, reviewer policy, and all supplied signatures were verified.
type VerifiedSet struct {
	valid                 bool
	setID                 string
	validationRunID       string
	routeID               string
	testProfileID         string
	policyID              string
	clientPlatform        string
	clientArchitecture    string
	manifestAsOf          string
	manifestSHA256        string
	hostRecordSHA256      string
	clientRecordSHA256    string
	sessionRecordSHA256   string
	payloadSHA256         string
	createdAt             time.Time
	expiresAt             time.Time
	signerKeyIDs          []string
	signerPrincipalIDs    []string
	signerOrganizationIDs []string
}

// Valid is false for a zero value and true only for a successfully verified set.
func (set VerifiedSet) Valid() bool { return set.valid }

func (set VerifiedSet) SetID() string               { return set.setID }
func (set VerifiedSet) ValidationRunID() string     { return set.validationRunID }
func (set VerifiedSet) RouteID() string             { return set.routeID }
func (set VerifiedSet) TestProfileID() string       { return set.testProfileID }
func (set VerifiedSet) PolicyID() string            { return set.policyID }
func (set VerifiedSet) ClientPlatform() string      { return set.clientPlatform }
func (set VerifiedSet) ClientArchitecture() string  { return set.clientArchitecture }
func (set VerifiedSet) ManifestAsOf() string        { return set.manifestAsOf }
func (set VerifiedSet) ManifestSHA256() string      { return set.manifestSHA256 }
func (set VerifiedSet) HostRecordSHA256() string    { return set.hostRecordSHA256 }
func (set VerifiedSet) ClientRecordSHA256() string  { return set.clientRecordSHA256 }
func (set VerifiedSet) SessionRecordSHA256() string { return set.sessionRecordSHA256 }
func (set VerifiedSet) PayloadSHA256() string       { return set.payloadSHA256 }
func (set VerifiedSet) CreatedAt() time.Time        { return set.createdAt }
func (set VerifiedSet) ExpiresAt() time.Time        { return set.expiresAt }

// SignerKeyIDs returns a defensive copy in envelope order.
func (set VerifiedSet) SignerKeyIDs() []string { return cloneStrings(set.signerKeyIDs) }

// SignerPrincipalIDs returns a defensive copy in envelope order.
func (set VerifiedSet) SignerPrincipalIDs() []string {
	return cloneStrings(set.signerPrincipalIDs)
}

// SignerOrganizationIDs returns a defensive copy in envelope order.
func (set VerifiedSet) SignerOrganizationIDs() []string {
	return cloneStrings(set.signerOrganizationIDs)
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}
