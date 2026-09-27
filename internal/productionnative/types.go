// Package productionnative verifies score-free, independently reviewed native
// observation records. It authenticates signed assertions and exact raw artifact
// bytes; a signed assertion alone cannot establish that hardware was physical,
// a game route worked, or a package was published. No production trust roots are
// provisioned here and no readiness points are awarded by this package.
package productionnative

import "time"

const (
	EnvelopeSchemaID = "https://leaguebridge.dev/schemas/production-native-envelope-v1.json"
	PayloadSchemaID  = "https://leaguebridge.dev/schemas/production-native-observation-v1.json"
	EnvelopeVersion  = 1
	PayloadVersion   = 1
	PayloadType      = "leaguebridge.production-native-observation.v1"
	PayloadEncoding  = "base64url-nopad"
	Algorithm        = "ed25519"

	KindNativeIntegration Kind = "native-integration"
	KindPhysicalBSD       Kind = "physical-bsd"
	KindPackageLifecycle  Kind = "package-lifecycle"

	MaxEnvelopeSize = 128 << 10
	MaxPayloadSize  = 32 << 10
	MaxArtifactSize = int64(256 << 20)
	MaxArtifactSet  = int64(1 << 30)
)

const (
	roleObserver    = "lab-observer"
	roleReviewer    = "independent-reviewer"
	policyID        = "leaguebridge-production-native-observations-v1"
	policyUnknown   = "unprovisioned"
	policyActive    = "provisioned"
	signatureDomain = "LeagueBridge/production-native-observation/v1\x00"
	keyIDDomain     = "LeagueBridge/production-native-reviewer-key/v1\x00"
)

// Kind selects one fixed observation inventory. It never selects a score.
type Kind string

// Cell identifies one native integration, physical BSD, or package lifecycle
// cell. Family is empty for the first two kinds.
type Cell struct {
	Family string `json:"family"`
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
}

var integrationCells = [...]Cell{
	{"", "linux", "amd64"}, {"", "linux", "arm64"},
	{"", "freebsd", "amd64"}, {"", "freebsd", "arm64"},
	{"", "openbsd", "amd64"}, {"", "openbsd", "arm64"},
	{"", "netbsd", "amd64"}, {"", "netbsd", "arm64"},
	{"", "dragonfly", "amd64"},
}

var bsdCells = [...]Cell{
	{"", "freebsd", "amd64"}, {"", "freebsd", "arm64"},
	{"", "openbsd", "amd64"}, {"", "openbsd", "arm64"},
	{"", "netbsd", "amd64"}, {"", "netbsd", "arm64"},
	{"", "dragonfly", "amd64"},
}

var lifecycleCells = [...]Cell{
	{"debian", "linux", "amd64"}, {"debian", "linux", "arm64"},
	{"rpm", "linux", "amd64"}, {"rpm", "linux", "arm64"},
	{"freebsd-pkg", "freebsd", "amd64"}, {"freebsd-pkg", "freebsd", "arm64"},
	{"openbsd-pkg", "openbsd", "amd64"}, {"openbsd-pkg", "openbsd", "arm64"},
	{"pkgsrc", "netbsd", "amd64"}, {"pkgsrc", "netbsd", "arm64"},
	{"dports", "dragonfly", "amd64"},
}

// ExpectedCells returns a detached copy of the immutable v1 inventory.
func ExpectedCells(kind Kind) []Cell {
	switch kind {
	case KindNativeIntegration:
		return append([]Cell(nil), integrationCells[:]...)
	case KindPhysicalBSD:
		return append([]Cell(nil), bsdCells[:]...)
	case KindPackageLifecycle:
		return append([]Cell(nil), lifecycleCells[:]...)
	default:
		return nil
	}
}

// ReleaseBinding must be derived independently from an opaque, live verified
// release and the authenticated archive manifest. In particular,
// ExecutableSHA256 must not be copied from the observation being verified.
// This package does not create a production ReleaseBinding from an untrusted
// record; future productionassessment wiring must provide that derivation.
type ReleaseBinding struct {
	Version          string `json:"version"`
	Commit           string `json:"commit"`
	Tree             string `json:"tree"`
	ReleaseID        int64  `json:"release_id"`
	ArchiveFilename  string `json:"archive_filename"`
	ArchiveSHA256    string `json:"archive_sha256"`
	ExecutableSHA256 string `json:"executable_sha256"`
}

// ExpectedObservation is selected by the verifier, independently of the
// envelope. Challenge must be selected by the caller before the observed run.
// This verifier cannot establish how the challenge was issued. For lifecycle
// observations PackageSHA256 must also come from independently authenticated
// publisher and live index evidence; this package does not establish either.
type ExpectedObservation struct {
	Kind          Kind
	Cell          Cell
	Release       ReleaseBinding
	PackageSHA256 string
	Challenge     string
	HostRoute     string
}

// ArtifactInput identifies an exact raw file retained with the signed record.
// The supplied path is inspected as a regular, non-symlink file and rechecked
// after signature verification. Kind is matched to the signed artifact list.
type ArtifactInput struct {
	Kind string
	Path string
}

type envelope struct {
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

type observation struct {
	Schema          string         `json:"$schema"`
	SchemaVersion   int            `json:"schema_version"`
	ObservationType string         `json:"observation_type"`
	Kind            Kind           `json:"kind"`
	PolicyID        string         `json:"policy_id"`
	ObservationID   string         `json:"observation_id"`
	RunID           string         `json:"run_id"`
	MachineID       string         `json:"machine_pseudonym"`
	Challenge       string         `json:"challenge"`
	CreatedAt       string         `json:"created_at"`
	ExpiresAt       string         `json:"expires_at"`
	Cell            Cell           `json:"cell"`
	Release         ReleaseBinding `json:"release"`
	PackageSHA256   string         `json:"package_sha256"`
	HostRoute       string         `json:"host_route"`
	NativeKernel    string         `json:"native_kernel"`
	Assertions      []string       `json:"assertions"`
	Artifacts       []artifact     `json:"artifacts"`
}

type artifact struct {
	Kind      string `json:"kind"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

// TrustPolicy is application-owned. Evidence files and envelopes cannot
// introduce reviewer keys. Its public production constructor is unprovisioned.
type TrustPolicy struct {
	policy trustPolicy
	valid  bool
}

func (policy TrustPolicy) ID() string {
	if policy.valid {
		return policy.policy.ID
	}
	return ""
}
func (policy TrustPolicy) Provisioned() bool {
	return policy.valid && policy.policy.Status == policyActive
}

// VerifiedObservation is opaque and has an invalid zero value. It proves
// authenticated assertions and retained artifact bytes only, not physical
// hardware truth, authorized gameplay, publication, or readiness credit.
type VerifiedObservation struct {
	valid          bool
	kind           Kind
	cell           Cell
	release        ReleaseBinding
	packageSHA256  string
	policyID       string
	policyDigest   string
	observationID  string
	runID          string
	machineID      string
	challenge      string
	payloadSHA256  string
	createdAt      time.Time
	expiresAt      time.Time
	artifactInputs []ArtifactInput
	artifacts      []artifact
}

func (verified VerifiedObservation) Valid() bool             { return verified.valid }
func (verified VerifiedObservation) Kind() Kind              { return verified.kind }
func (verified VerifiedObservation) Cell() Cell              { return verified.cell }
func (verified VerifiedObservation) Release() ReleaseBinding { return verified.release }
func (verified VerifiedObservation) ObservationID() string   { return verified.observationID }
func (verified VerifiedObservation) PayloadSHA256() string   { return verified.payloadSHA256 }
func (verified VerifiedObservation) ExpiresAt() time.Time    { return verified.expiresAt }

// VerifiedSet proves only that independently authenticated observation records
// cover one exact fixed inventory at verification time. Its zero value is
// invalid and it has no scoring method.
type VerifiedSet struct {
	valid          bool
	kind           Kind
	releaseVersion string
	releaseCommit  string
	releaseTree    string
	releaseID      int64
	policyID       string
	observations   []VerifiedObservation
}

func (set VerifiedSet) Valid() bool            { return set.valid }
func (set VerifiedSet) Kind() Kind             { return set.kind }
func (set VerifiedSet) ReleaseVersion() string { return set.releaseVersion }
func (set VerifiedSet) PolicyID() string       { return set.policyID }
