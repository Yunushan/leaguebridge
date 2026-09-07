// Package readiness exposes the repository's fail-closed production-readiness
// contract. Scores are derived from a fixed inventory; scorecard data cannot
// supply earned points or boolean pass values.
package readiness

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/exactjson"
	"github.com/Yunushan/leaguebridge/internal/fileinput"
	"github.com/Yunushan/leaguebridge/internal/target"
)

//go:embed data/scorecard.json
var embedded []byte

const (
	SchemaVersion        = 3
	MaximumValidity      = 30 * 24 * time.Hour
	MaximumFutureSkew    = 5 * time.Minute
	MaximumScorecardSize = 1 << 20
	MaximumEvidenceSize  = 4 << 20
	MaximumReasonSize    = 2048
	RemoteWindowsRouteID = "physical-windows-remote"
	RemoteMacOSRouteID   = "physical-macos-remote"
	RemoteArchitecture   = "amd64"
	RemoteGateWeight     = 25
	RemoteEvidenceV2     = 2
	RepositoryContentV1  = "repository-content-v1"
	CIAttestationV1      = "ci-attestation-v1"
	NativeRuntimeV2      = "native-runtime-attestation-v2"
	VendorAuthorization  = "vendor-authorization-v1"
	IndependentAuditV1   = "independent-audit-v1"
	ReleaseAttestation   = "release-attestation-v1"
	PackageAttestation   = "package-attestation-v1"

	RepositoryEvidenceVerificationPrefix = "leaguebridge-repository-evidence-v1:"
	RepositoryEvidenceVerifiedReason     = "build-time repository evidence was verified against the embedded scorecard"
	RepositoryEvidenceUnverifiedReason   = "build-time repository evidence verification is absent or does not match the embedded scorecard"
	LocalGameplayBlockedReason           = "Riot does not support Linux/BSD and states that Wine cannot satisfy Vanguard requirements; Riot also rejects virtual machines."
)

var (
	validSHA256          = regexp.MustCompile(`^[a-f0-9]{64}$`)
	validEvidenceSegment = regexp.MustCompile(`^[A-Za-z0-9.][A-Za-z0-9._+-]*$`)
)

type subcriterionContract struct {
	ID           string
	Name         string
	Weight       int
	EvidenceType string
	VerifierID   string
	Paths        []string
}

type categoryContract struct {
	ID          string
	Name        string
	Weight      int
	Subcriteria []subcriterionContract
}

// engineeringContract is the sole source of score weights and awardability.
// A repository criterion is satisfied only by its exact ordered path inventory.
// Authenticated evidence types remain deliberately unsatisfied unless the
// exact verifier, production trust policy, and score evaluator are all
// provisioned and reviewed for that evidence class.
var engineeringContract = []categoryContract{
	{
		ID: "honest-scope", Name: "Honest scope and documentation", Weight: 10,
		Subcriteria: []subcriterionContract{
			{ID: "scope-support-matrix", Name: "Support matrix", Weight: 4, EvidenceType: RepositoryContentV1, VerifierID: "docs-support-matrix-v1", Paths: []string{"README.md"}},
			{ID: "scope-explicit-limitations", Name: "Explicit limitations", Weight: 3, EvidenceType: RepositoryContentV1, VerifierID: "docs-explicit-limitations-v1", Paths: []string{"docs/SUPPORT_POLICY.md", "docs/READINESS.md", "docs/RELEASE_ASSESSMENT.md"}},
			{ID: "scope-primary-source-research", Name: "Dated primary-source research", Weight: 3, EvidenceType: RepositoryContentV1, VerifierID: "docs-primary-source-research-v1", Paths: []string{"docs/research/2026-08-26-platform-feasibility.md", "docs/research/2026-09-03-route-revalidation.md"}},
		},
	},
	{
		ID: "governance-legal-privacy", Name: "Governance, legal, and privacy", Weight: 10,
		Subcriteria: []subcriterionContract{
			{ID: "governance-policy-conduct", Name: "Governance and conduct", Weight: 3, EvidenceType: RepositoryContentV1, VerifierID: "governance-policy-conduct-v1", Paths: []string{"CODE_OF_CONDUCT.md", "GOVERNANCE.md"}},
			{ID: "governance-security-policy", Name: "Security policy", Weight: 3, EvidenceType: RepositoryContentV1, VerifierID: "governance-security-policy-v1", Paths: []string{"SECURITY.md"}},
			{ID: "governance-legal-privacy", Name: "Legal and privacy boundaries", Weight: 4, EvidenceType: RepositoryContentV1, VerifierID: "governance-legal-privacy-v1", Paths: []string{"LICENSE", "docs/LEGAL-AND-AUTHORIZATION.md", "docs/PRIVACY.md"}},
		},
	},
	{
		ID: "architecture-contracts", Name: "Architecture and data contracts", Weight: 15,
		Subcriteria: []subcriterionContract{
			{ID: "architecture-versioned-schemas", Name: "Versioned schemas", Weight: 5, EvidenceType: RepositoryContentV1, VerifierID: "schemas-offline-conformance-v1", Paths: []string{"schemas/compatibility-manifest.schema.json", "schemas/config.schema.json", "schemas/evidence-signature-envelope.schema.json", "schemas/evidence-trust-policy.schema.json", "schemas/package-manifest.schema.json", "schemas/readiness-scorecard.schema.json", "schemas/readiness-promotion-v4.schema.json", "schemas/validation-evidence-v2.schema.json", "schemas/validation-evidence.schema.json", "schemas/ci-attestation.schema.json", "schemas/native-package-staging.schema.json", "schemas/native-runtime-attestation.schema.json", "schemas/native-package-attestation.schema.json", "schemas/release-assessment.schema.json"}},
			{ID: "architecture-fail-closed-policy", Name: "Fail-closed policy", Weight: 5, EvidenceType: RepositoryContentV1, VerifierID: "compat-fail-closed-v1", Paths: []string{"internal/compat/policy.go", "internal/compat/policy_test.go"}},
			{ID: "architecture-reason-codes-adrs", Name: "Stable reason codes and ADRs", Weight: 3, EvidenceType: RepositoryContentV1, VerifierID: "reason-codes-adrs-v1", Paths: []string{"docs/adr/0001-fail-closed-policy.md", "docs/adr/0002-no-wine-vm-or-dll-backend.md", "docs/adr/0003-remote-physical-host-handoff.md", "docs/adr/0004-physical-macos-remote-handoff.md", "docs/adr/0005-authenticated-validation-evidence-v2.md", "internal/compat/manifest.go"}},
			{ID: "architecture-upstream-authorization", Name: "Authorized upstream extension contract", Weight: 2, EvidenceType: VendorAuthorization, VerifierID: "riot-linux-bsd-authorization-v1"},
		},
	},
	{
		ID: "implementation", Name: "Implementation quality", Weight: 20,
		Subcriteria: []subcriterionContract{
			{ID: "implementation-cli-controller", Name: "CLI/controller", Weight: 5, EvidenceType: RepositoryContentV1, VerifierID: "cli-controller-v1", Paths: []string{"cmd/leaguebridge/main.go", "internal/app/app.go", "internal/app/evidence.go", "internal/app/evidence_v2.go", "internal/app/readiness.go", "internal/evidence/artifacts.go", "internal/evidence/evidence.go", "internal/evidencev2/parse.go", "internal/evidencev2/policy.go", "internal/evidencev2/prepare.go", "internal/evidencev2/promotion.go", "internal/evidencev2/types.go", "internal/evidencev2/verify.go", "internal/readiness/readiness.go", "internal/app/readiness_release.go", "internal/releaseassessment/assessment.go", "internal/releaseassessment/publication.go", "internal/releaseassessment/source.go", "internal/releaseassessment/staging.go", "internal/releaseassessment/transport.go", "internal/releasecheck/releasecheck.go"}},
			{ID: "implementation-strict-config-fixed-argv", Name: "Strict config and fixed remote argv", Weight: 4, EvidenceType: RepositoryContentV1, VerifierID: "strict-config-fixed-argv-v1", Paths: []string{"internal/app/remote.go", "internal/kvm/kvm.go", "internal/config/config.go", "internal/exactjson/exactjson.go", "internal/fileinput/fileinput.go", "internal/fileinput/open_other.go", "internal/fileinput/open_unix.go", "internal/remote/remote.go", "internal/remote/control.go"}},
			{ID: "implementation-bounded-diagnostics-redaction", Name: "Bounded diagnostics and redaction", Weight: 4, EvidenceType: RepositoryContentV1, VerifierID: "bounded-diagnostics-redaction-v1", Paths: []string{"internal/diagnostics/bundle.go", "internal/diagnostics/report.go", "internal/redact/redact.go"}},
			{ID: "implementation-read-only-probes", Name: "Read-only host/client probes", Weight: 4, EvidenceType: RepositoryContentV1, VerifierID: "read-only-probes-v1", Paths: []string{"compatibility/sunshine-windows-amd64.lock.json", "internal/probe/alternatives.go", "internal/probe/client.go", "internal/probe/macos_host.go", "internal/probe/probe.go", "internal/probe/service.go", "internal/probe/service_other.go", "internal/probe/service_windows.go", "internal/probe/system.go", "internal/probe/system_tool_other.go", "internal/probe/system_tool_windows.go", "internal/probe/windows_host.go", "scripts/inspect-sunshine-host.ps1"}},
			{ID: "implementation-native-validated-integration", Name: "Native validated platform integration", Weight: 3, EvidenceType: NativeRuntimeV2, VerifierID: "native-integration-v2"},
		},
	},
	{
		ID: "tests-ci", Name: "Tests and CI", Weight: 20,
		Subcriteria: []subcriterionContract{
			{ID: "tests-unit-negative", Name: "Unit and negative tests", Weight: 5, EvidenceType: RepositoryContentV1, VerifierID: "unit-negative-tests-v1", Paths: []string{"internal/app/app_test.go", "internal/kvm/kvm_test.go", "internal/app/evidence_v2_test.go", "internal/compat/manifest_test.go", "internal/compat/policy_test.go", "internal/config/config_test.go", "internal/contracts/evidence_v2_schema_test.go", "internal/contracts/readiness_v4_schema_test.go", "internal/contracts/sunshine_workflow_test.go", "internal/contracts/sunshine_workflow_windows_test.go", "internal/evidence/artifacts_test.go", "internal/evidence/evidence_test.go", "internal/evidencev2/evidencev2_test.go", "internal/evidencev2/promotion_test.go", "internal/exactjson/exactjson_test.go", "internal/fileinput/fileinput_test.go", "internal/fileinput/fileinput_unix_test.go", "internal/packageinfo/manifest_test.go", "internal/probe/alternatives_test.go", "internal/probe/macos_host_test.go", "internal/probe/probe_test.go", "internal/probe/windows_host_hardening_test.go", "internal/remote/remote_test.go", "internal/vendorintegrity/vendorintegrity_test.go", "tools/releasecheck/main_test.go", "tools/releasecheck/release_script_test.go", "tools/sbom/main_test.go", "tools/vendorcheck/main_test.go", "internal/contracts/ci_attestation_schema_test.go", "internal/nativepackage/staging_test.go", "tools/ciattestation/main_test.go", "tools/nativepackagestage/main_test.go", "tools/releasecheck/workflow_format_test.go", "internal/app/remote_runtime_test.go", "internal/remote/runtime_regression_test.go", "internal/probe/control_readiness_test.go", "tools/ciartifact/main_test.go", "tools/cireleasegate/main_test.go", "tools/releasecheck/ci_transport_test.go", "internal/fileinput/directory_test.go", "internal/remote/control_test.go", "internal/ciattestation/ciattestation_test.go", "internal/cireleasegate/cireleasegate_test.go", "internal/currentci/currentci_test.go", "tools/currentci/main_test.go", "internal/app/readiness_release_test.go", "internal/contracts/release_assessment_schema_test.go", "internal/releasecheck/releasecheck_test.go", "internal/releasecheck/api_test.go", "internal/releaseassessment/assessment_test.go", "internal/releaseassessment/testdata/reviewed-v0.1.0-scorecard.json", "internal/currentci/output_bound_test.go", "internal/cireleasegate/output_bound_test.go", "internal/ciattestation/output_bound_test.go", "internal/diagnostics/output_bound_test.go", "tools/nativeattestation/output_bound_test.go", "tools/nativepackageattestation/output_bound_test.go"}},
			{ID: "tests-coverage-80", Name: "80% aggregate core coverage gate", Weight: 4, EvidenceType: RepositoryContentV1, VerifierID: "core-coverage-80-v1", Paths: []string{"tools/coverage/main.go", "tools/coverage/main_test.go"}},
			{ID: "tests-race-vet-linux", Name: "Linux race and vet", Weight: 3, EvidenceType: CIAttestationV1, VerifierID: "ci-race-vet-v1"},
			{ID: "tests-nine-target-cross-build", Name: "Nine-target Linux/BSD cross-build", Weight: 3, EvidenceType: CIAttestationV1, VerifierID: "ci-nine-target-cross-build-v1"},
			{ID: "tests-native-bsd-physical-smoke", Name: "Native BSD and physical-hardware smoke tests", Weight: 5, EvidenceType: NativeRuntimeV2, VerifierID: "native-bsd-physical-smoke-v2"},
		},
	},
	{
		ID: "security-supply-chain", Name: "Security and supply chain", Weight: 15,
		Subcriteria: []subcriterionContract{
			{ID: "security-threat-model", Name: "Threat model and scope", Weight: 4, EvidenceType: RepositoryContentV1, VerifierID: "threat-model-v1", Paths: []string{"SECURITY.md", "docs/THREAT_MODEL.md"}},
			{ID: "security-injection-bounds-redaction", Name: "Injection, bounds, and redaction tests", Weight: 4, EvidenceType: RepositoryContentV1, VerifierID: "security-negative-tests-v1", Paths: []string{"internal/kvm/kvm_test.go", "internal/app/evidence_v2_test.go", "internal/compat/manifest_test.go", "internal/config/config_test.go", "internal/contracts/evidence_v2_schema_test.go", "internal/contracts/readiness_v4_schema_test.go", "internal/contracts/sunshine_workflow_test.go", "internal/contracts/sunshine_workflow_windows_test.go", "internal/diagnostics/bundle_test.go", "internal/diagnostics/report_test.go", "internal/evidence/artifacts_test.go", "internal/evidence/evidence_test.go", "internal/evidencev2/evidencev2_test.go", "internal/evidencev2/promotion_test.go", "internal/exactjson/exactjson_test.go", "internal/fileinput/fileinput_test.go", "internal/fileinput/fileinput_unix_test.go", "internal/probe/alternatives_test.go", "internal/probe/probe_test.go", "internal/probe/windows_host_hardening_test.go", "internal/redact/redact_test.go", "internal/remote/remote_test.go", "internal/vendorintegrity/vendorintegrity_test.go", "tools/releasecheck/main_test.go", "tools/releasecheck/release_script_test.go", "tools/vendorcheck/main_test.go", "internal/contracts/ci_attestation_schema_test.go", "tools/ciattestation/main_test.go", "internal/app/remote_runtime_test.go", "internal/remote/runtime_regression_test.go", "internal/probe/control_readiness_test.go", "tools/ciartifact/main_test.go", "tools/cireleasegate/main_test.go", "tools/releasecheck/ci_transport_test.go", "internal/fileinput/directory_test.go", "internal/remote/control_test.go", "internal/ciattestation/ciattestation_test.go", "internal/cireleasegate/cireleasegate_test.go", "internal/currentci/currentci_test.go", "tools/currentci/main_test.go", "internal/app/readiness_release_test.go", "internal/contracts/release_assessment_schema_test.go", "internal/releasecheck/releasecheck_test.go", "internal/releasecheck/api_test.go", "internal/releaseassessment/assessment_test.go", "internal/releaseassessment/testdata/reviewed-v0.1.0-scorecard.json", "internal/currentci/output_bound_test.go", "internal/cireleasegate/output_bound_test.go", "internal/ciattestation/output_bound_test.go", "internal/diagnostics/output_bound_test.go", "tools/nativeattestation/output_bound_test.go", "tools/nativepackageattestation/output_bound_test.go"}},
			{ID: "security-pinned-least-privilege-ci", Name: "Pinned least-privilege CI", Weight: 3, EvidenceType: RepositoryContentV1, VerifierID: "pinned-least-privilege-ci-v1", Paths: []string{".github/workflows/ci.yml", ".github/workflows/evidence-freshness.yml", ".github/workflows/release.yml", "tools/cireleasegate/main.go", "tools/cireleasegate/main_test.go", "internal/cireleasegate/cireleasegate.go", "internal/cireleasegate/cireleasegate_test.go", "internal/currentci/currentci.go", "internal/currentci/currentci_test.go", "tools/currentci/main.go", "tools/currentci/main_test.go"}},
			{ID: "security-sbom-checksum-provenance", Name: "SBOM, checksum, and provenance tooling", Weight: 2, EvidenceType: RepositoryContentV1, VerifierID: "sbom-checksum-provenance-tools-v1", Paths: []string{".gitattributes", "go.mod", "go.sum", "scripts/release.sh", "scripts/install.sh", "scripts/uninstall.sh", "scripts/verify-install.sh", "scripts/verify-release-reproducible.sh", "internal/packageinfo/manifest.go", "internal/packageinfo/manifest_test.go", "internal/vendorintegrity/lock.go", "internal/vendorintegrity/vendorintegrity.go", "internal/vendorintegrity/vendorintegrity_test.go", "vendor/filippo.io/edwards25519/LICENSE", "vendor/modules.txt", "tools/canonicaltar/main.go", "tools/packagemanifest/main.go", "tools/readinesscheck/main.go", "tools/releasecheck/main.go", "tools/releasecheck/main_test.go", "tools/releasecheck/release_script_test.go", "tools/sbom/main.go", "tools/sbom/main_test.go", "tools/vendorcheck/main.go", "tools/vendorcheck/main_test.go", "tools/ciartifact/main.go", "tools/ciartifact/main_test.go", "tools/releasecheck/ci_transport_test.go", "tools/ciattestation/main.go", "internal/ciattestation/ciattestation.go", "internal/releasecheck/releasecheck.go", "internal/releasecheck/releasecheck_test.go", "internal/releasecheck/api_test.go", "internal/releaseassessment/assessment.go", "internal/releaseassessment/publication.go", "internal/releaseassessment/source.go", "internal/releaseassessment/staging.go", "internal/releaseassessment/transport.go", "tools/nativeattestation/main.go", "tools/nativepackageattestation/main.go"}},
			{ID: "security-independent-audit-closed", Name: "Closed independent audit findings", Weight: 2, EvidenceType: IndependentAuditV1, VerifierID: "independent-audit-v1"},
		},
	},
	{
		ID: "packaging-operations", Name: "Packaging and operations", Weight: 10,
		Subcriteria: []subcriterionContract{
			{ID: "packaging-nine-release-archives", Name: "Nine published Linux/BSD release archives", Weight: 2, EvidenceType: ReleaseAttestation, VerifierID: "release-nine-archives-v1"},
			{ID: "packaging-version-sbom-checksums", Name: "Version metadata, SBOMs, and checksums tooling", Weight: 2, EvidenceType: RepositoryContentV1, VerifierID: "release-metadata-tools-v1", Paths: []string{"internal/packageinfo/manifest.go", "internal/version/version.go", "tools/releasecheck/main.go", "tools/sbom/main.go", "internal/releasecheck/releasecheck.go"}},
			{ID: "packaging-publication-attestation", Name: "Release publication and attestation", Weight: 1, EvidenceType: ReleaseAttestation, VerifierID: "release-publication-attestation-v1"},
			{ID: "packaging-native-os-packages", Name: "Native OS packages", Weight: 3, EvidenceType: PackageAttestation, VerifierID: "native-packages-v1"},
			{ID: "packaging-install-uninstall-native-smoke", Name: "Install/uninstall and native smoke evidence", Weight: 2, EvidenceType: NativeRuntimeV2, VerifierID: "install-native-smoke-v2"},
		},
	},
}

type remotePlatformDefinition struct {
	Platform     string
	Architecture string
}

var remotePlatformContract = buildRemotePlatformContract()

func buildRemotePlatformContract() []remotePlatformDefinition {
	result := make([]remotePlatformDefinition, 0, len(target.Ordered()))
	for _, candidate := range target.Ordered() {
		platform, ok := target.EvidencePlatform(candidate.GOOS)
		if !ok {
			panic("unsupported readiness target platform " + candidate.GOOS)
		}
		result = append(result, remotePlatformDefinition{Platform: platform, Architecture: candidate.GOARCH})
	}
	return result
}

var remoteGateContract = []string{"physical-host", "client-runtime", "session-quality", "gameplay-interaction"}
var remoteRouteContract = []remoteRouteDefinition{
	{
		ID:     RemoteWindowsRouteID,
		Reason: "The physical Windows host and all client/session/gameplay gates remain unvalidated: the validation-evidence v2 verifier is implemented, but no production reviewer trust keys or authenticated physical-run evidence are provisioned; schema-v1 manual evidence remains non-promotable and readiness schema v3 remains hard-zero.",
	},
	{
		ID:     RemoteMacOSRouteID,
		Reason: "Sunshine's macOS host support is experimental and gamepad hosting is unavailable; validation-evidence v2 now verifies route-bound Windows or macOS/v1-record-backed sets, but no production reviewer trust keys or authenticated physical-run evidence are provisioned, and readiness schema v3 remains hard-zero.",
	},
}

type remoteRouteDefinition struct {
	ID     string
	Reason string
}

type Scorecard struct {
	SchemaVersion  int             `json:"schema_version"`
	AssessedAt     time.Time       `json:"assessed_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	Engineering    []Category      `json:"engineering"`
	LocalGameplay  Outcome         `json:"local_gameplay"`
	RemoteHandoffs []RemoteHandoff `json:"remote_handoffs"`
}

// EngineeringEvaluation is the only user-facing engineering-score result.
// Repository-backed points are unavailable unless the build injected the
// exact verification value after checking the immutable source snapshot.
type EngineeringEvaluation struct {
	Score                      int
	RepositoryEvidenceVerified bool
	VerificationReason         string
	categoryScores             map[string]int
}

func (e EngineeringEvaluation) CategoryScore(categoryID string) int {
	return e.categoryScores[categoryID]
}

type Category struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Weight      int            `json:"weight"`
	Subcriteria []Subcriterion `json:"subcriteria"`
}

type Subcriterion struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Weight       int                 `json:"weight"`
	EvidenceType string              `json:"evidence_type"`
	VerifierID   string              `json:"verifier_id"`
	Evidence     []EvidenceReference `json:"evidence"`
}

type EvidenceReference struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Outcome struct {
	Score  int    `json:"score"`
	State  string `json:"state"`
	Reason string `json:"reason"`
}

// RemoteHandoff contains only evidence inputs. Scores, states, and gate pass
// values are intentionally absent and are derived by EvaluateRemoteHandoffs.
type RemoteHandoff struct {
	RouteID                       string           `json:"route_id"`
	RequiredEvidenceSchemaVersion int              `json:"required_evidence_schema_version"`
	Reason                        string           `json:"reason"`
	Platforms                     []RemotePlatform `json:"platforms"`
}

type RemotePlatform struct {
	Platform     string                       `json:"platform"`
	Architecture string                       `json:"architecture"`
	EvidenceSets []RemoteEvidenceSetReference `json:"evidence_sets"`
}

type RemoteEvidenceSetReference struct {
	EvidenceType  string `json:"evidence_type"`
	SchemaVersion int    `json:"schema_version"`
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
}

type RemoteEvaluation struct {
	RouteID   string                     `json:"route_id"`
	Score     int                        `json:"score"`
	State     string                     `json:"state"`
	Reason    string                     `json:"reason"`
	Platforms []RemotePlatformEvaluation `json:"platforms"`
}

type RemotePlatformEvaluation struct {
	Platform     string                 `json:"platform"`
	Architecture string                 `json:"architecture"`
	Score        int                    `json:"score"`
	State        string                 `json:"state"`
	Gates        []RemoteGateEvaluation `json:"gates"`
}

type RemoteGateEvaluation struct {
	ID     string `json:"id"`
	Weight int    `json:"weight"`
	Passed bool   `json:"passed"`
}

func Embedded() (Scorecard, error) { return Parse(embedded) }

// EmbeddedJSON returns a defensive copy of the exact embedded scorecard bytes.
func EmbeddedJSON() []byte { return append([]byte(nil), embedded...) }

func EmbeddedSHA256() string {
	digest := sha256.Sum256(embedded)
	return fmt.Sprintf("%x", digest)
}

// ExpectedRepositoryEvidenceVerification returns the build-time value created
// only after readinesscheck verifies all repository evidence in the immutable
// release snapshot. It is a verification state marker, not publisher signing
// or cryptographic provenance.
func ExpectedRepositoryEvidenceVerification() string {
	return RepositoryEvidenceVerificationPrefix + EmbeddedSHA256()
}

func Parse(data []byte) (Scorecard, error) { return ParseAt(data, time.Now()) }

func ParseAt(data []byte, now time.Time) (Scorecard, error) {
	if len(data) > MaximumScorecardSize {
		return Scorecard{}, fmt.Errorf("readiness scorecard exceeds %d bytes", MaximumScorecardSize)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return Scorecard{}, fmt.Errorf("decode readiness scorecard: %w", err)
	}
	if err := exactjson.ValidateKeys(data, &Scorecard{}); err != nil {
		return Scorecard{}, fmt.Errorf("decode readiness scorecard: %w", err)
	}
	var scorecard Scorecard
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&scorecard); err != nil {
		return Scorecard{}, fmt.Errorf("decode readiness scorecard: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Scorecard{}, errors.New("readiness scorecard contains multiple JSON values")
		}
		return Scorecard{}, fmt.Errorf("decode trailing scorecard data: %w", err)
	}
	if err := scorecard.ValidateAt(now); err != nil {
		return Scorecard{}, err
	}
	return scorecard, nil
}

func (s Scorecard) Validate() error { return s.ValidateAt(time.Now()) }

func (s Scorecard) ValidateAt(now time.Time) error {
	if s.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported readiness schema_version %d", s.SchemaVersion)
	}
	if now.IsZero() {
		return errors.New("readiness evaluation time is required")
	}
	if s.AssessedAt.IsZero() || s.ExpiresAt.IsZero() {
		return errors.New("assessed_at and expires_at are required")
	}
	if s.AssessedAt.After(now.Add(MaximumFutureSkew)) {
		return errors.New("assessed_at is in the future")
	}
	if !s.ExpiresAt.After(s.AssessedAt) || s.ExpiresAt.Sub(s.AssessedAt) > MaximumValidity {
		return fmt.Errorf("readiness validity must be greater than zero and no more than %s", MaximumValidity)
	}
	if now.After(s.ExpiresAt) {
		return errors.New("readiness scorecard has expired")
	}
	if len(s.Engineering) != len(engineeringContract) {
		return fmt.Errorf("engineering categories count %d, expected %d", len(s.Engineering), len(engineeringContract))
	}
	totalWeight := 0
	for categoryIndex, category := range s.Engineering {
		contract := engineeringContract[categoryIndex]
		if category.ID != contract.ID || category.Name != contract.Name || category.Weight != contract.Weight {
			return fmt.Errorf("engineering category %d does not match the fixed %q contract", categoryIndex, contract.ID)
		}
		if len(category.Subcriteria) != len(contract.Subcriteria) {
			return fmt.Errorf("engineering category %q has %d subcriteria; want %d", category.ID, len(category.Subcriteria), len(contract.Subcriteria))
		}
		categoryWeight := 0
		for subcriterionIndex, criterion := range category.Subcriteria {
			required := contract.Subcriteria[subcriterionIndex]
			if criterion.ID != required.ID || criterion.Name != required.Name || criterion.Weight != required.Weight || criterion.EvidenceType != required.EvidenceType || criterion.VerifierID != required.VerifierID {
				return fmt.Errorf("engineering subcriterion %d in category %q does not match fixed contract %q", subcriterionIndex, category.ID, required.ID)
			}
			if criterion.Evidence == nil {
				return fmt.Errorf("engineering subcriterion %q evidence must be an array", criterion.ID)
			}
			if required.EvidenceType != RepositoryContentV1 {
				if len(criterion.Evidence) != 0 {
					return fmt.Errorf("engineering subcriterion %q requires unsupported authenticated evidence type %q and must remain unsatisfied", criterion.ID, required.EvidenceType)
				}
			} else {
				if len(criterion.Evidence) != len(required.Paths) {
					return fmt.Errorf("engineering subcriterion %q has %d evidence references; want %d", criterion.ID, len(criterion.Evidence), len(required.Paths))
				}
				for evidenceIndex, reference := range criterion.Evidence {
					if reference.Path != required.Paths[evidenceIndex] {
						return fmt.Errorf("engineering subcriterion %q evidence %d must be %q", criterion.ID, evidenceIndex, required.Paths[evidenceIndex])
					}
					if !validRepositoryEvidencePath(reference.Path) || !validSHA256.MatchString(reference.SHA256) {
						return fmt.Errorf("engineering subcriterion %q has an invalid content-addressed evidence reference", criterion.ID)
					}
				}
			}
			categoryWeight += criterion.Weight
		}
		if categoryWeight != category.Weight {
			return fmt.Errorf("engineering category %q subcriteria total %d; want %d", category.ID, categoryWeight, category.Weight)
		}
		totalWeight += category.Weight
	}
	if totalWeight != 100 {
		return fmt.Errorf("engineering weights total %d, expected 100", totalWeight)
	}
	if err := validateLocalGameplay(s.LocalGameplay); err != nil {
		return err
	}
	if len(s.RemoteHandoffs) != len(remoteRouteContract) {
		return fmt.Errorf("remote_handoffs has %d routes; want %d", len(s.RemoteHandoffs), len(remoteRouteContract))
	}
	for index, route := range s.RemoteHandoffs {
		if err := route.validate(remoteRouteContract[index], index); err != nil {
			return err
		}
	}
	return nil
}

func (r RemoteHandoff) validate(contract remoteRouteDefinition, routeIndex int) error {
	location := fmt.Sprintf("remote_handoffs[%d]", routeIndex)
	if r.RouteID != contract.ID {
		return fmt.Errorf("%s.route_id must be %q", location, contract.ID)
	}
	if r.RequiredEvidenceSchemaVersion != RemoteEvidenceV2 {
		return fmt.Errorf("%s.required_evidence_schema_version must be %d", location, RemoteEvidenceV2)
	}
	if r.Reason != contract.Reason {
		return fmt.Errorf("%s.reason must preserve the fixed route limitations", location)
	}
	if len(r.Platforms) != len(remotePlatformContract) {
		return fmt.Errorf("%s has %d platforms; want %d", location, len(r.Platforms), len(remotePlatformContract))
	}
	for index, platform := range r.Platforms {
		contractPlatform := remotePlatformContract[index]
		if platform.Platform != contractPlatform.Platform {
			return fmt.Errorf("%s platform %d must be %q", location, index, contractPlatform.Platform)
		}
		if platform.Architecture != contractPlatform.Architecture {
			return fmt.Errorf("%s platform %q architecture must be %q", location, platform.Platform, contractPlatform.Architecture)
		}
		if platform.EvidenceSets == nil {
			return fmt.Errorf("%s platform %q evidence_sets must be an array", location, platform.Platform)
		}
		if len(platform.EvidenceSets) != 0 {
			return fmt.Errorf("%s platform %q cannot be promoted: readiness schema v3 requires evidence_sets to remain empty; derived schema-v4 promotion is evaluated separately from this scorecard", location, platform.Platform)
		}
	}
	return nil
}

// EvaluateEngineering derives the user-facing score through one fail-closed
// build-time verification gate. Ad hoc/dev builds and mismatched scorecard
// stamps report zero repository-backed points.
func (s Scorecard) EvaluateEngineering(repositoryEvidenceVerification string) EngineeringEvaluation {
	evaluation := EngineeringEvaluation{
		VerificationReason: RepositoryEvidenceUnverifiedReason,
		categoryScores:     make(map[string]int, len(engineeringContract)),
	}
	if repositoryEvidenceVerification != ExpectedRepositoryEvidenceVerification() {
		return evaluation
	}
	evaluation.RepositoryEvidenceVerified = true
	evaluation.VerificationReason = RepositoryEvidenceVerifiedReason
	for _, contract := range engineeringContract {
		score := s.EngineeringCategoryScore(contract.ID)
		evaluation.categoryScores[contract.ID] = score
		evaluation.Score += score
	}
	return evaluation
}

// EngineeringScore derives the repository/source score from the fixed
// evidence-class contract. User-facing commands must use EvaluateEngineering
// so an unverified build cannot claim repository-backed points.
func (s Scorecard) EngineeringScore() int {
	total := 0
	for _, contract := range engineeringContract {
		total += s.EngineeringCategoryScore(contract.ID)
	}
	return total
}

func (s Scorecard) EngineeringCategoryScore(categoryID string) int {
	for categoryIndex, category := range s.Engineering {
		if category.ID != categoryID || categoryIndex >= len(engineeringContract) {
			continue
		}
		contract := engineeringContract[categoryIndex]
		if category.Name != contract.Name || category.Weight != contract.Weight || len(category.Subcriteria) != len(contract.Subcriteria) {
			return 0
		}
		total := 0
		for index, criterion := range category.Subcriteria {
			required := contract.Subcriteria[index]
			if repositoryCriterionSatisfied(criterion, required) {
				total += required.Weight
			}
		}
		return total
	}
	return 0
}

func repositoryCriterionSatisfied(criterion Subcriterion, required subcriterionContract) bool {
	if required.EvidenceType != RepositoryContentV1 || criterion.ID != required.ID || criterion.Name != required.Name || criterion.Weight != required.Weight || criterion.EvidenceType != required.EvidenceType || criterion.VerifierID != required.VerifierID || len(criterion.Evidence) != len(required.Paths) {
		return false
	}
	for index, reference := range criterion.Evidence {
		if reference.Path != required.Paths[index] || !validRepositoryEvidencePath(reference.Path) || !validSHA256.MatchString(reference.SHA256) {
			return false
		}
	}
	return true
}

// VerifyRepositoryEvidence validates every awarded repository reference against
// a source checkout. It rejects symlinks in the root, any ancestor, and the
// final file, and hashes a bounded regular-file stream.
func (s Scorecard) VerifyRepositoryEvidence(root string) error {
	if err := s.Validate(); err != nil {
		return fmt.Errorf("validate readiness scorecard: %w", err)
	}
	evidenceRoot, err := openEvidenceRoot(root)
	if err != nil {
		return err
	}
	defer evidenceRoot.Close()
	return s.verifyRepositoryEvidenceFromRoot(evidenceRoot)
}

// VerifyRepositoryEvidenceFromRoot validates every awarded repository
// reference beneath an already-pinned repository root. Callers that also
// need to inspect another repository file can therefore keep the scorecard
// and all evidence checks on the same directory handle.
func (s Scorecard) VerifyRepositoryEvidenceFromRoot(evidenceRoot *os.Root) error {
	if evidenceRoot == nil {
		return errors.New("repository root is nil")
	}
	if err := s.Validate(); err != nil {
		return fmt.Errorf("validate readiness scorecard: %w", err)
	}
	return s.verifyRepositoryEvidenceFromRoot(evidenceRoot)
}

func (s Scorecard) verifyRepositoryEvidenceFromRoot(evidenceRoot *os.Root) error {
	for categoryIndex, category := range s.Engineering {
		if categoryIndex >= len(engineeringContract) {
			return errors.New("engineering contract is invalid")
		}
		contract := engineeringContract[categoryIndex]
		for criterionIndex, criterion := range category.Subcriteria {
			if criterionIndex >= len(contract.Subcriteria) {
				return errors.New("engineering contract is invalid")
			}
			required := contract.Subcriteria[criterionIndex]
			if required.EvidenceType != RepositoryContentV1 {
				continue
			}
			if !repositoryCriterionSatisfied(criterion, required) {
				return fmt.Errorf("engineering subcriterion %q is not satisfied by its fixed repository contract", required.ID)
			}
			for _, reference := range criterion.Evidence {
				if err := verifyEvidenceFromRoot(evidenceRoot, reference); err != nil {
					return fmt.Errorf("engineering subcriterion %q: %w", required.ID, err)
				}
			}
		}
	}
	return nil
}

func openEvidenceRoot(root string) (*os.Root, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}
	if err := fileinput.RejectSymlinkedParents(absRoot); err != nil {
		return nil, fmt.Errorf("inspect repository root path: %w", err)
	}
	rootInfo, err := os.Lstat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect repository root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return nil, errors.New("repository root must be a non-symlink directory")
	}
	evidenceRoot, err := os.OpenRoot(absRoot)
	if err != nil {
		return nil, fmt.Errorf("open repository root: %w", err)
	}
	openedInfo, err := evidenceRoot.Stat(".")
	if err != nil || !os.SameFile(rootInfo, openedInfo) {
		evidenceRoot.Close()
		return nil, errors.New("repository root changed during verification setup")
	}
	return evidenceRoot, nil
}

func verifyEvidenceFile(root string, reference EvidenceReference) error {
	evidenceRoot, err := openEvidenceRoot(root)
	if err != nil {
		return err
	}
	defer evidenceRoot.Close()
	return verifyEvidenceFromRoot(evidenceRoot, reference)
}

func verifyEvidenceFromRoot(root *os.Root, reference EvidenceReference) error {
	return verifyEvidenceFromRootWithHook(root, reference, nil)
}

// verifyEvidenceFromRootWithHook contains the verifier implementation. The
// hook is unexported and used only by tests to replace the pathname between
// the initial path check and the final post-hash check.
func verifyEvidenceFromRootWithHook(root *os.Root, reference EvidenceReference, afterPathCheck func()) error {
	if !validRepositoryEvidencePath(reference.Path) || !validSHA256.MatchString(reference.SHA256) {
		return errors.New("invalid content-addressed evidence reference")
	}
	current := ""
	segments := strings.Split(reference.Path, "/")
	for index, segment := range segments {
		current = filepath.Join(current, segment)
		info, err := root.Lstat(current)
		if err != nil {
			return fmt.Errorf("evidence %q is unavailable: %w", reference.Path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("evidence %q traverses a symlink", reference.Path)
		}
		if index < len(segments)-1 {
			if !info.IsDir() {
				return fmt.Errorf("evidence %q has a non-directory ancestor", reference.Path)
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("evidence %q is not a regular non-symlink file", reference.Path)
		}
		if info.Size() > MaximumEvidenceSize {
			return fmt.Errorf("evidence %q exceeds %d bytes", reference.Path, MaximumEvidenceSize)
		}
	}
	file, err := fileinput.OpenRegularFromRoot(root, filepath.FromSlash(reference.Path))
	if err != nil {
		return fmt.Errorf("open evidence %q: %w", reference.Path, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened evidence %q: %w", reference.Path, err)
	}
	pathInfo, err := root.Lstat(filepath.FromSlash(reference.Path))
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		return fmt.Errorf("evidence %q changed during verification", reference.Path)
	}
	if afterPathCheck != nil {
		afterPathCheck()
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, MaximumEvidenceSize+1))
	if err != nil {
		return fmt.Errorf("hash evidence %q: %w", reference.Path, err)
	}
	if written > MaximumEvidenceSize {
		return fmt.Errorf("evidence %q exceeds %d bytes", reference.Path, MaximumEvidenceSize)
	}
	finalPathInfo, err := root.Lstat(filepath.FromSlash(reference.Path))
	if err != nil || finalPathInfo.Mode()&os.ModeSymlink != 0 || !finalPathInfo.Mode().IsRegular() || !os.SameFile(openedInfo, finalPathInfo) || finalPathInfo.Size() != written {
		return fmt.Errorf("evidence %q changed during verification", reference.Path)
	}
	if digest := fmt.Sprintf("%x", hasher.Sum(nil)); digest != reference.SHA256 {
		return fmt.Errorf("evidence %q SHA-256 = %s, want %s", reference.Path, digest, reference.SHA256)
	}
	return nil
}

// EvaluateRemoteHandoffs derives two explicit, independent zero-score matrices.
// Schema-v1 manual validation records are never promotion-safe, and readiness
// schema v3 intentionally has no bridge from an authenticated v2 VerifiedSet
// to stored scores, gates, or pass values.
func (s Scorecard) EvaluateRemoteHandoffs() []RemoteEvaluation {
	evaluations := make([]RemoteEvaluation, 0, len(remoteRouteContract))
	for _, route := range remoteRouteContract {
		evaluation := RemoteEvaluation{RouteID: route.ID, State: "unvalidated", Reason: route.Reason}
		for _, platform := range remotePlatformContract {
			item := RemotePlatformEvaluation{Platform: platform.Platform, Architecture: platform.Architecture, State: "unvalidated"}
			for _, gateID := range remoteGateContract {
				item.Gates = append(item.Gates, RemoteGateEvaluation{ID: gateID, Weight: RemoteGateWeight, Passed: false})
			}
			evaluation.Platforms = append(evaluation.Platforms, item)
		}
		evaluations = append(evaluations, evaluation)
	}
	return evaluations
}

func validateLocalGameplay(outcome Outcome) error {
	if outcome.Reason != LocalGameplayBlockedReason {
		return errors.New("local_gameplay reason does not match the fixed readiness schema version 3 limitation")
	}
	if outcome.Score != 0 || outcome.State != "blocked" {
		return fmt.Errorf("local_gameplay must remain 0/blocked under readiness schema version 3, got %d/%s", outcome.Score, outcome.State)
	}
	return nil
}

func validRepositoryEvidencePath(value string) bool {
	if len(value) == 0 || len(value) > 512 || strings.Contains(value, `\`) || path.IsAbs(value) || path.Clean(value) != value || value == "." || strings.HasPrefix(value, "../") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." || !validEvidenceSegment.MatchString(segment) {
			return false
		}
	}
	return true
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return walkJSON(decoder, "$", 0)
}

func walkJSON(decoder *json.Decoder, location string, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds 64 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("%s object key is not a string", location)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("%s has duplicate key %q", location, key)
			}
			seen[key] = struct{}{}
			if err := walkJSON(decoder, location+"."+key, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("%s has malformed object", location)
		}
		return nil
	case '[':
		index := 0
		for decoder.More() {
			if err := walkJSON(decoder, fmt.Sprintf("%s[%d]", location, index), depth+1); err != nil {
				return err
			}
			index++
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("%s has malformed array", location)
		}
		return nil
	default:
		return fmt.Errorf("%s has unexpected delimiter %q", location, delimiter)
	}
}
