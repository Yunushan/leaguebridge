package compat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// LaunchRequest describes the route and host for which launch permission is
// requested. Missing, unknown, or mismatched values are denied.
type LaunchRequest struct {
	BackendID        BackendID    `json:"backendId"`
	HostPlatform     Platform     `json:"hostPlatform"`
	HostArchitecture Architecture `json:"hostArchitecture"`
}

// Verdict is a fail-closed policy result. Evidence URLs always come from the
// compiled-in authoritative manifest, never from external data.
type Verdict struct {
	Decision       LaunchDecision `json:"decision"`
	Code           string         `json:"code"`
	Message        string         `json:"message"`
	BackendID      BackendID      `json:"backendId,omitempty"`
	ManifestAsOf   string         `json:"manifestAsOf,omitempty"`
	Freshness      Freshness      `json:"freshness,omitempty"`
	EvidenceURLs   []string       `json:"evidenceUrls,omitempty"`
	ExternalLoaded bool           `json:"externalLoaded"`
}

// IsAllowed is true only for an explicit allow verdict.
func (v Verdict) IsAllowed() bool {
	return v.Decision == DecisionAllow
}

// Policy evaluates only the immutable manifest decoded from embedded bytes.
// An optional external manifest can restrict a future embedded allow decision,
// but can never promote or replace an embedded decision.
type Policy struct {
	authoritative Manifest
	external      *Manifest
	lockedCode    string
	lockedMessage string
}

// NewPolicy constructs a policy from the embedded authority. externalJSON is
// optional and informational/restrictive only. If external data is invalid, a
// locked policy is returned together with an error so ignoring the error cannot
// accidentally create an allow path.
func NewPolicy(externalJSON []byte) (*Policy, error) {
	p := &Policy{}
	authoritative, err := Embedded()
	if err != nil {
		p.lock("EMBEDDED_MANIFEST_INVALID", "The compiled compatibility authority is invalid.")
		return p, err
	}
	p.authoritative = authoritative
	if len(bytes.TrimSpace(externalJSON)) == 0 {
		return p, nil
	}
	external, err := Parse(externalJSON)
	if err != nil {
		p.lock("EXTERNAL_MANIFEST_INVALID", "The external compatibility manifest is invalid; launch is locked.")
		return p, fmt.Errorf("external compatibility manifest: %w", err)
	}
	p.external = &external
	return p, nil
}

// DefaultPolicy constructs a policy with no external observations.
func DefaultPolicy() (*Policy, error) {
	return NewPolicy(nil)
}

// AuthoritativeManifest returns a deep copy of the embedded authority used by
// this policy. Mutating the result cannot change future verdicts.
func (p *Policy) AuthoritativeManifest() (Manifest, error) {
	if p == nil || p.authoritative.SchemaVersion == "" {
		return Manifest{}, fmt.Errorf("policy has no authoritative manifest")
	}
	encoded, err := json.Marshal(p.authoritative)
	if err != nil {
		return Manifest{}, fmt.Errorf("copy authoritative manifest: %w", err)
	}
	return Parse(encoded)
}

// Evaluate uses the current time. Prefer EvaluateAt in deterministic code and
// tests or when the evaluation time is part of an audit record.
func (p *Policy) Evaluate(request LaunchRequest) Verdict {
	return p.EvaluateAt(request, time.Now())
}

// EvaluateAt returns allow only after every embedded safety gate passes.
func (p *Policy) EvaluateAt(request LaunchRequest, at time.Time) Verdict {
	if p == nil {
		return deny("POLICY_UNAVAILABLE", "Compatibility policy is unavailable.", request.BackendID)
	}
	if p.lockedCode != "" {
		verdict := deny(p.lockedCode, p.lockedMessage, request.BackendID)
		verdict.ExternalLoaded = p.external != nil
		return verdict
	}
	if !knownPlatform(request.HostPlatform) {
		return p.denial("UNKNOWN_HOST_PLATFORM", fmt.Sprintf("Host platform %q is not recognized.", request.HostPlatform), request.BackendID, Freshness{})
	}
	if request.HostArchitecture != ArchitectureAMD64 {
		return p.denial("UNKNOWN_HOST_ARCHITECTURE", fmt.Sprintf("Host architecture %q is not supported by this manifest.", request.HostArchitecture), request.BackendID, Freshness{})
	}
	backend, ok := findBackend(p.authoritative, request.BackendID)
	if !ok {
		return p.denial("UNKNOWN_BACKEND", fmt.Sprintf("Backend %q is not present in the embedded compatibility authority.", request.BackendID), request.BackendID, Freshness{})
	}
	if !containsPlatform(backend.HostPlatforms, request.HostPlatform) {
		return p.denial("BACKEND_PLATFORM_MISMATCH", fmt.Sprintf("Backend %q is not defined for host platform %q.", backend.ID, request.HostPlatform), backend.ID, Freshness{})
	}
	if !containsArchitecture(backend.HostArchitectures, request.HostArchitecture) {
		return p.denial("BACKEND_ARCHITECTURE_MISMATCH", fmt.Sprintf("Backend %q is not defined for host architecture %q.", backend.ID, request.HostArchitecture), backend.ID, Freshness{})
	}
	freshness, err := p.authoritative.FreshnessAt(at)
	if err != nil {
		return p.denial("MANIFEST_FRESHNESS_INVALID", "The embedded manifest freshness could not be verified.", backend.ID, Freshness{})
	}
	switch freshness.State {
	case FreshnessFresh:
	case FreshnessStale:
		return p.denial("MANIFEST_STALE", "The embedded compatibility evidence is stale and must be reviewed before launch.", backend.ID, freshness)
	case FreshnessFuture:
		return p.denial("MANIFEST_NOT_YET_EFFECTIVE", "The embedded compatibility evidence is dated in the future.", backend.ID, freshness)
	default:
		return p.denial("MANIFEST_FRESHNESS_INVALID", "The embedded manifest has an unknown freshness state.", backend.ID, freshness)
	}

	// Authoritative denial is checked before any external observation. An
	// external allow can therefore never promote this result.
	if backend.LaunchVerdict != DecisionAllow {
		return p.denial(backend.ReasonCode, backend.Summary, backend.ID, freshness)
	}
	if backend.State != StateSupported || backend.Authorization != AuthorizationOfficial {
		return p.denial("EMBEDDED_AUTHORIZATION_INCOMPLETE", "The embedded authority lacks both supported state and official authorization.", backend.ID, freshness)
	}
	if p.authoritative.Policy.DefaultVerdict != DecisionDeny || !p.authoritative.Policy.RequireOfficialAuthorization {
		return p.denial("EMBEDDED_POLICY_INVARIANT_FAILED", "The embedded fail-closed policy invariant failed.", backend.ID, freshness)
	}

	// External data is deny-only. Missing, blocked, handoff-only, or
	// unauthorized external state can restrict an embedded allow; it cannot
	// create one. Its policy fields, dates, summaries, and URLs are never used
	// to weaken the embedded gate.
	if p.external != nil {
		externalFreshness, err := p.external.FreshnessAt(at)
		if err != nil || externalFreshness.State != FreshnessFresh {
			return p.denial("EXTERNAL_RESTRICTION", "External compatibility observations are invalid, stale, or not yet effective.", backend.ID, freshness)
		}
		externalBackend, ok := findBackend(*p.external, backend.ID)
		if !ok || externalBackend.LaunchVerdict != DecisionAllow || externalBackend.State != StateSupported || externalBackend.Authorization != AuthorizationOfficial {
			return p.denial("EXTERNAL_RESTRICTION", "External compatibility observations do not confirm the embedded allow decision.", backend.ID, freshness)
		}
	}

	verdict := Verdict{
		Decision:       DecisionAllow,
		Code:           "AUTHORIZED",
		Message:        "Launch is authorized by fresh embedded policy and was not restricted by external observations.",
		BackendID:      backend.ID,
		ManifestAsOf:   p.authoritative.AsOf,
		Freshness:      freshness,
		EvidenceURLs:   authoritativeEvidenceURLs(p.authoritative, backend),
		ExternalLoaded: p.external != nil,
	}
	return verdict
}

func (p *Policy) denial(code, message string, backendID BackendID, freshness Freshness) Verdict {
	verdict := deny(code, message, backendID)
	verdict.ManifestAsOf = p.authoritative.AsOf
	verdict.Freshness = freshness
	verdict.ExternalLoaded = p.external != nil
	if backend, ok := findBackend(p.authoritative, backendID); ok {
		verdict.EvidenceURLs = authoritativeEvidenceURLs(p.authoritative, backend)
	}
	return verdict
}

func deny(code, message string, backendID BackendID) Verdict {
	code = strings.TrimSpace(code)
	if code == "" {
		code = "DENIED"
	}
	return Verdict{
		Decision:  DecisionDeny,
		Code:      code,
		Message:   message,
		BackendID: backendID,
	}
}

func (p *Policy) lock(code, message string) {
	p.lockedCode = code
	p.lockedMessage = message
}

func findBackend(m Manifest, id BackendID) (Backend, bool) {
	for _, backend := range m.Backends {
		if backend.ID == id {
			return backend, true
		}
	}
	return Backend{}, false
}

func containsPlatform(values []Platform, target Platform) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsArchitecture(values []Architecture, target Architecture) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func authoritativeEvidenceURLs(m Manifest, backend Backend) []string {
	sources := make(map[string]string, len(m.Sources))
	for _, source := range m.Sources {
		sources[source.ID] = source.URL
	}
	urls := make([]string, 0, len(backend.SourceIDs))
	for _, id := range backend.SourceIDs {
		if value, ok := sources[id]; ok {
			urls = append(urls, value)
		}
	}
	return urls
}
