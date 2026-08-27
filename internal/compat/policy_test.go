package compat

import (
	"strings"
	"testing"
	"time"
)

var authorityDate = time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)

func TestPolicyDeniesEveryEmbeddedBackend(t *testing.T) {
	t.Parallel()

	policy, err := DefaultPolicy()
	if err != nil {
		t.Fatal(err)
	}
	manifest := mustEmbedded(t)
	for _, backend := range manifest.Backends {
		backend := backend
		t.Run(string(backend.ID), func(t *testing.T) {
			t.Parallel()
			verdict := policy.EvaluateAt(LaunchRequest{
				BackendID:        backend.ID,
				HostPlatform:     backend.HostPlatforms[0],
				HostArchitecture: ArchitectureAMD64,
			}, authorityDate)
			if verdict.IsAllowed() || verdict.Decision != DecisionDeny {
				t.Fatalf("verdict = %+v, want deny", verdict)
			}
			if verdict.Code != backend.ReasonCode {
				t.Fatalf("code = %q, want %q", verdict.Code, backend.ReasonCode)
			}
			if verdict.ManifestAsOf != AuthoritativeAsOf || verdict.Freshness.State != FreshnessFresh {
				t.Fatalf("missing authority metadata: %+v", verdict)
			}
			if len(verdict.EvidenceURLs) == 0 {
				t.Fatal("denial has no authoritative evidence URLs")
			}
		})
	}
}

func TestPolicyFailsClosedForUnknownAndMismatchedRequests(t *testing.T) {
	t.Parallel()

	policy, err := DefaultPolicy()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		req  LaunchRequest
		code string
	}{
		{name: "unknown backend", req: LaunchRequest{BackendID: "unknown", HostPlatform: PlatformLinux, HostArchitecture: ArchitectureAMD64}, code: "UNKNOWN_BACKEND"},
		{name: "unknown platform", req: LaunchRequest{BackendID: BackendWine, HostPlatform: "plan9", HostArchitecture: ArchitectureAMD64}, code: "UNKNOWN_HOST_PLATFORM"},
		{name: "missing platform", req: LaunchRequest{BackendID: BackendWine, HostArchitecture: ArchitectureAMD64}, code: "UNKNOWN_HOST_PLATFORM"},
		{name: "unknown architecture", req: LaunchRequest{BackendID: BackendWine, HostPlatform: PlatformLinux, HostArchitecture: "arm64"}, code: "UNKNOWN_HOST_ARCHITECTURE"},
		{name: "missing architecture", req: LaunchRequest{BackendID: BackendWine, HostPlatform: PlatformLinux}, code: "UNKNOWN_HOST_ARCHITECTURE"},
		{name: "platform mismatch", req: LaunchRequest{BackendID: BackendProton, HostPlatform: PlatformFreeBSD, HostArchitecture: ArchitectureAMD64}, code: "BACKEND_PLATFORM_MISMATCH"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := policy.EvaluateAt(test.req, authorityDate)
			if got.Decision != DecisionDeny || got.Code != test.code {
				t.Fatalf("verdict = %+v, want deny code %q", got, test.code)
			}
		})
	}
}

func TestPolicyDeniesStaleAndFutureAuthority(t *testing.T) {
	t.Parallel()

	policy, err := DefaultPolicy()
	if err != nil {
		t.Fatal(err)
	}
	req := LaunchRequest{BackendID: BackendWine, HostPlatform: PlatformLinux, HostArchitecture: ArchitectureAMD64}
	tests := []struct {
		name string
		at   time.Time
		code string
	}{
		{name: "future", at: time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC), code: "MANIFEST_NOT_YET_EFFECTIVE"},
		{name: "stale", at: time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC), code: "MANIFEST_STALE"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := policy.EvaluateAt(req, test.at)
			if got.Decision != DecisionDeny || got.Code != test.code {
				t.Fatalf("verdict = %+v, want deny code %q", got, test.code)
			}
		})
	}
}

func TestExternalManifestCannotPromoteEmbeddedDenial(t *testing.T) {
	t.Parallel()

	external := mustEmbedded(t)
	backend := backendPointer(t, &external, BackendWine)
	backend.State = StateSupported
	backend.Authorization = AuthorizationOfficial
	backend.LaunchVerdict = DecisionAllow
	external.Sources[0].URL = "https://attacker.invalid/not-authoritative"

	policy, err := NewPolicy(mustJSON(t, external))
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	verdict := policy.EvaluateAt(LaunchRequest{BackendID: BackendWine, HostPlatform: PlatformLinux, HostArchitecture: ArchitectureAMD64}, authorityDate)
	if verdict.Decision != DecisionDeny || verdict.Code != "VANGUARD_DRIVER_REQUIREMENTS_UNSATISFIED" {
		t.Fatalf("external promotion changed embedded denial: %+v", verdict)
	}
	if !verdict.ExternalLoaded {
		t.Fatal("verdict did not record external input")
	}
	for _, evidenceURL := range verdict.EvidenceURLs {
		if strings.Contains(evidenceURL, "attacker.invalid") {
			t.Fatalf("external URL leaked into authoritative evidence: %q", evidenceURL)
		}
	}
}

func TestExternalManifestCanOnlyRestrictFutureEmbeddedAllow(t *testing.T) {
	t.Parallel()

	policy, err := DefaultPolicy()
	if err != nil {
		t.Fatal(err)
	}
	authoritativeBackend := backendPointer(t, &policy.authoritative, BackendWine)
	authoritativeBackend.State = StateSupported
	authoritativeBackend.Authorization = AuthorizationOfficial
	authoritativeBackend.LaunchVerdict = DecisionAllow

	req := LaunchRequest{BackendID: BackendWine, HostPlatform: PlatformLinux, HostArchitecture: ArchitectureAMD64}
	if verdict := policy.EvaluateAt(req, authorityDate); verdict.Decision != DecisionAllow || verdict.Code != "AUTHORIZED" {
		t.Fatalf("complete embedded authorization did not allow: %+v", verdict)
	}

	blockedExternal := mustEmbedded(t)
	policy.external = &blockedExternal
	if verdict := policy.EvaluateAt(req, authorityDate); verdict.Decision != DecisionDeny || verdict.Code != "EXTERNAL_RESTRICTION" {
		t.Fatalf("external denial did not restrict embedded allow: %+v", verdict)
	}

	externalBackend := backendPointer(t, policy.external, BackendWine)
	externalBackend.State = StateSupported
	externalBackend.Authorization = AuthorizationOfficial
	externalBackend.LaunchVerdict = DecisionAllow
	if verdict := policy.EvaluateAt(req, authorityDate); verdict.Decision != DecisionAllow {
		t.Fatalf("matching external observation unexpectedly overrode embedded allow: %+v", verdict)
	}

	for _, test := range []struct {
		name string
		date string
	}{
		{name: "stale", date: "2026-07-01"},
		{name: "future", date: "2026-08-27"},
	} {
		t.Run(test.name, func(t *testing.T) {
			external := *policy.external
			external.Sources = append([]Source(nil), policy.external.Sources...)
			external.AsOf = test.date
			for i := range external.Sources {
				external.Sources[i].CheckedAt = test.date
			}
			policy.external = &external
			verdict := policy.EvaluateAt(req, authorityDate)
			if verdict.Decision != DecisionDeny || verdict.Code != "EXTERNAL_RESTRICTION" {
				t.Fatalf("%s external observation did not restrict allow: %+v", test.name, verdict)
			}
		})
	}
}

func TestInvalidExternalManifestReturnsLockedPolicy(t *testing.T) {
	t.Parallel()

	policy, err := NewPolicy([]byte(`{"schemaVersion":"1.0.0","schemaVersion":"1.0.0"}`))
	if err == nil {
		t.Fatal("NewPolicy() error = nil, want invalid external error")
	}
	if policy == nil {
		t.Fatal("NewPolicy() returned nil fail-closed policy")
	}
	verdict := policy.EvaluateAt(LaunchRequest{BackendID: BackendWine, HostPlatform: PlatformLinux, HostArchitecture: ArchitectureAMD64}, authorityDate)
	if verdict.Decision != DecisionDeny || verdict.Code != "EXTERNAL_MANIFEST_INVALID" {
		t.Fatalf("locked verdict = %+v", verdict)
	}
}

func TestAuthoritativeManifestCopyCannotChangePolicy(t *testing.T) {
	t.Parallel()

	policy, err := DefaultPolicy()
	if err != nil {
		t.Fatal(err)
	}
	copy, err := policy.AuthoritativeManifest()
	if err != nil {
		t.Fatal(err)
	}
	backend := backendPointer(t, &copy, BackendWine)
	backend.State = StateSupported
	backend.Authorization = AuthorizationOfficial
	backend.LaunchVerdict = DecisionAllow

	verdict := policy.EvaluateAt(LaunchRequest{BackendID: BackendWine, HostPlatform: PlatformLinux, HostArchitecture: ArchitectureAMD64}, authorityDate)
	if verdict.Decision != DecisionDeny {
		t.Fatalf("mutating returned copy changed policy: %+v", verdict)
	}
}

func TestNilPolicyDenies(t *testing.T) {
	t.Parallel()

	var policy *Policy
	verdict := policy.EvaluateAt(LaunchRequest{BackendID: BackendWine}, authorityDate)
	if verdict.Decision != DecisionDeny || verdict.Code != "POLICY_UNAVAILABLE" {
		t.Fatalf("nil policy verdict = %+v", verdict)
	}
}

func backendPointer(t *testing.T, manifest *Manifest, id BackendID) *Backend {
	t.Helper()
	for i := range manifest.Backends {
		if manifest.Backends[i].ID == id {
			return &manifest.Backends[i]
		}
	}
	t.Fatalf("backend %q not found", id)
	return nil
}
