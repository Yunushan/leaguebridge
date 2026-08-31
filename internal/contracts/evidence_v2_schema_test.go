package contracts

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const (
	evidenceV2SchemaID       = "https://leaguebridge.dev/schemas/validation-evidence-v2.schema.json"
	evidenceEnvelopeSchemaID = "https://leaguebridge.dev/schemas/evidence-signature-envelope.schema.json"
	evidenceTrustSchemaID    = "https://leaguebridge.dev/schemas/evidence-trust-policy.schema.json"
)

func TestAuthenticatedEvidenceSchemasAcceptOnlyBoundedScoreFreeContracts(t *testing.T) {
	payloadSchema := compileOffline(t, "schemas/validation-evidence-v2.schema.json", evidenceV2SchemaID)
	payload := validEvidenceV2Payload()
	if err := payloadSchema.Validate(payload); err != nil {
		t.Fatalf("v2 payload schema rejected valid payload: %v", err)
	}

	t.Run("payload forbids mutable promotion claims", func(t *testing.T) {
		for _, field := range []string{"passed", "score", "gate", "support", "launch_authorization"} {
			candidate := validEvidenceV2Payload()
			candidate[field] = true
			if err := payloadSchema.Validate(candidate); err == nil {
				t.Errorf("v2 payload schema accepted forbidden field %q", field)
			}
		}
	})

	t.Run("payload is route and cell bound", func(t *testing.T) {
		candidate := validEvidenceV2Payload()
		candidate["route_id"] = "physical-macos-remote"
		candidate["host_platform"] = "macos"
		candidate["host_architecture"] = "arm64"
		if err := payloadSchema.Validate(candidate); err != nil {
			t.Fatalf("v2 payload schema rejected a valid macOS route: %v", err)
		}
		candidate = validEvidenceV2Payload()
		candidate["route_id"] = "physical-macos-remote"
		candidate["host_platform"] = "windows"
		candidate["host_architecture"] = "amd64"
		if err := payloadSchema.Validate(candidate); err == nil {
			t.Fatal("v2 payload schema accepted a Windows host on the macOS route")
		}
		candidate = validEvidenceV2Payload()
		candidate["client_architecture"] = "arm64"
		if err := payloadSchema.Validate(candidate); err == nil {
			t.Fatal("v2 payload schema accepted a different client architecture")
		}
	})

	envelopeSchema := compileOffline(t, "schemas/evidence-signature-envelope.schema.json", evidenceEnvelopeSchemaID)
	envelope := validEvidenceEnvelope()
	if err := envelopeSchema.Validate(envelope); err != nil {
		t.Fatalf("signature envelope schema rejected valid envelope: %v", err)
	}

	t.Run("envelope rejects downgrade and noncanonical encodings", func(t *testing.T) {
		candidate := validEvidenceEnvelope()
		candidate["payload_type"] = "leaguebridge.validation-evidence-set.v1"
		if err := envelopeSchema.Validate(candidate); err == nil {
			t.Fatal("signature envelope schema accepted a v1 payload type")
		}
		candidate = validEvidenceEnvelope()
		candidate["payload"] = candidate["payload"].(string) + "="
		if err := envelopeSchema.Validate(candidate); err == nil {
			t.Fatal("signature envelope schema accepted padded base64url")
		}
		candidate = validEvidenceEnvelope()
		candidate["signatures"] = candidate["signatures"].([]any)[:1]
		if err := envelopeSchema.Validate(candidate); err == nil {
			t.Fatal("signature envelope schema accepted a one-party attestation")
		}
	})

	trustSchema := compileOffline(t, "schemas/evidence-trust-policy.schema.json", evidenceTrustSchemaID)
	unprovisioned := validUnprovisionedTrustPolicy()
	if err := trustSchema.Validate(unprovisioned); err != nil {
		t.Fatalf("trust-policy schema rejected the fail-closed production shape: %v", err)
	}
	provisioned := validProvisionedTrustPolicy()
	if err := trustSchema.Validate(provisioned); err != nil {
		t.Fatalf("trust-policy schema rejected a valid two-party policy: %v", err)
	}

	t.Run("unprovisioned means no keys", func(t *testing.T) {
		candidate := validUnprovisionedTrustPolicy()
		candidate["keys"] = validProvisionedTrustPolicy()["keys"]
		if err := trustSchema.Validate(candidate); err == nil {
			t.Fatal("trust-policy schema accepted keys in an unprovisioned policy")
		}
	})

	t.Run("provisioned requires both roles", func(t *testing.T) {
		candidate := validProvisionedTrustPolicy()
		candidate["keys"] = candidate["keys"].([]any)[:1]
		if err := trustSchema.Validate(candidate); err == nil {
			t.Fatal("trust-policy schema accepted a one-party provisioned policy")
		}
	})
}

func validEvidenceV2Payload() map[string]any {
	return map[string]any{
		"$schema":               evidenceV2SchemaID,
		"schema_version":        json.Number("2"),
		"set_id":                "set-0123456789abcdef0123456789abcdef",
		"validation_run_id":     "run-0123456789abcdef0123456789abcdef",
		"route_id":              "physical-windows-remote",
		"test_profile_id":       "remote-play-v1",
		"policy_id":             "leaguebridge-production-evidence-review-v1",
		"created_at":            "2026-08-26T12:00:00Z",
		"expires_at":            "2026-08-27T12:00:00Z",
		"manifest_as_of":        "2026-08-26",
		"manifest_sha256":       strings.Repeat("a", 64),
		"host_platform":         "windows",
		"host_architecture":     "amd64",
		"client_platform":       "linux",
		"client_architecture":   "amd64",
		"host_record_sha256":    strings.Repeat("b", 64),
		"client_record_sha256":  strings.Repeat("c", 64),
		"session_record_sha256": strings.Repeat("d", 64),
	}
}

func validEvidenceEnvelope() map[string]any {
	return map[string]any{
		"$schema":          evidenceEnvelopeSchemaID,
		"envelope_version": json.Number("1"),
		"payload_type":     "leaguebridge.validation-evidence-set.v2",
		"payload_encoding": "base64url-nopad",
		"payload":          base64.RawURLEncoding.EncodeToString([]byte(`{"fixture":true}`)),
		"signatures": []any{
			map[string]any{"algorithm": "ed25519", "key_id": "lbk1-" + strings.Repeat("a", 64), "signed_at": "2026-08-26T12:00:00Z", "signature": strings.Repeat("0", 128)},
			map[string]any{"algorithm": "ed25519", "key_id": "lbk1-" + strings.Repeat("b", 64), "signed_at": "2026-08-26T12:00:00Z", "signature": strings.Repeat("1", 128)},
		},
	}
}

func validUnprovisionedTrustPolicy() map[string]any {
	return map[string]any{
		"$schema":                        evidenceTrustSchemaID,
		"schema_version":                 json.Number("1"),
		"policy_id":                      "leaguebridge-production-evidence-review-v1",
		"status":                         "unprovisioned",
		"valid_from":                     "",
		"expires_at":                     "",
		"required_roles":                 []any{"lab-observer", "independent-reviewer"},
		"min_signatures":                 json.Number("2"),
		"require_distinct_principals":    true,
		"require_distinct_organizations": true,
		"keys":                           []any{},
	}
}

func validProvisionedTrustPolicy() map[string]any {
	policy := validUnprovisionedTrustPolicy()
	policy["status"] = "provisioned"
	policy["valid_from"] = "2026-08-25T00:00:00Z"
	policy["expires_at"] = "2026-09-25T00:00:00Z"
	policy["keys"] = []any{
		validTrustedReviewer("a", "lab-observer", "lab-person", "lab-org"),
		validTrustedReviewer("b", "independent-reviewer", "review-person", "review-org"),
	}
	return policy
}

func validTrustedReviewer(hexDigit, role, principal, organization string) map[string]any {
	return map[string]any{
		"key_id":           "lbk1-" + strings.Repeat(hexDigit, 64),
		"algorithm":        "ed25519",
		"public_key":       strings.Repeat(hexDigit, 64),
		"principal_id":     principal,
		"organization_id":  organization,
		"role":             role,
		"route_ids":        []any{"physical-windows-remote"},
		"client_platforms": []any{"linux"},
		"architectures":    []any{"amd64"},
		"test_profile_ids": []any{"remote-play-v1"},
		"not_before":       "2026-08-25T00:00:00Z",
		"not_after":        "2026-09-25T00:00:00Z",
		"revoked":          false,
	}
}
