package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/evidence"
	"github.com/Yunushan/leaguebridge/internal/evidencev2"
)

func TestEvidenceV2Dispatch(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing subcommand", []string{"evidence", "v2"}, "expected prepare, verify, or promote"},
		{"unknown subcommand", []string{"evidence", "v2", "other"}, "unknown subcommand"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a, _, errOut, _, _ := newTestApp(t)
			if code := a.Run(context.Background(), test.args); code != ExitUsage {
				t.Fatalf("code=%d stderr=%q", code, errOut.String())
			}
			if !strings.Contains(errOut.String(), test.want) {
				t.Fatalf("stderr=%q, want %q", errOut.String(), test.want)
			}
		})
	}
}

func TestEvidenceV2PromoteReachesUnprovisionedProductionPolicy(t *testing.T) {
	host, client, session, hostArtifacts, clientArtifacts, sessionArtifacts := writeVerifiedAppEvidenceSet(t, evidence.AttestationIndependent)
	envelope := writeStructurallyValidV2Envelope(t, host, client, session)

	a, out, errOut, _, _ := newTestApp(t)
	args := v2VerifyArgs(envelope, host, client, session, hostArtifacts, clientArtifacts, sessionArtifacts, true)
	args[2] = "promote"
	code := a.Run(context.Background(), args)
	if code != ExitBlocked || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	response := decodeEnvelope(t, out.Bytes())
	if response.OK || response.Command != "evidence v2 promote" {
		t.Fatalf("response=%+v", response)
	}
	for _, want := range []string{"promotion blocked", "trust policy", "unprovisioned", "records and artifacts are valid"} {
		if !strings.Contains(response.Error, want) {
			t.Fatalf("error=%q, want %q", response.Error, want)
		}
	}
}

func TestEvidenceV2PrepareWritesAnExactUnsignedPayload(t *testing.T) {
	host, client, session, hostArtifacts, clientArtifacts, sessionArtifacts := writeVerifiedAppEvidenceSet(t, evidence.AttestationIndependent)
	outputPath := filepath.Join(t.TempDir(), "payload.json")
	a, out, errOut, _, _ := newTestApp(t)
	if code := a.Run(context.Background(), v2PrepareArgs(host, client, session, hostArtifacts, clientArtifacts, sessionArtifacts, outputPath, false)); code != ExitOK || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	prepared, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(prepared, &payload); err != nil {
		t.Fatalf("payload=%q err=%v", prepared, err)
	}
	if payload["$schema"] != evidencev2.PayloadSchemaID || payload["schema_version"] != float64(evidencev2.PayloadVersion) || payload["policy_id"] != evidencev2.ProductionTrustPolicy().ID() {
		t.Fatalf("unexpected payload: %#v", payload)
	}
	for _, field := range []string{"score", "passed", "launch_authorization"} {
		if _, present := payload[field]; present {
			t.Fatalf("prepared payload contains promotion field %q", field)
		}
	}
	if !strings.Contains(out.String(), "Prepared unsigned validation-evidence v2 payload") || !strings.Contains(out.String(), "payload_sha256=") {
		t.Fatalf("stdout=%q", out.String())
	}
	original := append([]byte(nil), prepared...)
	if code := a.Run(context.Background(), v2PrepareArgs(host, client, session, hostArtifacts, clientArtifacts, sessionArtifacts, outputPath, false)); code != ExitUsage || !strings.Contains(errOut.String(), "destination already exists") {
		t.Fatalf("second prepare code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	unchanged, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, unchanged) {
		t.Fatal("prepare overwrote an existing payload")
	}
}

func TestEvidenceV2PrepareJSONReportsNonPromotingMetadata(t *testing.T) {
	host, client, session, hostArtifacts, clientArtifacts, sessionArtifacts := writeVerifiedAppEvidenceSet(t, evidence.AttestationIndependent)
	outputPath := filepath.Join(t.TempDir(), "payload.json")
	a, out, errOut, _, _ := newTestApp(t)
	if code := a.Run(context.Background(), v2PrepareArgs(host, client, session, hostArtifacts, clientArtifacts, sessionArtifacts, outputPath, true)); code != ExitOK || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	envelope := decodeEnvelope(t, out.Bytes())
	data := envelope.Data.(map[string]any)
	if data["unsigned"] != true || data["readiness_promotable"] != false || data["payload_path"] != outputPath {
		t.Fatalf("unexpected preparation metadata: %#v", data)
	}
	if data["payload_base64url"] == "" || data["payload_sha256"] == "" {
		t.Fatalf("metadata did not include exact payload material: %#v", data)
	}
}

func TestEvidenceV2PrepareRejectsUnverifiedArtifactSet(t *testing.T) {
	host, client, session, _, _, _ := writeVerifiedAppEvidenceSet(t, evidence.AttestationIndependent)
	empty := t.TempDir()
	a, out, errOut, _, _ := newTestApp(t)
	if code := a.Run(context.Background(), v2PrepareArgs(host, client, session, empty, empty, empty, "", true)); code != ExitBlocked || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if response := decodeEnvelope(t, out.Bytes()); response.OK || !strings.Contains(response.Error, "verify host artifacts") {
		t.Fatalf("response=%+v", response)
	}
}

func TestEvidenceV2VerifyRequiresEveryInput(t *testing.T) {
	complete := []string{
		"evidence", "v2", "verify",
		"--envelope", "envelope.json",
		"--host", "host.json",
		"--client", "client.json",
		"--session", "session.json",
		"--host-artifacts", "host-artifacts",
		"--client-artifacts", "client-artifacts",
		"--session-artifacts", "session-artifacts",
		"--route", evidencev2.RoutePhysicalWindowsRemote,
		"--client-platform", "linux",
		"--client-arch", "amd64",
	}
	for _, flag := range []string{
		"--envelope",
		"--host",
		"--client",
		"--session",
		"--host-artifacts",
		"--client-artifacts",
		"--session-artifacts",
		"--route",
		"--client-platform",
		"--client-arch",
	} {
		t.Run(strings.TrimPrefix(flag, "--"), func(t *testing.T) {
			args := removeV2Flag(complete, flag)
			a, _, errOut, _, _ := newTestApp(t)
			if code := a.Run(context.Background(), args); code != ExitUsage {
				t.Fatalf("code=%d stderr=%q", code, errOut.String())
			}
			if !strings.Contains(errOut.String(), flag+" is required") {
				t.Fatalf("stderr=%q", errOut.String())
			}
		})
	}
}

func TestEvidenceV2VerifyHasNoBypassOrTrustInjectionFlags(t *testing.T) {
	for _, flag := range []string{"--policy", "--key", "--sign", "--skip-artifacts", "--allow-expired"} {
		t.Run(strings.TrimPrefix(flag, "--"), func(t *testing.T) {
			a, _, errOut, _, _ := newTestApp(t)
			code := a.Run(context.Background(), []string{"evidence", "v2", "verify", flag, "fixture"})
			if code != ExitUsage || !strings.Contains(errOut.String(), "flag provided but not defined") {
				t.Fatalf("code=%d stderr=%q", code, errOut.String())
			}
		})
	}
}

func TestEvidenceV2VerifyRejectsInvalidEnvelope(t *testing.T) {
	host, client, session, hostArtifacts, clientArtifacts, sessionArtifacts := writeVerifiedAppEvidenceSet(t, evidence.AttestationIndependent)
	envelope := filepath.Join(t.TempDir(), "envelope.json")
	writeFile(t, envelope, []byte(`{}`))

	a, out, errOut, _, _ := newTestApp(t)
	code := a.Run(context.Background(), v2VerifyArgs(envelope, host, client, session, hostArtifacts, clientArtifacts, sessionArtifacts, true))
	if code != ExitBlocked || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	response := decodeEnvelope(t, out.Bytes())
	if response.OK || response.Command != "evidence v2 verify" || !strings.Contains(response.Error, "signature envelope") {
		t.Fatalf("response=%+v", response)
	}
}

func TestEvidenceV2VerifyReachesUnprovisionedProductionPolicy(t *testing.T) {
	host, client, session, hostArtifacts, clientArtifacts, sessionArtifacts := writeVerifiedAppEvidenceSet(t, evidence.AttestationIndependent)
	envelope := writeStructurallyValidV2Envelope(t, host, client, session)

	a, out, errOut, _, _ := newTestApp(t)
	code := a.Run(context.Background(), v2VerifyArgs(envelope, host, client, session, hostArtifacts, clientArtifacts, sessionArtifacts, true))
	if code != ExitBlocked || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	response := decodeEnvelope(t, out.Bytes())
	if response.OK || response.Command != "evidence v2 verify" {
		t.Fatalf("response=%+v", response)
	}
	for _, want := range []string{"verification blocked", "trust policy", "unprovisioned", "records and artifacts are valid"} {
		if !strings.Contains(response.Error, want) {
			t.Fatalf("error=%q, want %q", response.Error, want)
		}
	}
}

func TestEvidenceV2SuccessOutputIsAuthenticatedButNotReadinessPromotable(t *testing.T) {
	result := evidenceV2Verification{
		SchemaVersion:       evidencev2.PayloadVersion,
		SetID:               "set-0123456789abcdef0123456789abcdef",
		RouteID:             evidencev2.RoutePhysicalWindowsRemote,
		ClientPlatform:      "linux",
		ClientArchitecture:  "amd64",
		ExpiresAt:           "2026-08-27T12:00:00Z",
		SignerKeyIDs:        []string{"lbk1-" + strings.Repeat("1", 64), "lbk1-" + strings.Repeat("2", 64)},
		Authenticated:       false,
		ArtifactsVerified:   false,
		ReadinessPromotable: true,
		PromotionBoundary:   "unsafe-caller-value",
	}

	t.Run("json", func(t *testing.T) {
		a, out, errOut, _, _ := newTestApp(t)
		if code := a.writeEvidenceV2Verification(result, true); code != ExitOK || errOut.Len() != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		data := envelope.Data.(map[string]any)
		if data["authenticated"] != true || data["artifacts_verified"] != true || data["readiness_promotable"] != false {
			t.Fatalf("unexpected verification status: %#v", data)
		}
		if data["readiness_promotion_boundary"] != evidenceV2PromotionBoundary {
			t.Fatalf("unexpected promotion boundary: %#v", data["readiness_promotion_boundary"])
		}
		if _, exists := data["promotion_safe"]; exists {
			t.Fatalf("v2 output must not claim promotion_safe: %#v", data)
		}
	})

	t.Run("text", func(t *testing.T) {
		a, out, errOut, _, _ := newTestApp(t)
		if code := a.writeEvidenceV2Verification(result, false); code != ExitOK || errOut.Len() != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		text := out.String()
		for _, want := range []string{"authenticated and artifact-verified", "readiness_promotable=false", evidenceV2PromotionBoundary} {
			if !strings.Contains(text, want) {
				t.Fatalf("stdout=%q, want %q", text, want)
			}
		}
		if strings.Contains(text, "promotion-safe") {
			t.Fatalf("v2 output must not claim promotion-safe: %q", text)
		}
	})
}

func removeV2Flag(args []string, flag string) []string {
	result := make([]string, 0, len(args)-2)
	for index := 0; index < len(args); index++ {
		if args[index] == flag {
			index++
			continue
		}
		result = append(result, args[index])
	}
	return result
}

func v2VerifyArgs(envelope, host, client, session, hostArtifacts, clientArtifacts, sessionArtifacts string, asJSON bool) []string {
	args := []string{
		"evidence", "v2", "verify",
		"--envelope", envelope,
		"--host", host,
		"--client", client,
		"--session", session,
		"--host-artifacts", hostArtifacts,
		"--client-artifacts", clientArtifacts,
		"--session-artifacts", sessionArtifacts,
		"--route", evidencev2.RoutePhysicalWindowsRemote,
		"--client-platform", "linux",
		"--client-arch", "amd64",
	}
	if asJSON {
		args = append(args, "--json")
	}
	return args
}

func v2PrepareArgs(host, client, session, hostArtifacts, clientArtifacts, sessionArtifacts, output string, asJSON bool) []string {
	args := []string{
		"evidence", "v2", "prepare",
		"--host", host,
		"--client", client,
		"--session", session,
		"--host-artifacts", hostArtifacts,
		"--client-artifacts", clientArtifacts,
		"--session-artifacts", sessionArtifacts,
		"--route", evidencev2.RoutePhysicalWindowsRemote,
		"--client-platform", "linux",
		"--client-arch", "amd64",
	}
	if output != "" {
		args = append(args, "--output", output)
	}
	if asJSON {
		args = append(args, "--json")
	}
	return args
}

func writeStructurallyValidV2Envelope(t *testing.T, hostPath, clientPath, sessionPath string) string {
	t.Helper()
	hostData := mustReadV2Fixture(t, hostPath)
	clientData := mustReadV2Fixture(t, clientPath)
	sessionData := mustReadV2Fixture(t, sessionPath)
	host, err := evidence.Parse(hostData)
	if err != nil {
		t.Fatal(err)
	}
	client, err := evidence.Parse(clientData)
	if err != nil {
		t.Fatal(err)
	}
	session, err := evidence.Parse(sessionData)
	if err != nil {
		t.Fatal(err)
	}
	payload := struct {
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
	}{
		Schema:              evidencev2.PayloadSchemaID,
		SchemaVersion:       evidencev2.PayloadVersion,
		SetID:               "set-0123456789abcdef0123456789abcdef",
		ValidationRunID:     host.ValidationRunID,
		RouteID:             host.RouteID,
		TestProfileID:       host.TestProfileID,
		PolicyID:            evidencev2.ProductionTrustPolicy().ID(),
		CreatedAt:           session.CreatedAt,
		ExpiresAt:           session.ExpiresAt,
		ManifestAsOf:        host.ManifestAsOf,
		ManifestSHA256:      host.ManifestSHA256,
		HostPlatform:        host.Subject.Platform,
		HostArchitecture:    host.Subject.Architecture,
		ClientPlatform:      client.Subject.Platform,
		ClientArchitecture:  client.Subject.Architecture,
		HostRecordSHA256:    v2SHA256(hostData),
		ClientRecordSHA256:  v2SHA256(clientData),
		SessionRecordSHA256: v2SHA256(sessionData),
	}
	payloadData, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signatures := []map[string]string{
		{"algorithm": evidencev2.Algorithm, "key_id": "lbk1-" + strings.Repeat("1", 64), "signed_at": fixedNow.Format("2006-01-02T15:04:05Z"), "signature": strings.Repeat("a", 128)},
		{"algorithm": evidencev2.Algorithm, "key_id": "lbk1-" + strings.Repeat("2", 64), "signed_at": fixedNow.Format("2006-01-02T15:04:05Z"), "signature": strings.Repeat("b", 128)},
	}
	envelope := map[string]any{
		"$schema":          evidencev2.EnvelopeSchemaID,
		"envelope_version": evidencev2.EnvelopeVersion,
		"payload_type":     evidencev2.PayloadType,
		"payload_encoding": evidencev2.PayloadEncoding,
		"payload":          base64.RawURLEncoding.EncodeToString(payloadData),
		"signatures":       signatures,
	}
	envelopeData, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "envelope.json")
	writeFile(t, path, envelopeData)
	return path
}

func mustReadV2Fixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func v2SHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest)
}
