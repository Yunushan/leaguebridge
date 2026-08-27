package app

import (
	"fmt"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/evidence"
	"github.com/Yunushan/leaguebridge/internal/evidencev2"
)

type evidenceV2Verification struct {
	SchemaVersion         int      `json:"schema_version"`
	SetID                 string   `json:"set_id"`
	ValidationRunID       string   `json:"validation_run_id"`
	RouteID               string   `json:"route_id"`
	TestProfileID         string   `json:"test_profile_id"`
	PolicyID              string   `json:"policy_id"`
	ClientPlatform        string   `json:"client_platform"`
	ClientArchitecture    string   `json:"client_architecture"`
	ManifestAsOf          string   `json:"manifest_as_of"`
	ManifestSHA256        string   `json:"manifest_sha256"`
	HostRecordSHA256      string   `json:"host_record_sha256"`
	ClientRecordSHA256    string   `json:"client_record_sha256"`
	SessionRecordSHA256   string   `json:"session_record_sha256"`
	PayloadSHA256         string   `json:"payload_sha256"`
	CreatedAt             string   `json:"created_at"`
	ExpiresAt             string   `json:"expires_at"`
	SignerKeyIDs          []string `json:"signer_key_ids"`
	SignerPrincipalIDs    []string `json:"signer_principal_ids"`
	SignerOrganizationIDs []string `json:"signer_organization_ids"`
	Authenticated         bool     `json:"authenticated"`
	ArtifactsVerified     bool     `json:"artifacts_verified"`
	ReadinessPromotable   bool     `json:"readiness_promotable"`
	PromotionBoundary     string   `json:"readiness_promotion_boundary"`
}

const evidenceV2PromotionBoundary = "readiness-schema-v4"

func (a *App) runEvidenceV2(args []string) int {
	if len(args) == 0 {
		return a.commandError("evidence v2", false, ExitUsage, "expected verify")
	}
	if args[0] != "verify" {
		return a.commandError("evidence v2", false, ExitUsage, "unknown subcommand %q", args[0])
	}
	return a.runEvidenceV2Verify(args[1:])
}

func (a *App) runEvidenceV2Verify(args []string) int {
	set := a.flagSet("evidence v2 verify")
	envelopePath := set.String("envelope", "", "authenticated evidence signature-envelope JSON file")
	hostPath := set.String("host", "", "host evidence JSON file")
	clientPath := set.String("client", "", "client evidence JSON file")
	sessionPath := set.String("session", "", "session evidence JSON file")
	hostArtifacts := set.String("host-artifacts", "", "directory containing exactly the host artifacts")
	clientArtifacts := set.String("client-artifacts", "", "directory containing exactly the client artifacts")
	sessionArtifacts := set.String("session-artifacts", "", "directory containing exactly the session artifacts")
	route := set.String("route", "", "caller-expected readiness route")
	clientPlatform := set.String("client-platform", "", "caller-expected client operating system")
	clientArchitecture := set.String("client-arch", "", "caller-expected client architecture")
	asJSON := set.Bool("json", false, "emit JSON")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("evidence v2 verify", *asJSON, ExitUsage, "%v", err)
	}

	required := []struct {
		flag  string
		value string
	}{
		{"--envelope", *envelopePath},
		{"--host", *hostPath},
		{"--client", *clientPath},
		{"--session", *sessionPath},
		{"--host-artifacts", *hostArtifacts},
		{"--client-artifacts", *clientArtifacts},
		{"--session-artifacts", *sessionArtifacts},
		{"--route", *route},
		{"--client-platform", *clientPlatform},
		{"--client-arch", *clientArchitecture},
	}
	for _, item := range required {
		if strings.TrimSpace(item.value) == "" {
			return a.commandError("evidence v2 verify", *asJSON, ExitUsage, "%s is required", item.flag)
		}
	}

	envelopeData, err := readBounded(*envelopePath, evidencev2.MaxEnvelopeSize)
	if err != nil {
		return a.commandError("evidence v2 verify", *asJSON, ExitBlocked, "read signature envelope: %v", err)
	}
	type loadedRecord struct {
		data      []byte
		record    evidence.Record
		artifacts string
	}
	loaded := make(map[string]loadedRecord, 3)
	for _, item := range []struct {
		name      string
		path      string
		artifacts string
	}{
		{"host", *hostPath, *hostArtifacts},
		{"client", *clientPath, *clientArtifacts},
		{"session", *sessionPath, *sessionArtifacts},
	} {
		data, readErr := readBounded(item.path, evidence.MaxRecordSize)
		if readErr != nil {
			return a.commandError("evidence v2 verify", *asJSON, ExitBlocked, "read %s evidence: %v", item.name, readErr)
		}
		record, parseErr := evidence.Parse(data)
		if parseErr != nil {
			return a.commandError("evidence v2 verify", *asJSON, ExitBlocked, "%s evidence is invalid: %v", item.name, parseErr)
		}
		loaded[item.name] = loadedRecord{data: data, record: record, artifacts: item.artifacts}
	}

	verifications := evidence.ArtifactVerificationSet{}
	for _, item := range []struct {
		name         string
		verification *evidence.ArtifactVerification
	}{
		{"host", &verifications.Host},
		{"client", &verifications.Client},
		{"session", &verifications.Session},
	} {
		verification, verifyErr := evidence.VerifyArtifactBundle(loaded[item.name].record, loaded[item.name].artifacts)
		if verifyErr != nil {
			return a.commandError("evidence v2 verify", *asJSON, ExitBlocked, "verify %s artifacts: %v", item.name, verifyErr)
		}
		*item.verification = verification
	}

	verified, err := evidencev2.VerifySetAt(
		envelopeData,
		loaded["host"].data,
		loaded["client"].data,
		loaded["session"].data,
		evidencev2.ExpectedCell{
			RouteID:            *route,
			ClientPlatform:     *clientPlatform,
			ClientArchitecture: *clientArchitecture,
		},
		verifications,
		evidencev2.ProductionTrustPolicy(),
		a.now(),
	)
	if err != nil {
		return a.commandError("evidence v2 verify", *asJSON, ExitBlocked, "evidence v2 verification blocked: %v", err)
	}

	result := evidenceV2Verification{
		SchemaVersion:         evidencev2.PayloadVersion,
		SetID:                 verified.SetID(),
		ValidationRunID:       verified.ValidationRunID(),
		RouteID:               verified.RouteID(),
		TestProfileID:         verified.TestProfileID(),
		PolicyID:              verified.PolicyID(),
		ClientPlatform:        verified.ClientPlatform(),
		ClientArchitecture:    verified.ClientArchitecture(),
		ManifestAsOf:          verified.ManifestAsOf(),
		ManifestSHA256:        verified.ManifestSHA256(),
		HostRecordSHA256:      verified.HostRecordSHA256(),
		ClientRecordSHA256:    verified.ClientRecordSHA256(),
		SessionRecordSHA256:   verified.SessionRecordSHA256(),
		PayloadSHA256:         verified.PayloadSHA256(),
		CreatedAt:             verified.CreatedAt().Format("2006-01-02T15:04:05Z"),
		ExpiresAt:             verified.ExpiresAt().Format("2006-01-02T15:04:05Z"),
		SignerKeyIDs:          verified.SignerKeyIDs(),
		SignerPrincipalIDs:    verified.SignerPrincipalIDs(),
		SignerOrganizationIDs: verified.SignerOrganizationIDs(),
	}
	return a.writeEvidenceV2Verification(result, *asJSON)
}

func (a *App) writeEvidenceV2Verification(result evidenceV2Verification, asJSON bool) int {
	// A successful v2 verification authenticates evidence; readiness schema v3
	// cannot consume it. Keep this boundary fixed even if a future caller
	// accidentally populates the presentation fields differently.
	result.Authenticated = true
	result.ArtifactsVerified = true
	result.ReadinessPromotable = false
	result.PromotionBoundary = evidenceV2PromotionBoundary
	if asJSON {
		if code := a.writeJSON("evidence v2 verify", result); code != ExitOK {
			return code
		}
	} else {
		fmt.Fprintf(a.Stdout, "Evidence set %s is authenticated and artifact-verified for %s/%s/%s; expires=%s\n", result.SetID, result.RouteID, result.ClientPlatform, result.ClientArchitecture, result.ExpiresAt)
		fmt.Fprintf(a.Stdout, "readiness_promotable=false; readiness_promotion_boundary=%s\n", result.PromotionBoundary)
		fmt.Fprintf(a.Stdout, "host_sha256=%s\nclient_sha256=%s\nsession_sha256=%s\npayload_sha256=%s\n", result.HostRecordSHA256, result.ClientRecordSHA256, result.SessionRecordSHA256, result.PayloadSHA256)
		fmt.Fprintf(a.Stdout, "signer_key_ids=%s\n", strings.Join(result.SignerKeyIDs, ","))
	}
	return ExitOK
}
