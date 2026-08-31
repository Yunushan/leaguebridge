package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

type evidenceV2Preparation struct {
	SchemaVersion       int    `json:"schema_version"`
	SetID               string `json:"set_id"`
	ValidationRunID     string `json:"validation_run_id"`
	RouteID             string `json:"route_id"`
	PolicyID            string `json:"policy_id"`
	ClientPlatform      string `json:"client_platform"`
	ClientArchitecture  string `json:"client_architecture"`
	CreatedAt           string `json:"created_at"`
	ExpiresAt           string `json:"expires_at"`
	PayloadSHA256       string `json:"payload_sha256"`
	PayloadBase64URL    string `json:"payload_base64url"`
	PayloadPath         string `json:"payload_path,omitempty"`
	Unsigned            bool   `json:"unsigned"`
	ReadinessPromotable bool   `json:"readiness_promotable"`
}

type loadedEvidenceV2Record struct {
	data      []byte
	record    evidence.Record
	artifacts string
}

type evidenceV2RecordInput struct {
	name      string
	path      string
	artifacts string
}

type evidenceV2PayloadMetadata struct {
	SchemaVersion      int    `json:"schema_version"`
	SetID              string `json:"set_id"`
	ValidationRunID    string `json:"validation_run_id"`
	RouteID            string `json:"route_id"`
	TestProfileID      string `json:"test_profile_id"`
	PolicyID           string `json:"policy_id"`
	CreatedAt          string `json:"created_at"`
	ExpiresAt          string `json:"expires_at"`
	ClientPlatform     string `json:"client_platform"`
	ClientArchitecture string `json:"client_architecture"`
}

const evidenceV2PromotionBoundary = "readiness-schema-v4"

func (a *App) runEvidenceV2(args []string) int {
	if len(args) == 0 {
		return a.commandError("evidence v2", false, ExitUsage, "expected prepare, verify, or promote")
	}
	switch args[0] {
	case "prepare":
		return a.runEvidenceV2Prepare(args[1:])
	case "verify":
		return a.runEvidenceV2Verify(args[1:])
	case "promote":
		return a.runEvidenceV2Promote(args[1:])
	default:
		return a.commandError("evidence v2", false, ExitUsage, "unknown subcommand %q", args[0])
	}
}

func (a *App) runEvidenceV2Prepare(args []string) int {
	set := a.flagSet("evidence v2 prepare")
	envelopeInputs := newEvidenceV2InputFlags(set)
	outputPath := set.String("output", "", "write the exact unsigned payload JSON to a new file")
	asJSON := set.Bool("json", false, "emit preparation metadata as JSON")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("evidence v2 prepare", *asJSON, ExitUsage, "%v", err)
	}
	if err := requireEvidenceV2InputFlags(envelopeInputs); err != nil {
		return a.commandError("evidence v2 prepare", *asJSON, ExitUsage, "%v", err)
	}
	loaded, err := loadEvidenceV2Records([]evidenceV2RecordInput{
		{"host", *envelopeInputs.host, *envelopeInputs.hostArtifacts},
		{"client", *envelopeInputs.client, *envelopeInputs.clientArtifacts},
		{"session", *envelopeInputs.session, *envelopeInputs.sessionArtifacts},
	})
	if err != nil {
		return a.commandError("evidence v2 prepare", *asJSON, ExitBlocked, "%v", err)
	}
	verifications, err := verifyEvidenceV2Artifacts(loaded)
	if err != nil {
		return a.commandError("evidence v2 prepare", *asJSON, ExitBlocked, "%v", err)
	}
	payloadData, err := evidencev2.PreparePayloadAt(evidencev2.PrepareRequest{
		HostData:    loaded["host"].data,
		ClientData:  loaded["client"].data,
		SessionData: loaded["session"].data,
		Expected: evidencev2.ExpectedCell{
			RouteID:            *envelopeInputs.route,
			ClientPlatform:     *envelopeInputs.clientPlatform,
			ClientArchitecture: *envelopeInputs.clientArchitecture,
		},
		Verifications: verifications,
		PolicyID:      evidencev2.ProductionTrustPolicy().ID(),
	}, a.now())
	if err != nil {
		return a.commandError("evidence v2 prepare", *asJSON, ExitBlocked, "prepare evidence v2 payload: %v", err)
	}
	var metadata evidenceV2PayloadMetadata
	if err := json.Unmarshal(payloadData, &metadata); err != nil {
		return a.commandError("evidence v2 prepare", *asJSON, ExitInternal, "decode prepared payload metadata: %v", err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(payloadData))
	result := evidenceV2Preparation{
		SchemaVersion:       metadata.SchemaVersion,
		SetID:               metadata.SetID,
		ValidationRunID:     metadata.ValidationRunID,
		RouteID:             metadata.RouteID,
		PolicyID:            metadata.PolicyID,
		ClientPlatform:      metadata.ClientPlatform,
		ClientArchitecture:  metadata.ClientArchitecture,
		CreatedAt:           metadata.CreatedAt,
		ExpiresAt:           metadata.ExpiresAt,
		PayloadSHA256:       digest,
		PayloadBase64URL:    base64.RawURLEncoding.EncodeToString(payloadData),
		Unsigned:            true,
		ReadinessPromotable: false,
	}
	if strings.TrimSpace(*outputPath) != "" {
		writtenPath, writeErr := publishEvidenceV2Payload(*outputPath, payloadData)
		if writeErr != nil {
			return a.commandError("evidence v2 prepare", *asJSON, ExitUsage, "write payload: %v", writeErr)
		}
		result.PayloadPath = writtenPath
	}
	if *asJSON {
		return a.writeJSON("evidence v2 prepare", result)
	}
	if result.PayloadPath == "" {
		if written, writeErr := a.Stdout.Write(payloadData); writeErr != nil {
			return a.commandError("evidence v2 prepare", false, ExitInternal, "write prepared payload: %v", writeErr)
		} else if written != len(payloadData) {
			return a.commandError("evidence v2 prepare", false, ExitInternal, "write prepared payload: %v", io.ErrShortWrite)
		}
		return ExitOK
	}
	fmt.Fprintf(a.Stdout, "Prepared unsigned validation-evidence v2 payload at %s\n", result.PayloadPath)
	fmt.Fprintf(a.Stdout, "set_id=%s\nvalidation_run_id=%s\npayload_sha256=%s\n", result.SetID, result.ValidationRunID, result.PayloadSHA256)
	fmt.Fprintln(a.Stdout, "Sign these exact payload bytes through the separately governed reviewer process; this command does not sign or promote readiness.")
	return ExitOK
}

func (a *App) runEvidenceV2Verify(args []string) int {
	set := a.flagSet("evidence v2 verify")
	envelopePath := set.String("envelope", "", "authenticated evidence signature-envelope JSON file")
	inputs := newEvidenceV2InputFlags(set)
	asJSON := set.Bool("json", false, "emit JSON")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("evidence v2 verify", *asJSON, ExitUsage, "%v", err)
	}
	if strings.TrimSpace(*envelopePath) == "" {
		return a.commandError("evidence v2 verify", *asJSON, ExitUsage, "--envelope is required")
	}
	if err := requireEvidenceV2InputFlags(inputs); err != nil {
		return a.commandError("evidence v2 verify", *asJSON, ExitUsage, "%v", err)
	}

	verified, err := a.verifyEvidenceV2Set(
		*envelopePath,
		*inputs.host,
		*inputs.client,
		*inputs.session,
		*inputs.hostArtifacts,
		*inputs.clientArtifacts,
		*inputs.sessionArtifacts,
		evidencev2.ExpectedCell{RouteID: *inputs.route, ClientPlatform: *inputs.clientPlatform, ClientArchitecture: *inputs.clientArchitecture},
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

func (a *App) runEvidenceV2Promote(args []string) int {
	set := a.flagSet("evidence v2 promote")
	envelopePath := set.String("envelope", "", "authenticated evidence signature-envelope JSON file")
	inputs := newEvidenceV2InputFlags(set)
	asJSON := set.Bool("json", false, "emit the schema-v4 promotion result as JSON")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("evidence v2 promote", *asJSON, ExitUsage, "%v", err)
	}
	if strings.TrimSpace(*envelopePath) == "" {
		return a.commandError("evidence v2 promote", *asJSON, ExitUsage, "--envelope is required")
	}
	if err := requireEvidenceV2InputFlags(inputs); err != nil {
		return a.commandError("evidence v2 promote", *asJSON, ExitUsage, "%v", err)
	}
	verified, err := a.verifyEvidenceV2Set(
		*envelopePath,
		*inputs.host,
		*inputs.client,
		*inputs.session,
		*inputs.hostArtifacts,
		*inputs.clientArtifacts,
		*inputs.sessionArtifacts,
		evidencev2.ExpectedCell{RouteID: *inputs.route, ClientPlatform: *inputs.clientPlatform, ClientArchitecture: *inputs.clientArchitecture},
	)
	if err != nil {
		return a.commandError("evidence v2 promote", *asJSON, ExitBlocked, "evidence v2 promotion blocked: %v", err)
	}
	promotion, err := evidencev2.PromoteRemoteSetAt(verified, a.now())
	if err != nil {
		return a.commandError("evidence v2 promote", *asJSON, ExitBlocked, "derive readiness promotion: %v", err)
	}
	if *asJSON {
		return a.writeJSON("evidence v2 promote", promotion)
	}
	fmt.Fprintf(a.Stdout, "Readiness promotion validated for %s/%s/%s; score=%d/100; state=%s; promotion_safe=%t\n", promotion.RouteID, promotion.ClientPlatform, promotion.ClientArchitecture, promotion.Score, promotion.State, promotion.PromotionSafe)
	fmt.Fprintf(a.Stdout, "set_id=%s\nvalidation_run_id=%s\npromotion_boundary=%s\n", promotion.SetID, promotion.ValidationRunID, promotion.PromotionBoundary)
	for _, gate := range promotion.Gates {
		fmt.Fprintf(a.Stdout, "gate_%s=%t\n", gate.ID, gate.Passed)
	}
	fmt.Fprintf(a.Stdout, "signer_key_ids=%s\n", strings.Join(promotion.SignerKeyIDs, ","))
	return ExitOK
}

func (a *App) verifyEvidenceV2Set(envelopePath, hostPath, clientPath, sessionPath, hostArtifacts, clientArtifacts, sessionArtifacts string, expected evidencev2.ExpectedCell) (evidencev2.VerifiedSet, error) {
	envelopeData, err := readBounded(envelopePath, evidencev2.MaxEnvelopeSize)
	if err != nil {
		return evidencev2.VerifiedSet{}, fmt.Errorf("read signature envelope: %v", err)
	}
	loaded, err := loadEvidenceV2Records([]evidenceV2RecordInput{
		{"host", hostPath, hostArtifacts},
		{"client", clientPath, clientArtifacts},
		{"session", sessionPath, sessionArtifacts},
	})
	if err != nil {
		return evidencev2.VerifiedSet{}, err
	}
	verifications, err := verifyEvidenceV2Artifacts(loaded)
	if err != nil {
		return evidencev2.VerifiedSet{}, err
	}
	return evidencev2.VerifySetAt(
		envelopeData,
		loaded["host"].data,
		loaded["client"].data,
		loaded["session"].data,
		expected,
		verifications,
		evidencev2.ProductionTrustPolicy(),
		a.now(),
	)
}

type evidenceV2InputFlags struct {
	host               *string
	client             *string
	session            *string
	hostArtifacts      *string
	clientArtifacts    *string
	sessionArtifacts   *string
	route              *string
	clientPlatform     *string
	clientArchitecture *string
}

func newEvidenceV2InputFlags(set *flag.FlagSet) evidenceV2InputFlags {
	return evidenceV2InputFlags{
		host:               set.String("host", "", "host evidence JSON file"),
		client:             set.String("client", "", "client evidence JSON file"),
		session:            set.String("session", "", "session evidence JSON file"),
		hostArtifacts:      set.String("host-artifacts", "", "directory containing exactly the host artifacts"),
		clientArtifacts:    set.String("client-artifacts", "", "directory containing exactly the client artifacts"),
		sessionArtifacts:   set.String("session-artifacts", "", "directory containing exactly the session artifacts"),
		route:              set.String("route", "", "caller-expected readiness route"),
		clientPlatform:     set.String("client-platform", "", "caller-expected client operating system"),
		clientArchitecture: set.String("client-arch", "", "caller-expected client architecture"),
	}
}

func requireEvidenceV2InputFlags(flags evidenceV2InputFlags) error {
	required := []struct {
		name  string
		value string
	}{
		{"--host", dereferenceString(flags.host)},
		{"--client", dereferenceString(flags.client)},
		{"--session", dereferenceString(flags.session)},
		{"--host-artifacts", dereferenceString(flags.hostArtifacts)},
		{"--client-artifacts", dereferenceString(flags.clientArtifacts)},
		{"--session-artifacts", dereferenceString(flags.sessionArtifacts)},
		{"--route", dereferenceString(flags.route)},
		{"--client-platform", dereferenceString(flags.clientPlatform)},
		{"--client-arch", dereferenceString(flags.clientArchitecture)},
	}
	for _, item := range required {
		if strings.TrimSpace(item.value) == "" {
			return fmt.Errorf("%s is required", item.name)
		}
	}
	return nil
}

func dereferenceString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func loadEvidenceV2Records(inputs []evidenceV2RecordInput) (map[string]loadedEvidenceV2Record, error) {
	loaded := make(map[string]loadedEvidenceV2Record, len(inputs))
	for _, item := range inputs {
		data, err := readBounded(item.path, evidence.MaxRecordSize)
		if err != nil {
			return nil, fmt.Errorf("read %s evidence: %v", item.name, err)
		}
		record, err := evidence.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s evidence is invalid: %v", item.name, err)
		}
		loaded[item.name] = loadedEvidenceV2Record{data: data, record: record, artifacts: item.artifacts}
	}
	return loaded, nil
}

func verifyEvidenceV2Artifacts(loaded map[string]loadedEvidenceV2Record) (evidence.ArtifactVerificationSet, error) {
	verifications := evidence.ArtifactVerificationSet{}
	for _, item := range []struct {
		name         string
		verification *evidence.ArtifactVerification
	}{
		{"host", &verifications.Host},
		{"client", &verifications.Client},
		{"session", &verifications.Session},
	} {
		loadedRecord, ok := loaded[item.name]
		if !ok {
			return evidence.ArtifactVerificationSet{}, fmt.Errorf("%s evidence is missing", item.name)
		}
		verification, err := evidence.VerifyArtifactBundle(loadedRecord.record, loadedRecord.artifacts)
		if err != nil {
			return evidence.ArtifactVerificationSet{}, fmt.Errorf("verify %s artifacts: %v", item.name, err)
		}
		*item.verification = verification
	}
	return verifications, nil
}

func publishEvidenceV2Payload(path string, data []byte) (string, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", fmt.Errorf("resolve output path: %w", err)
	}
	if filepath.Base(absolute) == "." || filepath.Base(absolute) == string(filepath.Separator) {
		return "", errors.New("output path must name a file")
	}
	parent := filepath.Dir(absolute)
	info, err := os.Lstat(parent)
	if err != nil {
		return "", fmt.Errorf("inspect output directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("output parent must be a non-symlink directory")
	}
	if _, err := publishEvidenceTemplateSet(parent, []evidenceTemplateFile{{name: filepath.Base(absolute), data: data}}); err != nil {
		return "", err
	}
	return absolute, nil
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
