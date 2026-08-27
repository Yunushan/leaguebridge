package app

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/evidence"
	"github.com/Yunushan/leaguebridge/internal/version"
)

type evidenceValidation struct {
	RecordID          string              `json:"record_id"`
	RecordType        evidence.RecordType `json:"record_type"`
	RecordSHA256      string              `json:"record_sha256"`
	ArtifactsVerified bool                `json:"artifacts_verified"`
	Evaluation        evidence.Evaluation `json:"evaluation"`
}

type evidenceSetValidation struct {
	HostRecordSHA256    string                 `json:"host_record_sha256"`
	ClientRecordSHA256  string                 `json:"client_record_sha256"`
	SessionRecordSHA256 string                 `json:"session_record_sha256"`
	ArtifactsVerified   bool                   `json:"artifacts_verified"`
	Evaluation          evidence.SetEvaluation `json:"evaluation"`
}

func (a *App) runEvidence(args []string) int {
	if len(args) == 0 {
		return a.commandError("evidence", false, ExitUsage, "expected template, validate, verify-set, or v2")
	}
	switch args[0] {
	case "template":
		return a.runEvidenceTemplate(args[1:])
	case "validate":
		return a.runEvidenceValidate(args[1:])
	case "verify-set":
		return a.runEvidenceVerifySet(args[1:])
	case "v2":
		return a.runEvidenceV2(args[1:])
	default:
		return a.commandError("evidence", false, ExitUsage, "unknown subcommand %q", args[0])
	}
}

func (a *App) runEvidenceVerifySet(args []string) int {
	set := a.flagSet("evidence verify-set")
	hostPath := set.String("host", "", "host evidence JSON file")
	clientPath := set.String("client", "", "client evidence JSON file")
	sessionPath := set.String("session", "", "session evidence JSON file")
	hostArtifacts := set.String("host-artifacts", "", "directory containing exactly the host artifacts")
	clientArtifacts := set.String("client-artifacts", "", "directory containing exactly the client artifacts")
	sessionArtifacts := set.String("session-artifacts", "", "directory containing exactly the session artifacts")
	asJSON := set.Bool("json", false, "emit JSON")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("evidence verify-set", *asJSON, ExitUsage, "%v", err)
	}
	paths := []struct {
		name string
		flag string
		path string
	}{
		{"host", "--host", *hostPath},
		{"client", "--client", *clientPath},
		{"session", "--session", *sessionPath},
	}
	for _, item := range paths {
		if strings.TrimSpace(item.path) == "" {
			return a.commandError("evidence verify-set", *asJSON, ExitUsage, "%s is required", item.flag)
		}
	}
	artifactDirectories := map[string]string{
		"host":    *hostArtifacts,
		"client":  *clientArtifacts,
		"session": *sessionArtifacts,
	}
	artifactDirectoryCount := 0
	for _, directory := range artifactDirectories {
		if strings.TrimSpace(directory) != "" {
			artifactDirectoryCount++
		}
	}
	if artifactDirectoryCount != 0 && artifactDirectoryCount != len(artifactDirectories) {
		return a.commandError("evidence verify-set", *asJSON, ExitUsage, "--host-artifacts, --client-artifacts, and --session-artifacts must be supplied together")
	}
	type loadedRecord struct {
		record evidence.Record
		digest string
	}
	loaded := make(map[string]loadedRecord, 3)
	for _, item := range paths {
		data, err := readBounded(item.path, evidence.MaxRecordSize)
		if err != nil {
			return a.commandError("evidence verify-set", *asJSON, ExitUsage, "read %s evidence: %v", item.name, err)
		}
		record, err := evidence.Parse(data)
		if err != nil {
			return a.commandError("evidence verify-set", *asJSON, ExitBlocked, "%s evidence is invalid: %v", item.name, err)
		}
		loaded[item.name] = loadedRecord{record: record, digest: fmt.Sprintf("%x", sha256.Sum256(data))}
	}
	artifactsVerified := artifactDirectoryCount == len(artifactDirectories)
	var evaluation evidence.SetEvaluation
	var err error
	if artifactsVerified {
		verifications := evidence.ArtifactVerificationSet{}
		for _, item := range []struct {
			name         string
			verification *evidence.ArtifactVerification
		}{{"host", &verifications.Host}, {"client", &verifications.Client}, {"session", &verifications.Session}} {
			verification, verifyErr := evidence.VerifyArtifactBundle(loaded[item.name].record, artifactDirectories[item.name])
			if verifyErr != nil {
				return a.commandError("evidence verify-set", *asJSON, ExitBlocked, "verify %s artifacts: %v", item.name, verifyErr)
			}
			*item.verification = verification
		}
		evaluation, err = evidence.EvaluateVerifiedSetAt(
			loaded["host"].record,
			loaded["client"].record,
			loaded["session"].record,
			loaded["host"].digest,
			loaded["client"].digest,
			verifications,
			a.now(),
		)
	} else {
		evaluation, err = evidence.EvaluateSetAt(
			loaded["host"].record,
			loaded["client"].record,
			loaded["session"].record,
			loaded["host"].digest,
			loaded["client"].digest,
			a.now(),
		)
	}
	if err != nil {
		return a.commandError("evidence verify-set", *asJSON, ExitBlocked, "evidence set cannot be evaluated: %v", err)
	}
	result := evidenceSetValidation{
		HostRecordSHA256:    loaded["host"].digest,
		ClientRecordSHA256:  loaded["client"].digest,
		SessionRecordSHA256: loaded["session"].digest,
		ArtifactsVerified:   artifactsVerified,
		Evaluation:          evaluation,
	}
	if *asJSON {
		if code := a.writeJSON("evidence verify-set", result); code != ExitOK {
			return code
		}
	} else {
		fmt.Fprintf(a.Stdout, "Evidence set state=%s; artifacts_verified=%t; promotion_safe=%t\n", evaluation.State, artifactsVerified, evaluation.PromotionSafe)
		fmt.Fprintf(a.Stdout, "host_sha256=%s\nclient_sha256=%s\nsession_sha256=%s\n", result.HostRecordSHA256, result.ClientRecordSHA256, result.SessionRecordSHA256)
		for _, reason := range evaluation.Reasons {
			fmt.Fprintf(a.Stdout, "- %s\n", reason)
		}
	}
	if evaluation.State != evidence.StateComplete || !evaluation.PromotionSafe {
		return ExitBlocked
	}
	return ExitOK
}

func (a *App) runEvidenceTemplate(args []string) int {
	set := a.flagSet("evidence template")
	recordType := set.String("type", "", "host, client, or session")
	platform := set.String("platform", a.GOOS, "windows for a host; linux or supported BSD for a client/session")
	architecture := set.String("arch", a.GOARCH, "amd64 (the only supported evidence architecture)")
	runID := set.String("run-id", "", "shared run- plus 32 lowercase hexadecimal digits; generated when omitted")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("evidence template", false, ExitUsage, "%v", err)
	}
	if strings.TrimSpace(*recordType) == "" {
		return a.commandError("evidence template", false, ExitUsage, "--type is required")
	}
	record, err := evidence.NewTemplateWithRunID(
		evidence.RecordType(strings.ToLower(strings.TrimSpace(*recordType))),
		*platform,
		*architecture,
		version.Current().Version,
		*runID,
		a.now(),
	)
	if err != nil {
		return a.commandError("evidence template", false, ExitUsage, "cannot create template: %v", err)
	}
	if err := printJSONValue(a.Stdout, record); err != nil {
		return a.commandError("evidence template", false, ExitInternal, "write template: %v", err)
	}
	return ExitOK
}

func (a *App) runEvidenceValidate(args []string) int {
	set := a.flagSet("evidence validate")
	file := set.String("file", "", "validation evidence JSON file")
	artifacts := set.String("artifacts", "", "directory containing exactly the declared artifacts")
	asJSON := set.Bool("json", false, "emit JSON")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("evidence validate", *asJSON, ExitUsage, "%v", err)
	}
	if strings.TrimSpace(*file) == "" {
		return a.commandError("evidence validate", *asJSON, ExitUsage, "--file is required")
	}
	data, err := readBounded(*file, evidence.MaxRecordSize)
	if err != nil {
		return a.commandError("evidence validate", *asJSON, ExitUsage, "read evidence: %v", err)
	}
	record, err := evidence.Parse(data)
	if err != nil {
		return a.commandError("evidence validate", *asJSON, ExitBlocked, "evidence is invalid: %v", err)
	}
	artifactsVerified := strings.TrimSpace(*artifacts) != ""
	var evaluation evidence.Evaluation
	if artifactsVerified {
		verification, verifyErr := evidence.VerifyArtifactBundle(record, *artifacts)
		if verifyErr != nil {
			return a.commandError("evidence validate", *asJSON, ExitBlocked, "verify artifacts: %v", verifyErr)
		}
		evaluation, err = evidence.EvaluateVerifiedAt(record, verification, a.now())
	} else {
		evaluation, err = evidence.EvaluateAt(record, a.now())
	}
	if err != nil {
		return a.commandError("evidence validate", *asJSON, ExitBlocked, "evidence cannot be evaluated: %v", err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	result := evidenceValidation{
		RecordID:          record.RecordID,
		RecordType:        record.RecordType,
		RecordSHA256:      digest,
		ArtifactsVerified: artifactsVerified,
		Evaluation:        evaluation,
	}
	if *asJSON {
		if code := a.writeJSON("evidence validate", result); code != ExitOK {
			return code
		}
	} else {
		fmt.Fprintf(a.Stdout, "Evidence %s is structurally valid; state=%s; artifacts_verified=%t; promotion_safe=%t; sha256=%s\n", record.RecordID, evaluation.State, artifactsVerified, evaluation.PromotionSafe, digest)
		for _, reason := range evaluation.Reasons {
			fmt.Fprintf(a.Stdout, "- %s\n", reason)
		}
	}
	if evaluation.State != evidence.StateComplete || !evaluation.PromotionSafe {
		return ExitBlocked
	}
	return ExitOK
}
