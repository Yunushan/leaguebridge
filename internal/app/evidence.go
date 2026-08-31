package app

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/evidence"
	"github.com/Yunushan/leaguebridge/internal/fileinput"
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
		return a.commandError("evidence", false, ExitUsage, "expected template, template-set, validate, verify-set, or v2")
	}
	switch args[0] {
	case "template":
		return a.runEvidenceTemplate(args[1:])
	case "template-set":
		return a.runEvidenceTemplateSet(args[1:])
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
	route := set.String("route", evidence.RoutePhysicalWindowsRemote, "physical-host route: physical-windows-remote or physical-macos-remote")
	platform := set.String("platform", a.GOOS, "windows/macos for a host; linux or supported BSD for a client/session")
	architecture := set.String("arch", a.GOARCH, "amd64 for Windows/Linux/BSD; amd64 or arm64 for a macOS host")
	runID := set.String("run-id", "", "shared run- plus 32 lowercase hexadecimal digits; generated when omitted")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("evidence template", false, ExitUsage, "%v", err)
	}
	if strings.TrimSpace(*recordType) == "" {
		return a.commandError("evidence template", false, ExitUsage, "--type is required")
	}
	routeID, err := normalizeEvidenceRoute(*route)
	if err != nil {
		return a.commandError("evidence template", false, ExitUsage, "%v", err)
	}
	record, err := evidence.NewTemplateWithRunIDAndRoute(
		evidence.RecordType(strings.ToLower(strings.TrimSpace(*recordType))),
		*platform,
		*architecture,
		version.Current().Version,
		*runID,
		routeID,
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

// evidenceTemplateSetResult is deliberately a small, path-oriented result.
// The records themselves are written to separate files so that the exact bytes
// later hashed into a session binding are not changed by a presentation layer.
type evidenceTemplateSetResult struct {
	ValidationRunID string `json:"validation_run_id"`
	Directory       string `json:"directory"`
	Host            string `json:"host"`
	Client          string `json:"client"`
	Session         string `json:"session"`
}

type evidenceTemplateFile struct {
	name string
	data []byte
}

type stagedEvidenceTemplate struct {
	target        string
	temporaryName string
	identity      os.FileInfo
	linked        bool
}

// runEvidenceTemplateSet creates the three schema-v1 records for one shared
// validation run and publishes them as an overwrite-protected set. The host
// route and architecture are explicit; the client platform remains an
// explicit Linux/BSD choice. No record is marked observed or promotion-safe.
func (a *App) runEvidenceTemplateSet(args []string) int {
	set := a.flagSet("evidence template-set")
	directory := set.String("directory", "", "destination directory for host.json, client.json, and session.json")
	route := set.String("route", evidence.RoutePhysicalWindowsRemote, "physical-host route: physical-windows-remote or physical-macos-remote")
	hostArchitecture := set.String("host-arch", "amd64", "host architecture: amd64 for Windows; amd64 or arm64 for macOS")
	clientPlatform := set.String("client-platform", "linux", "linux, freebsd, openbsd, netbsd, or dragonflybsd")
	clientArchitecture := set.String("client-arch", "amd64", "amd64 (the only supported evidence architecture)")
	runID := set.String("run-id", "", "shared run- plus 32 lowercase hexadecimal digits; generated when omitted")
	asJSON := set.Bool("json", false, "emit JSON")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("evidence template-set", *asJSON, ExitUsage, "%v", err)
	}
	if strings.TrimSpace(*directory) == "" {
		return a.commandError("evidence template-set", *asJSON, ExitUsage, "--directory is required")
	}
	routeID, err := normalizeEvidenceRoute(*route)
	if err != nil {
		return a.commandError("evidence template-set", *asJSON, ExitUsage, "%v", err)
	}

	now := a.now()
	hostPlatform := "windows"
	if routeID == evidence.RoutePhysicalMacOSRemote {
		hostPlatform = "macos"
	}
	host, err := evidence.NewTemplateWithRunIDAndRoute(evidence.RecordHost, hostPlatform, *hostArchitecture, version.Current().Version, *runID, routeID, now)
	if err != nil {
		return a.commandError("evidence template-set", *asJSON, ExitUsage, "cannot create host template: %v", err)
	}
	client, err := evidence.NewTemplateWithRunIDAndRoute(evidence.RecordClient, *clientPlatform, *clientArchitecture, version.Current().Version, host.ValidationRunID, routeID, now)
	if err != nil {
		return a.commandError("evidence template-set", *asJSON, ExitUsage, "cannot create client template: %v", err)
	}
	session, err := evidence.NewTemplateWithRunIDAndRoute(evidence.RecordSession, *clientPlatform, *clientArchitecture, version.Current().Version, host.ValidationRunID, routeID, now)
	if err != nil {
		return a.commandError("evidence template-set", *asJSON, ExitUsage, "cannot create session template: %v", err)
	}

	files := make([]evidenceTemplateFile, 0, 3)
	for _, item := range []struct {
		name   string
		record evidence.Record
	}{{"host.json", host}, {"client.json", client}, {"session.json", session}} {
		data, encodeErr := encodeEvidenceRecord(item.record)
		if encodeErr != nil {
			return a.commandError("evidence template-set", *asJSON, ExitInternal, "encode %s: %v", item.name, encodeErr)
		}
		files = append(files, evidenceTemplateFile{name: item.name, data: data})
	}

	absoluteDirectory, err := prepareEvidenceTemplateDirectory(*directory)
	if err != nil {
		return a.commandError("evidence template-set", *asJSON, ExitUsage, "prepare destination: %v", err)
	}
	paths, err := publishEvidenceTemplateSet(absoluteDirectory, files)
	if err != nil {
		return a.commandError("evidence template-set", *asJSON, ExitUsage, "publish template set: %v", err)
	}
	result := evidenceTemplateSetResult{
		ValidationRunID: host.ValidationRunID,
		Directory:       absoluteDirectory,
		Host:            paths["host.json"],
		Client:          paths["client.json"],
		Session:         paths["session.json"],
	}
	if *asJSON {
		return a.writeJSON("evidence template-set", result)
	}
	fmt.Fprintf(a.Stdout, "Created unverified evidence templates for validation_run_id=%s\n", result.ValidationRunID)
	fmt.Fprintf(a.Stdout, "host=%s\nclient=%s\nsession=%s\n", result.Host, result.Client, result.Session)
	fmt.Fprintln(a.Stdout, "The three files are overwrite-protected and share the same validation run; replace checks only with observed evidence.")
	return ExitOK
}

func normalizeEvidenceRoute(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "windows", evidence.RoutePhysicalWindowsRemote:
		return evidence.RoutePhysicalWindowsRemote, nil
	case "macos", "darwin", evidence.RoutePhysicalMacOSRemote:
		return evidence.RoutePhysicalMacOSRemote, nil
	default:
		return "", fmt.Errorf("route must be windows, macos, %s, or %s", evidence.RoutePhysicalWindowsRemote, evidence.RoutePhysicalMacOSRemote)
	}
}

func encodeEvidenceRecord(record evidence.Record) ([]byte, error) {
	var output bytes.Buffer
	if err := printJSONValue(&output, record); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func prepareEvidenceTemplateDirectory(directory string) (string, error) {
	directory = strings.TrimSpace(directory)
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return "", fmt.Errorf("resolve directory: %w", err)
	}
	if err := fileinput.EnsureDirectoryTree(absolute, 0o700); err != nil {
		return "", fmt.Errorf("create directory: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", fmt.Errorf("inspect directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("destination must be a regular, non-symlink directory")
	}
	return absolute, nil
}

// publishEvidenceTemplateSet stages every file before linking any destination.
// Final paths are created with an exclusive same-directory hard link, so an
// existing file is never overwritten. If publication fails after one link, the
// helper removes only files whose identity still matches its own staged file.
func publishEvidenceTemplateSet(directory string, files []evidenceTemplateFile) (map[string]string, error) {
	root, err := fileinput.OpenDirectoryRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	staged := make([]stagedEvidenceTemplate, 0, len(files))
	cleanup := func(removePublished bool) {
		for _, item := range staged {
			if removePublished && item.linked {
				targetName := filepath.Base(item.target)
				if info, err := root.Lstat(targetName); err == nil && item.identity != nil && os.SameFile(info, item.identity) {
					_ = root.Remove(targetName)
				}
			}
			if item.temporaryName != "" {
				_ = root.Remove(item.temporaryName)
			}
		}
	}

	// Check the complete destination set first so a collision cannot leave a
	// newly generated subset beside an older set.
	for _, file := range files {
		target := filepath.Join(directory, file.name)
		if _, err := root.Lstat(file.name); err == nil {
			return nil, fmt.Errorf("destination already exists: %s", target)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect destination %s: %w", target, err)
		}
	}

	for _, file := range files {
		target := filepath.Join(directory, file.name)
		temporary, temporaryName, err := fileinput.CreateTempFile(root, ".leaguebridge-evidence-", 0o600)
		if err != nil {
			cleanup(false)
			return nil, fmt.Errorf("create temporary file for %s: %w", file.name, err)
		}
		stagedItem := stagedEvidenceTemplate{target: target, temporaryName: temporaryName}
		staged = append(staged, stagedItem)
		if chmodErr := temporary.Chmod(0o600); chmodErr != nil {
			err = chmodErr
		} else {
			if n, writeErr := temporary.Write(file.data); writeErr != nil {
				err = writeErr
			} else if n != len(file.data) {
				err = io.ErrShortWrite
			}
		}
		if err == nil {
			err = temporary.Sync()
		}
		if closeErr := temporary.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			cleanup(false)
			return nil, fmt.Errorf("stage %s: %w", file.name, err)
		}
		identity, err := root.Lstat(temporaryName)
		if err != nil {
			cleanup(false)
			return nil, fmt.Errorf("inspect staged %s: %w", file.name, err)
		}
		if identity.Mode()&os.ModeSymlink != 0 || !identity.Mode().IsRegular() {
			cleanup(false)
			return nil, fmt.Errorf("staged %s is not a regular, non-symlink file", file.name)
		}
		staged[len(staged)-1].identity = identity
	}

	paths := make(map[string]string, len(staged))
	for index := range staged {
		item := &staged[index]
		if err := fileinput.LinkInRoot(root, item.temporaryName, filepath.Base(item.target)); err != nil {
			cleanup(true)
			return nil, fmt.Errorf("publish %s: %w", filepath.Base(item.target), err)
		}
		item.linked = true
		paths[filepath.Base(item.target)] = item.target
	}
	cleanup(false)
	return paths, nil
}
