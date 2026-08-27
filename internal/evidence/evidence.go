// Package evidence defines bounded, versioned manual-validation records for
// physical streaming hosts, Linux/BSD clients, and end-to-end sessions.
// Records are evidence inputs, never launch authorization by themselves.
package evidence

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Yunushan/leaguebridge/internal/compat"
	"github.com/Yunushan/leaguebridge/internal/fileinput"
)

const (
	SchemaID                   = "https://leaguebridge.dev/schemas/validation-evidence.schema.json"
	SchemaVersion              = 1
	RoutePhysicalWindowsRemote = "physical-windows-remote"
	TestProfileRemotePlayV1    = "remote-play-v1"
	SessionMetricsV1           = "session-metrics-v1"
	MaxRecordSize              = 1 << 20
	MaxValidity                = 30 * 24 * time.Hour
	MaxArtifactSize            = 1 << 30
	MaxArtifactBundleSize      = 4 << 30

	MinimumSessionDurationSeconds      = 1800
	MaximumSessionDurationSeconds      = 8 * 60 * 60
	MinimumStreamWidth                 = 1920
	MinimumStreamHeight                = 1080
	MaximumStreamDimension             = 8192
	MinimumTargetFrameRate             = 60
	MaximumTargetFrameRate             = 240
	MinimumAverageFrameRate            = 55
	MaximumAverageFrameRate            = 240
	MaximumMeasurementSampleCount      = 10_000_000
	MaximumMeasurementSamplesPerSecond = 1000
	MaximumEncodeLatencyMS             = 30
	MaximumNetworkLatencyMS            = 80
	MaximumDecodeLatencyMS             = 30
	MaximumEndToEndLatencyMS           = 150
	MaximumDroppedFramesPercent        = 1
)

type RecordType string

const (
	RecordHost    RecordType = "host"
	RecordClient  RecordType = "client"
	RecordSession RecordType = "session"
)

type CheckStatus string

const (
	StatusPass       CheckStatus = "pass"
	StatusFail       CheckStatus = "fail"
	StatusUnverified CheckStatus = "unverified"
	StatusNA         CheckStatus = "not-applicable"
)

type CheckMethod string

const (
	MethodAutomatic CheckMethod = "automatic"
	MethodManual    CheckMethod = "manual"
	MethodExternal  CheckMethod = "external"
)

type AttestationLevel string

const (
	AttestationSelf        AttestationLevel = "self-attested"
	AttestationLab         AttestationLevel = "lab-observed"
	AttestationIndependent AttestationLevel = "independent-review"
)

type State string

const (
	StateComplete       State = "complete"
	StateClaimsComplete State = "claims-complete"
	StatePending        State = "pending"
	StateExpired        State = "expired"
)

type Record struct {
	Schema                 string                  `json:"$schema"`
	SchemaVersion          int                     `json:"schema_version"`
	RecordID               string                  `json:"record_id"`
	RecordType             RecordType              `json:"record_type"`
	ValidationRunID        string                  `json:"validation_run_id"`
	RouteID                string                  `json:"route_id"`
	TestProfileID          string                  `json:"test_profile_id"`
	CreatedAt              string                  `json:"created_at"`
	ExpiresAt              string                  `json:"expires_at"`
	ManifestAsOf           string                  `json:"manifest_as_of"`
	ManifestSHA256         string                  `json:"manifest_sha256"`
	ToolVersion            string                  `json:"tool_version"`
	Subject                Subject                 `json:"subject"`
	Attestation            Attestation             `json:"attestation"`
	Bindings               *Bindings               `json:"bindings,omitempty"`
	StreamProfile          *StreamProfile          `json:"stream_profile,omitempty"`
	MeasurementMethodology *MeasurementMethodology `json:"measurement_methodology,omitempty"`
	Checks                 []Check                 `json:"checks"`
	Measurements           []Measurement           `json:"measurements,omitempty"`
}

type Subject struct {
	Role         RecordType `json:"role"`
	Platform     string     `json:"platform"`
	Architecture string     `json:"architecture"`
	Environment  string     `json:"environment"`
}

type Attestation struct {
	Level      AttestationLevel `json:"level"`
	Reviewer   string           `json:"reviewer"`
	ReviewedAt string           `json:"reviewed_at"`
	Artifacts  []Artifact       `json:"artifacts"`
	Notes      string           `json:"notes"`
}

type Bindings struct {
	HostRecordSHA256   string `json:"host_record_sha256"`
	ClientRecordSHA256 string `json:"client_record_sha256"`
}

type Check struct {
	ID         string      `json:"id"`
	Status     CheckStatus `json:"status"`
	Method     CheckMethod `json:"method"`
	ObservedAt string      `json:"observed_at"`
	Summary    string      `json:"summary"`
	Artifacts  []Artifact  `json:"artifacts"`
}

type Artifact struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	MediaType string `json:"media_type"`
}

type StreamProfile struct {
	Width           int     `json:"width"`
	Height          int     `json:"height"`
	TargetFrameRate float64 `json:"target_frame_rate"`
	Codec           string  `json:"codec"`
	Transport       string  `json:"transport"`
}

// MeasurementMethodology identifies the single bounded capture from which all
// required session metrics were aggregated.
type MeasurementMethodology struct {
	Version               string `json:"version"`
	CaptureStartedAt      string `json:"capture_started_at"`
	CaptureEndedAt        string `json:"capture_ended_at"`
	SampleCount           int64  `json:"sample_count"`
	CollectorID           string `json:"collector_id"`
	CollectorVersion      string `json:"collector_version"`
	CaptureArtifactSHA256 string `json:"capture_artifact_sha256"`
}

type Measurement struct {
	ID    string  `json:"id"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
}

type Evaluation struct {
	State         State    `json:"state"`
	PromotionSafe bool     `json:"promotion_safe"`
	Reasons       []string `json:"reasons"`
}

type SetEvaluation struct {
	State         State      `json:"state"`
	PromotionSafe bool       `json:"promotion_safe"`
	Host          Evaluation `json:"host"`
	Client        Evaluation `json:"client"`
	Session       Evaluation `json:"session"`
	Reasons       []string   `json:"reasons"`
}

var (
	recordIDPattern     = regexp.MustCompile(`^(?:host|client|session)-[a-f0-9]{32}$`)
	runIDPattern        = regexp.MustCompile(`^run-[a-f0-9]{32}$`)
	idPattern           = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)
	sha256Pattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
	artifactNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
)

var requiredChecks = map[RecordType][]string{
	RecordHost: {
		"host.physical-machine",
		"host.supported-os",
		"host.hardware-requirements",
		"host.security-requirements",
		"host.riot-installation",
		"host.local-practice-tool",
		"host.streaming-server",
	},
	RecordClient: {
		"client.platform",
		"client.moonlight",
		"client.display",
		"client.audio",
		"client.decoder",
	},
	RecordSession: {
		"session.pair",
		"session.app-list",
		"session.video",
		"session.keyboard-mouse",
		"session.audio",
		"session.latency",
		"session.practice-tool",
		"session.vanguard-errors",
		"session.patch-current",
	},
}

type measurementRequirement struct {
	ID               string
	Unit             string
	RequirePositive  bool
	MinimumInclusive float64
	MaximumInclusive float64
	HasMaximum       bool
}

var requiredSessionMeasurements = []measurementRequirement{
	{ID: "session-duration", Unit: "seconds", MinimumInclusive: MinimumSessionDurationSeconds, MaximumInclusive: MaximumSessionDurationSeconds, HasMaximum: true},
	{ID: "average-frame-rate", Unit: "fps", MinimumInclusive: MinimumAverageFrameRate, MaximumInclusive: MaximumAverageFrameRate, HasMaximum: true},
	{ID: "encode-latency", Unit: "ms", RequirePositive: true, MaximumInclusive: MaximumEncodeLatencyMS, HasMaximum: true},
	{ID: "network-latency", Unit: "ms", RequirePositive: true, MaximumInclusive: MaximumNetworkLatencyMS, HasMaximum: true},
	{ID: "decode-latency", Unit: "ms", RequirePositive: true, MaximumInclusive: MaximumDecodeLatencyMS, HasMaximum: true},
	{ID: "end-to-end-latency", Unit: "ms", RequirePositive: true, MaximumInclusive: MaximumEndToEndLatencyMS, HasMaximum: true},
	{ID: "dropped-frames", Unit: "percent", MaximumInclusive: MaximumDroppedFramesPercent, HasMaximum: true},
}

var checkSummaries = map[string]string{
	"host.physical-machine":      "Confirm a retail physical host without concealing or spoofing virtualization.",
	"host.supported-os":          "Record a currently supported and updated host operating system.",
	"host.hardware-requirements": "Verify CPU, GPU, memory, storage, and driver requirements against Riot guidance.",
	"host.security-requirements": "Verify applicable Secure Boot, TPM, VBS/HVCI, and IOMMU requirements using vendor guidance.",
	"host.riot-installation":     "Verify official Riot Client, League, and anti-cheat installation integrity.",
	"host.local-practice-tool":   "Complete a direct local Practice Tool session before streaming.",
	"host.streaming-server":      "Verify Sunshine is current, safely bound, and configured without exposing credentials.",
	"client.platform":            "Record the native Linux or BSD kernel and userspace version.",
	"client.moonlight":           "Verify a trusted Moonlight installation and record its version.",
	"client.display":             "Verify the active desktop/display stack and fullscreen behavior.",
	"client.audio":               "Verify usable audio output on the client.",
	"client.decoder":             "Verify hardware or software decode capability under an actual stream.",
	"session.pair":               "Pair Moonlight and Sunshine without routing credentials through LeagueBridge.",
	"session.app-list":           "Retrieve the configured streaming application list successfully.",
	"session.video":              "Verify stable video, fullscreen/window behavior, and reconnect.",
	"session.keyboard-mouse":     "Verify keyboard, mouse, modifiers, cursor capture, camera movement, and chat input.",
	"session.audio":              "Verify game audio throughout the session.",
	"session.latency":            "Record encode, network, decode, and end-to-end latency plus dropped frames.",
	"session.practice-tool":      "Complete Practice Tool or a custom game through the streamed session.",
	"session.vanguard-errors":    "Confirm that Riot Client and Vanguard reported no streaming-related error.",
	"session.patch-current":      "Record the League patch and repeat validation after material updates.",
}

// NewTemplate creates a structurally valid, deliberately unverified record.
func NewTemplate(recordType RecordType, platform, architecture, toolVersion string, now time.Time) (Record, error) {
	return NewTemplateWithRunID(recordType, platform, architecture, toolVersion, "", now)
}

// NewTemplateWithRunID creates a template for an existing validation run. An
// empty runID generates a new privacy-safe random identifier.
func NewTemplateWithRunID(recordType RecordType, platform, architecture, toolVersion, runID string, now time.Time) (Record, error) {
	if now.IsZero() {
		return Record{}, errors.New("template time is required")
	}
	if toolVersion = strings.TrimSpace(toolVersion); toolVersion == "" {
		toolVersion = "unknown"
	}
	recordID, err := newRecordID(recordType)
	if err != nil {
		return Record{}, err
	}
	if runID = strings.TrimSpace(runID); runID == "" {
		runID, err = newRunID()
		if err != nil {
			return Record{}, err
		}
	} else if !runIDPattern.MatchString(runID) {
		return Record{}, fmt.Errorf("invalid validation run id %q", runID)
	}
	checks, ok := requiredChecks[recordType]
	if !ok {
		return Record{}, fmt.Errorf("unsupported evidence type %q", recordType)
	}
	manifest, err := compat.Embedded()
	if err != nil {
		return Record{}, fmt.Errorf("load embedded compatibility evidence: %w", err)
	}
	manifestDigest, err := compat.CanonicalSHA256(manifest)
	if err != nil {
		return Record{}, fmt.Errorf("digest embedded compatibility evidence: %w", err)
	}
	recordChecks := make([]Check, 0, len(checks))
	for _, id := range checks {
		recordChecks = append(recordChecks, Check{ID: id, Status: StatusUnverified, Method: MethodManual, Summary: checkSummaries[id], Artifacts: []Artifact{}})
	}
	record := Record{
		Schema:          SchemaID,
		SchemaVersion:   SchemaVersion,
		RecordID:        recordID,
		RecordType:      recordType,
		ValidationRunID: runID,
		RouteID:         RoutePhysicalWindowsRemote,
		TestProfileID:   TestProfileRemotePlayV1,
		CreatedAt:       now.UTC().Format(time.RFC3339),
		ExpiresAt:       now.UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
		ManifestAsOf:    compat.AuthoritativeAsOf,
		ManifestSHA256:  manifestDigest,
		ToolVersion:     toolVersion,
		Subject: Subject{
			Role:         recordType,
			Platform:     normalizePlatform(platform),
			Architecture: normalizeArchitecture(architecture),
			Environment:  "unverified",
		},
		Attestation: Attestation{
			Level:      AttestationSelf,
			Reviewer:   "",
			ReviewedAt: "",
			Artifacts:  []Artifact{},
			Notes:      "Replace unverified checks only with observed evidence; do not include credentials or machine identifiers.",
		},
		Checks: recordChecks,
	}
	if recordType == RecordSession {
		record.Bindings = &Bindings{}
		record.StreamProfile = &StreamProfile{Codec: "unverified", Transport: "unverified"}
		record.MeasurementMethodology = &MeasurementMethodology{Version: SessionMetricsV1}
		record.Measurements = make([]Measurement, 0, len(requiredSessionMeasurements))
		for _, requirement := range requiredSessionMeasurements {
			record.Measurements = append(record.Measurements, Measurement{ID: requirement.ID, Value: 0, Unit: requirement.Unit})
		}
	}
	if err := Validate(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func newRunID() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate validation run id: %w", err)
	}
	return "run-" + hex.EncodeToString(random), nil
}

func newRecordID(recordType RecordType) (string, error) {
	if _, ok := requiredChecks[recordType]; !ok {
		return "", fmt.Errorf("unsupported evidence type %q", recordType)
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate evidence record id: %w", err)
	}
	return string(recordType) + "-" + hex.EncodeToString(random), nil
}

// Parse strictly decodes one bounded record and rejects duplicate/unknown fields.
func Parse(data []byte) (Record, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return Record{}, errors.New("evidence record is empty")
	}
	if len(data) > MaxRecordSize {
		return Record{}, fmt.Errorf("evidence record exceeds %d bytes", MaxRecordSize)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return Record{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record Record
	if err := decoder.Decode(&record); err != nil {
		return Record{}, fmt.Errorf("decode evidence record: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Record{}, errors.New("decode evidence record: trailing JSON value")
		}
		return Record{}, fmt.Errorf("decode evidence record: %w", err)
	}
	if err := rejectUnknownKeys(data); err != nil {
		return Record{}, err
	}
	if err := Validate(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

// ReadFile reads only a regular, non-symlink input and enforces MaxRecordSize.
func ReadFile(path string) (Record, error) {
	file, err := fileinput.OpenRegular(path)
	if err != nil {
		return Record{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxRecordSize+1))
	if err != nil {
		return Record{}, err
	}
	return Parse(data)
}

// Validate enforces record identity, platform role, freshness bounds, and the
// exact required check inventory. It does not promote a record.
func Validate(record Record) error {
	if record.Schema != SchemaID {
		return fmt.Errorf("unknown evidence $schema %q", record.Schema)
	}
	if record.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported evidence schema_version %d", record.SchemaVersion)
	}
	if !recordIDPattern.MatchString(record.RecordID) || !strings.HasPrefix(record.RecordID, string(record.RecordType)+"-") {
		return fmt.Errorf("invalid evidence record_id %q", record.RecordID)
	}
	required, ok := requiredChecks[record.RecordType]
	if !ok {
		return fmt.Errorf("unsupported evidence record_type %q", record.RecordType)
	}
	if !runIDPattern.MatchString(record.ValidationRunID) {
		return fmt.Errorf("invalid validation_run_id %q", record.ValidationRunID)
	}
	if record.RouteID != RoutePhysicalWindowsRemote {
		return fmt.Errorf("unsupported evidence route_id %q", record.RouteID)
	}
	if record.TestProfileID != TestProfileRemotePlayV1 {
		return fmt.Errorf("unsupported evidence test_profile_id %q", record.TestProfileID)
	}
	if !sha256Pattern.MatchString(record.ManifestSHA256) {
		return errors.New("manifest_sha256 must be a lowercase SHA-256")
	}
	created, err := parseTimestamp("created_at", record.CreatedAt)
	if err != nil {
		return err
	}
	expires, err := parseTimestamp("expires_at", record.ExpiresAt)
	if err != nil {
		return err
	}
	if !expires.After(created) || expires.Sub(created) > MaxValidity {
		return fmt.Errorf("expires_at must be after created_at and within %s", MaxValidity)
	}
	manifestDate, err := time.Parse("2006-01-02", record.ManifestAsOf)
	if err != nil {
		return errors.New("manifest_as_of must be a valid YYYY-MM-DD date")
	}
	createdDate, _ := time.Parse("2006-01-02", created.UTC().Format("2006-01-02"))
	if createdDate.Before(manifestDate) {
		return errors.New("created_at cannot precede manifest_as_of")
	}
	if !validText(record.ToolVersion, 256) {
		return errors.New("tool_version is required and must not exceed 256 bytes")
	}
	if err := validateSubject(record.RecordType, record.Subject); err != nil {
		return err
	}
	if err := validateAttestation(record.Attestation); err != nil {
		return err
	}
	if record.RecordType == RecordSession {
		if record.Bindings == nil {
			return errors.New("session evidence requires bindings")
		}
		for _, binding := range []struct {
			name  string
			value string
		}{
			{"host_record_sha256", record.Bindings.HostRecordSHA256},
			{"client_record_sha256", record.Bindings.ClientRecordSHA256},
		} {
			if binding.value != "" && !sha256Pattern.MatchString(binding.value) {
				return fmt.Errorf("bindings.%s must be empty or lowercase SHA-256", binding.name)
			}
		}
		if record.StreamProfile == nil {
			return errors.New("session evidence requires stream_profile")
		}
		if err := validateStreamProfile(*record.StreamProfile); err != nil {
			return err
		}
		if record.MeasurementMethodology == nil {
			return errors.New("session evidence requires measurement_methodology")
		}
	} else {
		if record.Bindings != nil {
			return errors.New("bindings are allowed only for session evidence")
		}
		if record.StreamProfile != nil {
			return errors.New("stream_profile is allowed only for session evidence")
		}
		if record.MeasurementMethodology != nil {
			return errors.New("measurement_methodology is allowed only for session evidence")
		}
	}
	if err := validateChecks(record.Checks, required); err != nil {
		return err
	}
	if err := validateGlobalArtifactNames(record); err != nil {
		return err
	}
	if err := validateTimeOrder(record, created, expires); err != nil {
		return err
	}
	if err := validateMeasurements(record.RecordType, record.Measurements); err != nil {
		return err
	}
	if record.RecordType == RecordSession {
		if err := validateMeasurementMethodology(record, created, expires); err != nil {
			return err
		}
	}
	return nil
}

func validateTimeOrder(record Record, created, expires time.Time) error {
	var reviewed time.Time
	if record.Attestation.Level != AttestationSelf {
		reviewed, _ = time.Parse(time.RFC3339, record.Attestation.ReviewedAt)
		if reviewed.Before(created) {
			return errors.New("attestation.reviewed_at cannot precede created_at")
		}
		if !reviewed.Before(expires) {
			return errors.New("attestation.reviewed_at must precede expires_at")
		}
	}
	for _, check := range record.Checks {
		if check.Status == StatusUnverified {
			continue
		}
		observed, _ := time.Parse(time.RFC3339, check.ObservedAt)
		if observed.Before(created) {
			return fmt.Errorf("check %q observed_at cannot precede created_at", check.ID)
		}
		if !observed.Before(expires) {
			return fmt.Errorf("check %q observed_at must precede expires_at", check.ID)
		}
		if record.Attestation.Level != AttestationSelf && observed.After(reviewed) {
			return fmt.Errorf("check %q observed_at cannot follow attestation.reviewed_at", check.ID)
		}
	}
	return nil
}

func validateSubject(recordType RecordType, subject Subject) error {
	if subject.Role != recordType {
		return fmt.Errorf("subject.role %q does not match record_type %q", subject.Role, recordType)
	}
	if !validText(subject.Environment, 512) {
		return errors.New("subject.environment is required and must not exceed 512 bytes")
	}
	switch recordType {
	case RecordHost:
		if subject.Platform != "windows" {
			return errors.New("physical-windows-remote host evidence platform must be windows")
		}
		if subject.Architecture != "amd64" {
			return errors.New("Windows host evidence architecture must be amd64")
		}
	case RecordClient, RecordSession:
		switch subject.Platform {
		case "linux", "freebsd", "openbsd", "netbsd", "dragonflybsd":
		default:
			return errors.New("client/session evidence platform must be linux or a supported BSD")
		}
		if subject.Architecture != "amd64" {
			return errors.New("client/session evidence architecture must be amd64")
		}
	}
	return nil
}

func validateStreamProfile(profile StreamProfile) error {
	if profile.Width < 0 || profile.Width > MaximumStreamDimension || profile.Height < 0 || profile.Height > MaximumStreamDimension {
		return fmt.Errorf("stream_profile dimensions must be between 0 and %d", MaximumStreamDimension)
	}
	if math.IsNaN(profile.TargetFrameRate) || math.IsInf(profile.TargetFrameRate, 0) || profile.TargetFrameRate < 0 || profile.TargetFrameRate > MaximumTargetFrameRate {
		return fmt.Errorf("stream_profile.target_frame_rate must be finite and between 0 and %d", MaximumTargetFrameRate)
	}
	switch profile.Codec {
	case "unverified", "h264", "hevc", "av1":
	default:
		return fmt.Errorf("invalid stream_profile.codec %q", profile.Codec)
	}
	switch profile.Transport {
	case "unverified", "wired-lan", "wifi", "wan":
	default:
		return fmt.Errorf("invalid stream_profile.transport %q", profile.Transport)
	}
	return nil
}

func validateAttestation(attestation Attestation) error {
	switch attestation.Level {
	case AttestationSelf:
		if strings.TrimSpace(attestation.Reviewer) != "" {
			return errors.New("self-attested evidence must not name a reviewer")
		}
		if strings.TrimSpace(attestation.ReviewedAt) != "" {
			return errors.New("self-attested evidence must not set reviewed_at")
		}
		if len(attestation.Artifacts) != 0 {
			return errors.New("self-attested evidence must not claim review artifacts")
		}
	case AttestationLab, AttestationIndependent:
		if !validText(attestation.Reviewer, 256) {
			return errors.New("reviewed evidence requires a bounded reviewer identifier")
		}
		if _, err := parseTimestamp("attestation.reviewed_at", attestation.ReviewedAt); err != nil {
			return err
		}
		if err := validateArtifacts("attestation.artifacts", attestation.Artifacts, 1, 16); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid attestation level %q", attestation.Level)
	}
	if len(attestation.Notes) > 4096 {
		return errors.New("attestation notes exceed 4096 bytes")
	}
	return nil
}

func validateChecks(checks []Check, required []string) error {
	if len(checks) != len(required) {
		return fmt.Errorf("evidence record has %d checks; want %d", len(checks), len(required))
	}
	wanted := make(map[string]struct{}, len(required))
	for _, id := range required {
		wanted[id] = struct{}{}
	}
	seen := make(map[string]struct{}, len(checks))
	for _, check := range checks {
		if _, ok := wanted[check.ID]; !ok {
			return fmt.Errorf("unexpected evidence check %q", check.ID)
		}
		if _, duplicate := seen[check.ID]; duplicate {
			return fmt.Errorf("duplicate evidence check %q", check.ID)
		}
		seen[check.ID] = struct{}{}
		switch check.Status {
		case StatusPass, StatusFail, StatusUnverified, StatusNA:
		default:
			return fmt.Errorf("check %q has invalid status %q", check.ID, check.Status)
		}
		switch check.Method {
		case MethodAutomatic, MethodManual, MethodExternal:
		default:
			return fmt.Errorf("check %q has invalid method %q", check.ID, check.Method)
		}
		if !validText(check.Summary, 1024) {
			return fmt.Errorf("check %q summary is required and must not exceed 1024 bytes", check.ID)
		}
		if check.Status == StatusUnverified {
			if strings.TrimSpace(check.ObservedAt) != "" || len(check.Artifacts) != 0 {
				return fmt.Errorf("unverified check %q must not claim observations or artifacts", check.ID)
			}
			continue
		}
		if _, err := parseTimestamp("check "+check.ID+" observed_at", check.ObservedAt); err != nil {
			return err
		}
		if err := validateArtifacts("check "+check.ID+" artifacts", check.Artifacts, 1, 16); err != nil {
			return err
		}
	}
	return nil
}

func validateMeasurements(recordType RecordType, measurements []Measurement) error {
	if len(measurements) > 64 {
		return errors.New("evidence record has more than 64 measurements")
	}
	seen := make(map[string]struct{}, len(measurements))
	for _, measurement := range measurements {
		if len(measurement.ID) > 128 || !idPattern.MatchString(measurement.ID) {
			return fmt.Errorf("invalid measurement id %q", measurement.ID)
		}
		if _, duplicate := seen[measurement.ID]; duplicate {
			return fmt.Errorf("duplicate measurement %q", measurement.ID)
		}
		seen[measurement.ID] = struct{}{}
		if math.IsNaN(measurement.Value) || math.IsInf(measurement.Value, 0) || measurement.Value < 0 {
			return fmt.Errorf("measurement %q value must be finite and non-negative", measurement.ID)
		}
		if !validText(measurement.Unit, 64) {
			return fmt.Errorf("measurement %q unit is required", measurement.ID)
		}
		if measurement.ID == "dropped-frames" && measurement.Value > 100 {
			return errors.New("measurement \"dropped-frames\" cannot exceed 100 percent")
		}
		if measurement.ID == "session-duration" && measurement.Value > MaximumSessionDurationSeconds {
			return fmt.Errorf("measurement \"session-duration\" cannot exceed %d seconds", MaximumSessionDurationSeconds)
		}
		if measurement.ID == "average-frame-rate" && measurement.Value > MaximumAverageFrameRate {
			return fmt.Errorf("measurement \"average-frame-rate\" cannot exceed %d fps", MaximumAverageFrameRate)
		}
	}
	if recordType == RecordSession {
		for _, requirement := range requiredSessionMeasurements {
			found := false
			for _, measurement := range measurements {
				if measurement.ID == requirement.ID {
					found = true
					if measurement.Unit != requirement.Unit {
						return fmt.Errorf("session measurement %q must use unit %q", requirement.ID, requirement.Unit)
					}
					break
				}
			}
			if !found {
				return fmt.Errorf("session evidence requires measurement %q", requirement.ID)
			}
		}
	}
	return nil
}

func validateMeasurementMethodology(record Record, created, expires time.Time) error {
	methodology := *record.MeasurementMethodology
	if methodology.Version != SessionMetricsV1 {
		return fmt.Errorf("unsupported measurement_methodology.version %q", methodology.Version)
	}
	if methodology.CaptureStartedAt == "" {
		if methodology.CaptureEndedAt != "" || methodology.SampleCount != 0 || methodology.CollectorID != "" || methodology.CollectorVersion != "" || methodology.CaptureArtifactSHA256 != "" {
			return errors.New("unverified measurement_methodology must use empty capture fields and zero sample_count")
		}
		return nil
	}
	started, err := parseTimestamp("measurement_methodology.capture_started_at", methodology.CaptureStartedAt)
	if err != nil {
		return err
	}
	ended, err := parseTimestamp("measurement_methodology.capture_ended_at", methodology.CaptureEndedAt)
	if err != nil {
		return err
	}
	if !ended.After(started) {
		return errors.New("measurement_methodology.capture_ended_at must follow capture_started_at")
	}
	if started.Before(created) {
		return errors.New("measurement_methodology.capture_started_at cannot precede created_at")
	}
	if !ended.Before(expires) {
		return errors.New("measurement_methodology.capture_ended_at must precede expires_at")
	}
	duration := ended.Sub(started).Seconds()
	if duration > MaximumSessionDurationSeconds {
		return fmt.Errorf("measurement capture cannot exceed %d seconds", MaximumSessionDurationSeconds)
	}
	if methodology.SampleCount < 1 || methodology.SampleCount > MaximumMeasurementSampleCount {
		return fmt.Errorf("measurement_methodology.sample_count must be between 1 and %d", MaximumMeasurementSampleCount)
	}
	minimumSamples := int64(math.Ceil(duration))
	maximumSamples := int64(math.Ceil(duration * MaximumMeasurementSamplesPerSecond))
	if methodology.SampleCount < minimumSamples || methodology.SampleCount > maximumSamples {
		return fmt.Errorf("measurement_methodology.sample_count must provide between 1 and %d common observations per capture second", MaximumMeasurementSamplesPerSecond)
	}
	if len(methodology.CollectorID) > 128 || !idPattern.MatchString(methodology.CollectorID) {
		return errors.New("measurement_methodology.collector_id must be a bounded lowercase identifier")
	}
	if !validText(methodology.CollectorVersion, 128) {
		return errors.New("measurement_methodology.collector_version is required and must not exceed 128 bytes")
	}
	if !sha256Pattern.MatchString(methodology.CaptureArtifactSHA256) {
		return errors.New("measurement_methodology.capture_artifact_sha256 must be a lowercase SHA-256")
	}
	if record.Attestation.Level != AttestationSelf {
		reviewed, _ := time.Parse(time.RFC3339, record.Attestation.ReviewedAt)
		if ended.After(reviewed) {
			return errors.New("measurement capture cannot end after attestation.reviewed_at")
		}
	}
	bound := false
	for _, check := range record.Checks {
		if check.ID != "session.latency" {
			continue
		}
		for _, artifact := range check.Artifacts {
			if artifact.SHA256 == methodology.CaptureArtifactSHA256 {
				bound = true
				break
			}
		}
	}
	if !bound {
		return errors.New("measurement capture must bind to an artifact declared by check session.latency")
	}
	durationValue := 0.0
	for _, measurement := range record.Measurements {
		if measurement.ID == "session-duration" {
			durationValue = measurement.Value
			break
		}
	}
	if math.Abs(durationValue-duration) > 0.001 {
		return fmt.Errorf("session-duration %.3f seconds does not match capture interval %.3f seconds", durationValue, duration)
	}
	return nil
}

// EvaluateAt returns claims-complete only for fresh, current-manifest, reviewed
// records whose exact required checks all pass. Artifact descriptors remain
// unverified. It never authorizes gameplay or launch.
func EvaluateAt(record Record, now time.Time) (Evaluation, error) {
	return evaluateAt(record, nil, now)
}

// EvaluateVerifiedAt returns complete only when verification was produced by
// VerifyArtifactBundle for this exact record. Manual reviewer identity remains
// unauthenticated and PromotionSafe is therefore always false.
func EvaluateVerifiedAt(record Record, verification ArtifactVerification, now time.Time) (Evaluation, error) {
	return evaluateAt(record, &verification, now)
}

func evaluateAt(record Record, verification *ArtifactVerification, now time.Time) (Evaluation, error) {
	if err := Validate(record); err != nil {
		return Evaluation{}, err
	}
	artifactsVerified := verification != nil
	if artifactsVerified {
		matches, err := matchesArtifactVerification(record, *verification)
		if err != nil {
			return Evaluation{}, err
		}
		if !matches {
			return Evaluation{}, errors.New("artifact verification does not match the evaluated evidence record")
		}
	}
	if now.IsZero() {
		return Evaluation{}, errors.New("evaluation time is required")
	}
	now = now.UTC()
	created, _ := time.Parse(time.RFC3339, record.CreatedAt)
	expires, _ := time.Parse(time.RFC3339, record.ExpiresAt)
	if !now.Before(expires) {
		return Evaluation{State: StateExpired, PromotionSafe: false, Reasons: []string{"evidence record has expired"}}, nil
	}
	reasons := make([]string, 0)
	if created.After(now) {
		reasons = append(reasons, "record creation time is in the future")
	}
	if record.ManifestAsOf != compat.AuthoritativeAsOf {
		reasons = append(reasons, "record does not target the current embedded compatibility evidence date")
	}
	manifest, err := compat.Embedded()
	if err != nil {
		return Evaluation{}, fmt.Errorf("load embedded compatibility evidence: %w", err)
	}
	currentManifestDigest, err := compat.CanonicalSHA256(manifest)
	if err != nil {
		return Evaluation{}, fmt.Errorf("digest embedded compatibility evidence: %w", err)
	}
	if record.ManifestSHA256 != currentManifestDigest {
		reasons = append(reasons, "record is not bound to the current embedded compatibility manifest content")
	}
	freshness, err := manifest.FreshnessAt(now)
	if err != nil {
		return Evaluation{}, fmt.Errorf("evaluate embedded compatibility evidence freshness: %w", err)
	}
	if freshness.State != compat.FreshnessFresh {
		reasons = append(reasons, fmt.Sprintf("embedded compatibility evidence is %s", freshness.State))
	}
	if record.Attestation.Level == AttestationSelf {
		reasons = append(reasons, "self-attested evidence requires lab or independent review")
	} else {
		reviewed, _ := time.Parse(time.RFC3339, record.Attestation.ReviewedAt)
		if reviewed.After(now) {
			reasons = append(reasons, "review timestamp is in the future")
		}
	}
	if record.RecordType == RecordSession && (record.Bindings.HostRecordSHA256 == "" || record.Bindings.ClientRecordSHA256 == "") {
		reasons = append(reasons, "session evidence is not bound to host and client record hashes")
	}
	for _, check := range record.Checks {
		if check.Status != StatusUnverified {
			observed, _ := time.Parse(time.RFC3339, check.ObservedAt)
			if observed.After(now) {
				reasons = append(reasons, fmt.Sprintf("check %s observation is in the future", check.ID))
			}
		}
		if check.Status != StatusPass {
			reasons = append(reasons, fmt.Sprintf("check %s is %s", check.ID, check.Status))
		}
	}
	if record.RecordType == RecordSession {
		methodology := *record.MeasurementMethodology
		if methodology.CaptureStartedAt == "" {
			reasons = append(reasons, "session measurement capture methodology is unverified")
		} else {
			started, _ := time.Parse(time.RFC3339, methodology.CaptureStartedAt)
			ended, _ := time.Parse(time.RFC3339, methodology.CaptureEndedAt)
			if started.After(now) {
				reasons = append(reasons, "session measurement capture start is in the future")
			}
			if ended.After(now) {
				reasons = append(reasons, "session measurement capture end is in the future")
			}
		}
		reasons = append(reasons, streamProfileReasons(*record.StreamProfile)...)
		reasons = append(reasons, sessionMeasurementReasons(record.Measurements, *record.StreamProfile)...)
	}
	if len(reasons) != 0 {
		return Evaluation{State: StatePending, PromotionSafe: false, Reasons: reasons}, nil
	}
	// Attestation fields and artifact references are user-authored data. Until a
	// future schema verifies them against an embedded trust root, no record can
	// safely drive an automated readiness promotion.
	state := StateClaimsComplete
	completionReason := "all required claims passed, but declared artifact bytes were not supplied and verified"
	if artifactsVerified {
		state = StateComplete
		completionReason = "all required claims passed and every declared artifact byte was size- and SHA-256-verified"
	}
	if record.RecordType == RecordSession {
		completionReason += "; host/client binding values still require evidence verify-set"
	}
	completionReason += "; manual review claims are not authenticated by a trusted key and cannot promote readiness automatically"
	return Evaluation{State: state, PromotionSafe: false, Reasons: []string{completionReason}}, nil
}

// EvaluateSetAt evaluates an exact host/client/session chain. The supplied
// digests must be SHA-256 hashes of the raw host and client record bytes.
func EvaluateSetAt(host, client, session Record, hostDigest, clientDigest string, now time.Time) (SetEvaluation, error) {
	return evaluateSetAt(host, client, session, hostDigest, clientDigest, nil, now)
}

// ArtifactVerificationSet binds three artifact-bundle verification results to
// the corresponding exact host, client, and session records.
type ArtifactVerificationSet struct {
	Host    ArtifactVerification
	Client  ArtifactVerification
	Session ArtifactVerification
}

// EvaluateVerifiedSetAt evaluates a hash-bound record set whose three artifact
// bundles have already been verified. It still never promotes manual evidence.
func EvaluateVerifiedSetAt(host, client, session Record, hostDigest, clientDigest string, verifications ArtifactVerificationSet, now time.Time) (SetEvaluation, error) {
	return evaluateSetAt(host, client, session, hostDigest, clientDigest, &verifications, now)
}

func evaluateSetAt(host, client, session Record, hostDigest, clientDigest string, verifications *ArtifactVerificationSet, now time.Time) (SetEvaluation, error) {
	for _, pair := range []struct {
		name   string
		record Record
		want   RecordType
	}{
		{"host", host, RecordHost},
		{"client", client, RecordClient},
		{"session", session, RecordSession},
	} {
		if pair.record.RecordType != pair.want {
			return SetEvaluation{}, fmt.Errorf("%s record has type %q; want %q", pair.name, pair.record.RecordType, pair.want)
		}
	}
	if !sha256Pattern.MatchString(hostDigest) || !sha256Pattern.MatchString(clientDigest) {
		return SetEvaluation{}, errors.New("host and client record digests must be lowercase SHA-256")
	}
	if host.RouteID != client.RouteID || host.RouteID != session.RouteID {
		return SetEvaluation{}, errors.New("host, client, and session route_id values must match")
	}
	var hostEvaluation, clientEvaluation, sessionEvaluation Evaluation
	var err error
	if verifications == nil {
		hostEvaluation, err = EvaluateAt(host, now)
	} else {
		hostEvaluation, err = EvaluateVerifiedAt(host, verifications.Host, now)
	}
	if err != nil {
		return SetEvaluation{}, fmt.Errorf("evaluate host evidence: %w", err)
	}
	if verifications == nil {
		clientEvaluation, err = EvaluateAt(client, now)
	} else {
		clientEvaluation, err = EvaluateVerifiedAt(client, verifications.Client, now)
	}
	if err != nil {
		return SetEvaluation{}, fmt.Errorf("evaluate client evidence: %w", err)
	}
	if verifications == nil {
		sessionEvaluation, err = EvaluateAt(session, now)
	} else {
		sessionEvaluation, err = EvaluateVerifiedAt(session, verifications.Session, now)
	}
	if err != nil {
		return SetEvaluation{}, fmt.Errorf("evaluate session evidence: %w", err)
	}

	result := SetEvaluation{Host: hostEvaluation, Client: clientEvaluation, Session: sessionEvaluation}
	reasons := make([]string, 0)
	if session.Bindings.HostRecordSHA256 != hostDigest {
		reasons = append(reasons, "session host binding does not match the supplied host record")
	}
	if session.Bindings.ClientRecordSHA256 != clientDigest {
		reasons = append(reasons, "session client binding does not match the supplied client record")
	}
	if session.Subject.Platform != client.Subject.Platform || session.Subject.Architecture != client.Subject.Architecture {
		reasons = append(reasons, "session subject does not match the supplied client platform and architecture")
	}
	if host.ValidationRunID != client.ValidationRunID || host.ValidationRunID != session.ValidationRunID {
		reasons = append(reasons, "host, client, and session validation_run_id values do not match")
	}
	sessionExpires, _ := time.Parse(time.RFC3339, session.ExpiresAt)
	hostExpires, _ := time.Parse(time.RFC3339, host.ExpiresAt)
	clientExpires, _ := time.Parse(time.RFC3339, client.ExpiresAt)
	if sessionExpires.After(hostExpires) {
		reasons = append(reasons, "session evidence expires after the bound host evidence")
	}
	if sessionExpires.After(clientExpires) {
		reasons = append(reasons, "session evidence expires after the bound client evidence")
	}
	if session.MeasurementMethodology.CaptureStartedAt != "" {
		captureStarted, _ := time.Parse(time.RFC3339, session.MeasurementMethodology.CaptureStartedAt)
		for _, reviewedRecord := range []struct {
			name   string
			record Record
		}{{"host", host}, {"client", client}} {
			if reviewedRecord.record.Attestation.Level == AttestationSelf {
				continue
			}
			reviewed, _ := time.Parse(time.RFC3339, reviewedRecord.record.Attestation.ReviewedAt)
			if !reviewed.Before(captureStarted) {
				reasons = append(reasons, fmt.Sprintf("%s review must complete before the session capture starts", reviewedRecord.name))
			}
		}
	}
	expired := false
	wantState := StateClaimsComplete
	if verifications != nil {
		wantState = StateComplete
	}
	for _, item := range []struct {
		name       string
		evaluation Evaluation
	}{
		{"host", hostEvaluation},
		{"client", clientEvaluation},
		{"session", sessionEvaluation},
	} {
		evaluation := item.evaluation
		if evaluation.State == StateExpired {
			expired = true
		}
		if evaluation.State != wantState {
			for _, reason := range evaluation.Reasons {
				reasons = append(reasons, item.name+": "+reason)
			}
		}
	}
	if len(reasons) != 0 {
		result.State = StatePending
		if expired {
			result.State = StateExpired
		}
		result.Reasons = reasons
		return result, nil
	}
	result.State = wantState
	result.PromotionSafe = false
	if verifications == nil {
		result.Reasons = []string{"the record claims and supplied binding digest values are complete, but declared artifact bytes were not supplied or verified and manual review claims are unauthenticated"}
	} else {
		result.Reasons = []string{"the evidence set is hash-bound and every declared artifact byte was verified, but manual review claims are not authenticated by a trusted key and cannot promote readiness automatically"}
	}
	return result, nil
}

func sessionMeasurementReasons(measurements []Measurement, profile StreamProfile) []string {
	values := make(map[string]float64, len(measurements))
	for _, measurement := range measurements {
		values[measurement.ID] = measurement.Value
	}
	reasons := make([]string, 0)
	for _, requirement := range requiredSessionMeasurements {
		value := values[requirement.ID]
		if requirement.RequirePositive && value <= 0 {
			reasons = append(reasons, fmt.Sprintf("session measurement %s is still a zero placeholder", requirement.ID))
			continue
		}
		if value < requirement.MinimumInclusive {
			reasons = append(reasons, fmt.Sprintf("session measurement %s is %.3f %s; minimum is %.3f %s", requirement.ID, value, requirement.Unit, requirement.MinimumInclusive, requirement.Unit))
		}
		if requirement.HasMaximum && value > requirement.MaximumInclusive {
			reasons = append(reasons, fmt.Sprintf("session measurement %s is %.3f %s; maximum is %.3f %s", requirement.ID, value, requirement.Unit, requirement.MaximumInclusive, requirement.Unit))
		}
	}
	for _, component := range []string{"encode-latency", "network-latency", "decode-latency"} {
		if values["end-to-end-latency"] < values[component] {
			reasons = append(reasons, fmt.Sprintf("session end-to-end p95 latency is lower than %s p95 latency and is internally inconsistent", component))
		}
	}
	if profile.TargetFrameRate > 0 && values["average-frame-rate"] < profile.TargetFrameRate*0.9 {
		reasons = append(reasons, "session average frame rate is below 90 percent of the recorded target frame rate")
	}
	return reasons
}

func streamProfileReasons(profile StreamProfile) []string {
	reasons := make([]string, 0)
	if profile.Width < MinimumStreamWidth || profile.Height < MinimumStreamHeight {
		reasons = append(reasons, fmt.Sprintf("stream target is %dx%d; minimum profile is %dx%d", profile.Width, profile.Height, MinimumStreamWidth, MinimumStreamHeight))
	}
	if profile.TargetFrameRate < MinimumTargetFrameRate {
		reasons = append(reasons, fmt.Sprintf("stream target frame rate is %.3f fps; minimum is %.3f fps", profile.TargetFrameRate, float64(MinimumTargetFrameRate)))
	}
	if profile.Codec == "unverified" {
		reasons = append(reasons, "stream codec is unverified")
	}
	if profile.Transport == "unverified" {
		reasons = append(reasons, "stream transport is unverified")
	}
	return reasons
}

func validateArtifacts(name string, artifacts []Artifact, minimum, maximum int) error {
	if len(artifacts) < minimum || len(artifacts) > maximum {
		return fmt.Errorf("%s must contain between %d and %d entries", name, minimum, maximum)
	}
	seen := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		if !artifactNamePattern.MatchString(artifact.Name) {
			return fmt.Errorf("%s artifact name %q is invalid", name, artifact.Name)
		}
		if _, duplicate := seen[artifact.Name]; duplicate {
			return fmt.Errorf("%s contains duplicate artifact name %q", name, artifact.Name)
		}
		seen[artifact.Name] = struct{}{}
		if !sha256Pattern.MatchString(artifact.SHA256) {
			return fmt.Errorf("%s artifact %q must have a lowercase SHA-256", name, artifact.Name)
		}
		if artifact.SizeBytes <= 0 || artifact.SizeBytes > MaxArtifactSize {
			return fmt.Errorf("%s artifact %q size_bytes must be between 1 and %d", name, artifact.Name, MaxArtifactSize)
		}
		mediaType, parameters, err := mime.ParseMediaType(artifact.MediaType)
		if err != nil || len(parameters) != 0 || mediaType != artifact.MediaType || mediaType != strings.ToLower(mediaType) {
			return fmt.Errorf("%s artifact %q has invalid canonical media_type", name, artifact.Name)
		}
	}
	return nil
}

func normalizePlatform(value string) string {
	switch value = strings.ToLower(strings.TrimSpace(value)); value {
	case "darwin":
		return "macos"
	case "dragonfly":
		return "dragonflybsd"
	default:
		return value
	}
}

func normalizeArchitecture(value string) string {
	switch value = strings.ToLower(strings.TrimSpace(value)); value {
	case "x86_64", "x64":
		return "amd64"
	case "aarch64":
		return "arm64"
	default:
		return value
	}
}

func parseTimestamp(name, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339", name)
	}
	return parsed, nil
}

func validText(value string, maximum int) bool {
	return len(value) <= maximum && strings.TrimSpace(value) != ""
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSON(decoder, "$", 0); err != nil {
		return fmt.Errorf("decode evidence record: %w", err)
	}
	return nil
}

func rejectUnknownKeys(data []byte) error {
	top, err := decodeObject(data, "$")
	if err != nil {
		return fmt.Errorf("decode evidence record: %w", err)
	}
	if err := exactKeys(top, "$", "$schema", "schema_version", "record_id", "record_type", "validation_run_id", "route_id", "test_profile_id", "created_at", "expires_at", "manifest_as_of", "manifest_sha256", "tool_version", "subject", "attestation", "bindings", "stream_profile", "measurement_methodology", "checks", "measurements"); err != nil {
		return err
	}
	if err := requireKeys(top, "$", "$schema", "schema_version", "record_id", "record_type", "validation_run_id", "route_id", "test_profile_id", "created_at", "expires_at", "manifest_as_of", "manifest_sha256", "tool_version", "subject", "attestation", "checks"); err != nil {
		return err
	}

	subject, err := decodeObject(top["subject"], "$.subject")
	if err != nil {
		return fmt.Errorf("decode evidence record: %w", err)
	}
	if err := exactKeys(subject, "$.subject", "role", "platform", "architecture", "environment"); err != nil {
		return err
	}
	if err := requireKeys(subject, "$.subject", "role", "platform", "architecture", "environment"); err != nil {
		return err
	}

	attestation, err := decodeObject(top["attestation"], "$.attestation")
	if err != nil {
		return fmt.Errorf("decode evidence record: %w", err)
	}
	if err := exactKeys(attestation, "$.attestation", "level", "reviewer", "reviewed_at", "artifacts", "notes"); err != nil {
		return err
	}
	if err := requireKeys(attestation, "$.attestation", "level", "reviewer", "reviewed_at", "artifacts", "notes"); err != nil {
		return err
	}
	attestationArtifacts, err := decodeArray(attestation["artifacts"], "$.attestation.artifacts")
	if err != nil {
		return fmt.Errorf("decode evidence record: %w", err)
	}
	if err := validateRawArtifacts(attestationArtifacts, "$.attestation.artifacts"); err != nil {
		return err
	}

	if raw, present := top["bindings"]; present {
		bindings, err := decodeObject(raw, "$.bindings")
		if err != nil {
			return fmt.Errorf("decode evidence record: %w", err)
		}
		if err := exactKeys(bindings, "$.bindings", "host_record_sha256", "client_record_sha256"); err != nil {
			return err
		}
		if err := requireKeys(bindings, "$.bindings", "host_record_sha256", "client_record_sha256"); err != nil {
			return err
		}
	}
	if raw, present := top["stream_profile"]; present {
		profile, err := decodeObject(raw, "$.stream_profile")
		if err != nil {
			return fmt.Errorf("decode evidence record: %w", err)
		}
		if err := exactKeys(profile, "$.stream_profile", "width", "height", "target_frame_rate", "codec", "transport"); err != nil {
			return err
		}
		if err := requireKeys(profile, "$.stream_profile", "width", "height", "target_frame_rate", "codec", "transport"); err != nil {
			return err
		}
	}
	if raw, present := top["measurement_methodology"]; present {
		methodology, err := decodeObject(raw, "$.measurement_methodology")
		if err != nil {
			return fmt.Errorf("decode evidence record: %w", err)
		}
		if err := exactKeys(methodology, "$.measurement_methodology", "version", "capture_started_at", "capture_ended_at", "sample_count", "collector_id", "collector_version", "capture_artifact_sha256"); err != nil {
			return err
		}
		if err := requireKeys(methodology, "$.measurement_methodology", "version", "capture_started_at", "capture_ended_at", "sample_count", "collector_id", "collector_version", "capture_artifact_sha256"); err != nil {
			return err
		}
	}

	checks, err := decodeArray(top["checks"], "$.checks")
	if err != nil {
		return fmt.Errorf("decode evidence record: %w", err)
	}
	for index, item := range checks {
		path := fmt.Sprintf("$.checks[%d]", index)
		object, err := decodeObject(item, path)
		if err != nil {
			return fmt.Errorf("decode evidence record: %w", err)
		}
		if err := exactKeys(object, path, "id", "status", "method", "observed_at", "summary", "artifacts"); err != nil {
			return err
		}
		if err := requireKeys(object, path, "id", "status", "method", "observed_at", "summary", "artifacts"); err != nil {
			return err
		}
		artifacts, err := decodeArray(object["artifacts"], path+".artifacts")
		if err != nil {
			return fmt.Errorf("decode evidence record: %w", err)
		}
		if err := validateRawArtifacts(artifacts, path+".artifacts"); err != nil {
			return err
		}
	}

	if raw, present := top["measurements"]; present {
		measurements, err := decodeArray(raw, "$.measurements")
		if err != nil {
			return fmt.Errorf("decode evidence record: %w", err)
		}
		for index, item := range measurements {
			path := fmt.Sprintf("$.measurements[%d]", index)
			object, err := decodeObject(item, path)
			if err != nil {
				return fmt.Errorf("decode evidence record: %w", err)
			}
			if err := exactKeys(object, path, "id", "value", "unit"); err != nil {
				return err
			}
			if err := requireKeys(object, path, "id", "value", "unit"); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateRawArtifacts(items []json.RawMessage, path string) error {
	for index, item := range items {
		itemPath := fmt.Sprintf("%s[%d]", path, index)
		object, err := decodeObject(item, itemPath)
		if err != nil {
			return fmt.Errorf("decode evidence record: %w", err)
		}
		if err := exactKeys(object, itemPath, "name", "sha256", "size_bytes", "media_type"); err != nil {
			return err
		}
		if err := requireKeys(object, itemPath, "name", "sha256", "size_bytes", "media_type"); err != nil {
			return err
		}
	}
	return nil
}

func decodeObject(data []byte, path string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, fmt.Errorf("%s must be an object", path)
	}
	if object == nil {
		return nil, fmt.Errorf("%s must be an object", path)
	}
	return object, nil
}

func decodeArray(data []byte, path string) ([]json.RawMessage, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, fmt.Errorf("%s must be an array", path)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("%s must be an array", path)
	}
	return items, nil
}

func exactKeys(object map[string]json.RawMessage, path string, allowed ...string) error {
	wanted := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		wanted[key] = struct{}{}
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, ok := wanted[key]; !ok {
			return fmt.Errorf("decode evidence record: %s has unknown field %q", path, key)
		}
	}
	return nil
}

func requireKeys(object map[string]json.RawMessage, path string, required ...string) error {
	for _, key := range required {
		value, ok := object[key]
		if !ok {
			return fmt.Errorf("decode evidence record: %s is missing required field %q", path, key)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("decode evidence record: %s field %q must not be null", path, key)
		}
	}
	return nil
}

func walkJSON(decoder *json.Decoder, path string, depth int) error {
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
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("%s object key is not a string", path)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("%s has duplicate key %q", path, key)
			}
			seen[key] = struct{}{}
			if err := walkJSON(decoder, path+"."+key, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		index := 0
		for decoder.More() {
			if err := walkJSON(decoder, fmt.Sprintf("%s[%d]", path, index), depth+1); err != nil {
				return err
			}
			index++
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("%s has unexpected delimiter %q", path, delimiter)
	}
}
