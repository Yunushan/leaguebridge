// Package diagnostics creates bounded, credential-free support reports.
package diagnostics

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Yunushan/leaguebridge/internal/redact"
)

const (
	SchemaVersion = 1

	MaxChecks           = 256
	MaxToolVersionBytes = 128
	MaxCheckIDBytes     = 128
	MaxSummaryBytes     = 4 * 1024
	MaxDetailBytes      = 64 * 1024
	MaxRemediationBytes = 16 * 1024
	MaxReportSize       = 1024 * 1024
)

// Status is the bounded outcome of a diagnostic check.
type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	StatusInfo Status = "info"
)

// Platform intentionally excludes hostnames, usernames, device identifiers,
// and network addresses.
type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

// Check is generated diagnostic context, not captured process output. Detail
// and Remediation may explain a result but must never be used for raw logs.
// Marshal applies defense-in-depth redaction to all three text fields.
type Check struct {
	ID          string `json:"id"`
	Status      Status `json:"status"`
	Summary     string `json:"summary"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

// Report is an allowlist of information permitted in a support bundle. Adding
// a new diagnostic category requires an explicit schema change here.
type Report struct {
	SchemaVersion int       `json:"schema_version"`
	Timestamp     time.Time `json:"timestamp"`
	ToolVersion   string    `json:"tool_version"`
	Platform      Platform  `json:"platform"`
	Checks        []Check   `json:"checks"`
}

// NewReport creates a report for the current process and time. Marshal is the
// validation and redaction boundary and should be used before displaying or
// persisting the report.
func NewReport(toolVersion string, checks ...Check) Report {
	return Report{
		SchemaVersion: SchemaVersion,
		Timestamp:     time.Now().UTC(),
		ToolVersion:   toolVersion,
		Platform: Platform{
			OS:           runtime.GOOS,
			Architecture: runtime.GOARCH,
		},
		Checks: append([]Check(nil), checks...),
	}
}

// Marshal validates, redacts, sorts, and deterministically encodes a report.
// For an identical Report value it returns identical bytes. A final newline is
// included so the result is suitable for a terminal or a support bundle.
func Marshal(report Report) ([]byte, error) {
	clean, err := normalize(report)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(reportWire(clean), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode diagnostic report: %w", err)
	}
	data = append(data, '\n')
	if len(data) > MaxReportSize {
		return nil, fmt.Errorf("diagnostic report exceeds %d bytes", MaxReportSize)
	}
	return data, nil
}

// MarshalJSON keeps direct use of encoding/json behind the same validation and
// redaction boundary. Marshal remains the preferred deterministic, indented
// representation used by previews and bundles.
func (report Report) MarshalJSON() ([]byte, error) {
	clean, err := normalize(report)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(reportWire(clean))
	if err != nil {
		return nil, fmt.Errorf("encode diagnostic report: %w", err)
	}
	if len(data) > MaxReportSize {
		return nil, fmt.Errorf("diagnostic report exceeds %d bytes", MaxReportSize)
	}
	return data, nil
}

type reportWire Report

// Preview returns exactly the sanitized JSON that WriteBundle would include.
// It performs no filesystem operations.
func Preview(report Report) ([]byte, error) {
	return Marshal(report)
}

func normalize(report Report) (Report, error) {
	if report.SchemaVersion != SchemaVersion {
		return Report{}, fmt.Errorf("unsupported diagnostic schema_version %d (expected %d)", report.SchemaVersion, SchemaVersion)
	}
	if report.Timestamp.IsZero() {
		return Report{}, errors.New("diagnostic timestamp is required")
	}
	if report.Timestamp.Year() < 1 || report.Timestamp.Year() > 9999 {
		return Report{}, errors.New("diagnostic timestamp is outside the JSON time range")
	}
	if err := validateIdentifier("tool version", report.ToolVersion, MaxToolVersionBytes); err != nil {
		return Report{}, err
	}
	if redact.String(report.ToolVersion) != report.ToolVersion {
		return Report{}, errors.New("tool version resembles sensitive data")
	}
	if err := validateIdentifier("platform OS", report.Platform.OS, 32); err != nil {
		return Report{}, err
	}
	if err := validateIdentifier("platform architecture", report.Platform.Architecture, 32); err != nil {
		return Report{}, err
	}
	if report.Platform.OS != runtime.GOOS || report.Platform.Architecture != runtime.GOARCH {
		return Report{}, errors.New("diagnostic platform does not match the running tool")
	}
	if len(report.Checks) > MaxChecks {
		return Report{}, fmt.Errorf("diagnostic report has more than %d checks", MaxChecks)
	}

	clean := Report{
		SchemaVersion: SchemaVersion,
		Timestamp:     report.Timestamp.UTC().Round(0),
		ToolVersion:   report.ToolVersion,
		Platform:      report.Platform,
		Checks:        make([]Check, len(report.Checks)),
	}
	seen := make(map[string]struct{}, len(report.Checks))
	for i, check := range report.Checks {
		if err := validateIdentifier("check ID", check.ID, MaxCheckIDBytes); err != nil {
			return Report{}, fmt.Errorf("check %d: %w", i, err)
		}
		if redact.String(check.ID) != check.ID {
			return Report{}, fmt.Errorf("check %d: check ID resembles sensitive data", i)
		}
		if _, exists := seen[check.ID]; exists {
			return Report{}, fmt.Errorf("check %d duplicates a check ID", i)
		}
		seen[check.ID] = struct{}{}
		if !check.Status.valid() {
			return Report{}, fmt.Errorf("check %d has an invalid status", i)
		}
		if err := validateText("summary", check.Summary, MaxSummaryBytes, true); err != nil {
			return Report{}, fmt.Errorf("check %d: %w", i, err)
		}
		if err := validateText("detail", check.Detail, MaxDetailBytes, false); err != nil {
			return Report{}, fmt.Errorf("check %d: %w", i, err)
		}
		if err := validateText("remediation", check.Remediation, MaxRemediationBytes, false); err != nil {
			return Report{}, fmt.Errorf("check %d: %w", i, err)
		}

		clean.Checks[i] = Check{
			ID:          check.ID,
			Status:      check.Status,
			Summary:     redact.String(check.Summary),
			Detail:      redact.String(check.Detail),
			Remediation: redact.String(check.Remediation),
		}
	}

	// Check IDs are unique, so sorting by ID fully determines array order and
	// prevents map/filesystem discovery order from changing a report.
	sort.Slice(clean.Checks, func(i, j int) bool {
		return clean.Checks[i].ID < clean.Checks[j].ID
	})
	return clean, nil
}

func (s Status) valid() bool {
	switch s {
	case StatusPass, StatusWarn, StatusFail, StatusInfo:
		return true
	default:
		return false
	}
}

func validateIdentifier(name, value string, maxBytes int) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("%s exceeds %d bytes", name, maxBytes)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '.', '-', '_', '+', '~':
			continue
		default:
			return fmt.Errorf("%s contains unsupported characters", name)
		}
	}
	return nil
}

func validateText(name, value string, maxBytes int, required bool) error {
	if required && strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("%s exceeds %d bytes", name, maxBytes)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	if strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("%s contains a NUL byte", name)
	}
	return nil
}
