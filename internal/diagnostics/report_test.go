package diagnostics

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestMarshalIsDeterministicAllowlistedAndRedacted(t *testing.T) {
	report := fixedReport()
	report.Checks = []Check{
		{
			ID:          "z-network",
			Status:      StatusWarn,
			Summary:     `alice@example.com uses C:\Users\Alice\LeagueBridge`,
			Detail:      "token=opaque-secret-123 peer=192.168.1.44 hostname=gaming-pc.local",
			Remediation: "See https://support-leagueoflegends.riotgames.com/",
		},
		{
			ID:      "a-runtime",
			Status:  StatusPass,
			Summary: "runtime available",
		},
	}

	first, err := Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("Marshal returned different bytes for the same report")
	}
	if len(first) == 0 || first[len(first)-1] != '\n' {
		t.Fatal("Marshal result does not end in a newline")
	}
	for _, leaked := range []string{
		"alice@example.com", "Alice", "opaque-secret-123", "192.168.1.44", "gaming-pc.local",
	} {
		if bytes.Contains(first, []byte(leaked)) {
			t.Fatalf("report leaked %q:\n%s", leaked, first)
		}
	}
	if !bytes.Contains(first, []byte("support-leagueoflegends.riotgames.com")) {
		t.Fatalf("public remediation context was unexpectedly removed:\n%s", first)
	}
	if report.Checks[0].ID != "z-network" || !strings.Contains(report.Checks[0].Detail, "opaque-secret-123") {
		t.Fatal("Marshal mutated its input")
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(first, &object); err != nil {
		t.Fatal(err)
	}
	assertExactKeys(t, object, "schema_version", "timestamp", "tool_version", "platform", "checks")

	var decoded Report
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Checks) != 2 || decoded.Checks[0].ID != "a-runtime" || decoded.Checks[1].ID != "z-network" {
		t.Fatalf("checks were not deterministically ordered: %+v", decoded.Checks)
	}
	for i, raw := range mustRawChecks(t, object["checks"]) {
		var checkObject map[string]json.RawMessage
		if err := json.Unmarshal(raw, &checkObject); err != nil {
			t.Fatalf("decode check %d: %v", i, err)
		}
		assertExactKeys(t, checkObject, "id", "status", "summary", "detail", "remediation")
	}
	var platformObject map[string]json.RawMessage
	if err := json.Unmarshal(object["platform"], &platformObject); err != nil {
		t.Fatal(err)
	}
	assertExactKeys(t, platformObject, "os", "architecture")
}

func TestEncodingJSONCannotBypassRedaction(t *testing.T) {
	report := fixedReport()
	report.Checks[0].Detail = "password=direct-json-secret"
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("direct-json-secret")) {
		t.Fatalf("encoding/json bypassed redaction: %s", data)
	}
	if !bytes.Contains(data, []byte("REDACTED_SECRET")) {
		t.Fatalf("encoding/json output lacks a redaction marker: %s", data)
	}
}

func TestMarshalRejectsInvalidReports(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{"schema", func(r *Report) { r.SchemaVersion = 0 }},
		{"timestamp", func(r *Report) { r.Timestamp = time.Time{} }},
		{"tool version", func(r *Report) { r.ToolVersion = "bad/version" }},
		{"sensitive tool version", func(r *Report) { r.ToolVersion = "RGAPI-0123456789abcdef" }},
		{"platform OS", func(r *Report) { r.Platform.OS = "" }},
		{"platform architecture", func(r *Report) { r.Platform.Architecture = "amd64;command" }},
		{"duplicate ID", func(r *Report) { r.Checks = append(r.Checks, r.Checks[0]) }},
		{"invalid ID", func(r *Report) { r.Checks[0].ID = "bad/id" }},
		{"invalid status", func(r *Report) { r.Checks[0].Status = Status("maybe") }},
		{"empty summary", func(r *Report) { r.Checks[0].Summary = " \t" }},
		{"oversize summary", func(r *Report) { r.Checks[0].Summary = strings.Repeat("s", MaxSummaryBytes+1) }},
		{"oversize detail", func(r *Report) { r.Checks[0].Detail = strings.Repeat("d", MaxDetailBytes+1) }},
		{"oversize remediation", func(r *Report) { r.Checks[0].Remediation = strings.Repeat("r", MaxRemediationBytes+1) }},
		{"invalid UTF-8", func(r *Report) { r.Checks[0].Detail = string([]byte{0xff}) }},
		{"NUL", func(r *Report) { r.Checks[0].Detail = "before\x00after" }},
		{"too many checks", func(r *Report) {
			r.Checks = make([]Check, MaxChecks+1)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := fixedReport()
			tt.mutate(&report)
			if _, err := Marshal(report); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestMarshalEnforcesFinalSizeBound(t *testing.T) {
	report := fixedReport()
	report.Checks = make([]Check, 17)
	for i := range report.Checks {
		report.Checks[i] = Check{
			ID:      "check-" + string(rune('a'+i)),
			Status:  StatusInfo,
			Summary: "bounded check",
			Detail:  strings.Repeat("x", MaxDetailBytes),
		}
	}
	if _, err := Marshal(report); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected final report size error, got %v", err)
	}
}

func TestPreviewMatchesMarshalAndDoesNotWrite(t *testing.T) {
	directory := t.TempDir()
	oldWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWorkingDirectory) })

	report := fixedReport()
	want, err := Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Preview(report)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("Preview differs from Marshal")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Preview wrote %d filesystem entries", len(entries))
	}
}

func FuzzMarshalDoesNotLeakLabeledSecrets(f *testing.F) {
	for _, seed := range []string{"hunter2", "a value with spaces", "ümlaut", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}
		secret := base64.RawURLEncoding.EncodeToString([]byte(raw))
		if len(secret) < 8 {
			secret += "01234567"
		}
		report := fixedReport()
		report.Checks[0].Detail = "password=" + secret + " access_token=" + secret
		data, err := Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("sanitized report leaked encoded secret: %s", data)
		}
	})
}

func fixedReport() Report {
	return Report{
		SchemaVersion: SchemaVersion,
		Timestamp:     time.Date(2026, time.August, 26, 7, 30, 0, 123456789, time.FixedZone("test", 3*60*60)),
		ToolVersion:   "1.0.0-test",
		Platform: Platform{
			OS:           runtime.GOOS,
			Architecture: runtime.GOARCH,
		},
		Checks: []Check{{
			ID:          "runtime",
			Status:      StatusPass,
			Summary:     "runtime available",
			Detail:      "generated detail",
			Remediation: "",
		}},
	}
}

func assertExactKeys(t *testing.T, object map[string]json.RawMessage, expected ...string) {
	t.Helper()
	if len(object) != len(expected) {
		t.Fatalf("unexpected field count: got %d, want %d (%v)", len(object), len(expected), object)
	}
	for _, key := range expected {
		if _, ok := object[key]; !ok {
			t.Fatalf("required field %q is missing from %v", key, object)
		}
	}
}

func mustRawChecks(t *testing.T, raw json.RawMessage) []json.RawMessage {
	t.Helper()
	var checks []json.RawMessage
	if err := json.Unmarshal(raw, &checks); err != nil {
		t.Fatal(err)
	}
	return checks
}
