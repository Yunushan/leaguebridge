package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/compat"
)

var testNow = time.Date(2026, time.August, 26, 12, 0, 0, 0, time.UTC)

func TestNewTemplate(t *testing.T) {
	tests := []struct {
		name         string
		recordType   RecordType
		platform     string
		architecture string
		wantPlatform string
		wantArch     string
	}{
		{"Windows host", RecordHost, "WINDOWS", "x86_64", "windows", "amd64"},
		{"Linux client", RecordClient, "LINUX", "x64", "linux", "amd64"},
		{"DragonFly session", RecordSession, "dragonfly", "amd64", "dragonflybsd", "amd64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record, err := NewTemplate(tt.recordType, tt.platform, tt.architecture, "v1.2.3", testNow)
			if err != nil {
				t.Fatal(err)
			}
			if record.Schema != SchemaID || record.SchemaVersion != SchemaVersion || record.RouteID != RoutePhysicalWindowsRemote || record.ManifestAsOf != compat.AuthoritativeAsOf {
				t.Fatalf("unexpected contract identity: %+v", record)
			}
			if !runIDPattern.MatchString(record.ValidationRunID) {
				t.Fatalf("validation run id = %q", record.ValidationRunID)
			}
			manifest, err := compat.Embedded()
			if err != nil {
				t.Fatal(err)
			}
			wantDigest, err := compat.CanonicalSHA256(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if record.ManifestSHA256 != wantDigest {
				t.Fatalf("manifest digest = %q, want %q", record.ManifestSHA256, wantDigest)
			}
			if !strings.HasPrefix(record.RecordID, string(tt.recordType)+"-") || len(record.RecordID) != len(tt.recordType)+33 {
				t.Fatalf("record id = %q", record.RecordID)
			}
			if record.Subject.Platform != tt.wantPlatform || record.Subject.Architecture != tt.wantArch {
				t.Fatalf("subject = %+v", record.Subject)
			}
			if record.Attestation.Level != AttestationSelf || record.Attestation.Artifacts == nil {
				t.Fatalf("attestation = %+v", record.Attestation)
			}
			for _, check := range record.Checks {
				if check.Status != StatusUnverified || check.ObservedAt != "" || check.Artifacts == nil || len(check.Artifacts) != 0 {
					t.Fatalf("template check unexpectedly claims evidence: %+v", check)
				}
			}
			if tt.recordType == RecordSession {
				if record.Bindings == nil || record.MeasurementMethodology == nil || record.MeasurementMethodology.Version != SessionMetricsV1 || len(record.Measurements) != len(requiredSessionMeasurements) {
					t.Fatalf("session fields = bindings=%+v methodology=%+v measurements=%+v", record.Bindings, record.MeasurementMethodology, record.Measurements)
				}
			} else if record.Bindings != nil {
				t.Fatalf("non-session has bindings: %+v", record.Bindings)
			}
			if err := Validate(record); err != nil {
				t.Fatalf("template did not validate: %v", err)
			}
		})
	}
	const runID = "run-0123456789abcdef0123456789abcdef"
	shared, err := NewTemplateWithRunID(RecordClient, "linux", "amd64", "test", runID, testNow)
	if err != nil || shared.ValidationRunID != runID {
		t.Fatalf("shared run template = %+v, err=%v", shared, err)
	}

}

func TestNewTemplateRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name         string
		recordType   RecordType
		platform     string
		architecture string
		now          time.Time
	}{
		{"unknown type", "other", "linux", "amd64", testNow},
		{"zero time", RecordClient, "linux", "amd64", time.Time{}},
		{"host platform", RecordHost, "linux", "amd64", testNow},
		{"macOS host is not the implemented route", RecordHost, "darwin", "arm64", testNow},
		{"Windows architecture", RecordHost, "windows", "arm64", testNow},
		{"client platform", RecordClient, "windows", "amd64", testNow},
		{"client architecture", RecordClient, "linux", "arm64", testNow},
	}
	if _, err := NewTemplateWithRunID(RecordClient, "linux", "amd64", "dev", "machine-name", testNow); err == nil {
		t.Fatal("invalid validation run id was accepted")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewTemplate(tt.recordType, tt.platform, tt.architecture, "dev", tt.now); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseStrictRoundTrip(t *testing.T) {
	record := completeRecord(t, RecordSession, AttestationIndependent)
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.RecordID != record.RecordID || len(parsed.Checks) != len(record.Checks) {
		t.Fatalf("parsed record differs: %+v", parsed)
	}

	valid := string(data)
	tests := []struct {
		name string
		data string
		want string
	}{
		{"empty", "  ", "empty"},
		{"non-object", "[]", "cannot unmarshal"},
		{"duplicate top key", strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1), "duplicate key"},
		{"duplicate nested key", strings.Replace(valid, `"platform":"linux"`, `"platform":"linux","platform":"linux"`, 1), "duplicate key"},
		{"unknown top field", strings.Replace(valid, `"record_id":`, `"unexpected":true,"record_id":`, 1), "unknown field"},
		{"case variant field", strings.Replace(valid, `"record_id":`, `"Record_id":`, 1), "unknown field"},
		{"unknown check field", strings.Replace(valid, `"status":"pass"`, `"extra":true,"status":"pass"`, 1), "unknown field"},
		{"trailing value", valid + ` {}`, "trailing JSON value"},
		{"invalid structure", `{}`, "missing required field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want substring %q", err, tt.want)
			}
		})
	}

	shapeTests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"missing route", func(value map[string]any) { delete(value, "route_id") }, "missing required field \"route_id\""},
		{"missing validation run", func(value map[string]any) { delete(value, "validation_run_id") }, "missing required field \"validation_run_id\""},
		{"missing reviewer", func(value map[string]any) { delete(value["attestation"].(map[string]any), "reviewer") }, "missing required field \"reviewer\""},
		{"null notes", func(value map[string]any) { value["attestation"].(map[string]any)["notes"] = nil }, "must not be null"},
		{"missing observed at", func(value map[string]any) { delete(value["checks"].([]any)[0].(map[string]any), "observed_at") }, "missing required field \"observed_at\""},
		{"null check artifacts", func(value map[string]any) { value["checks"].([]any)[0].(map[string]any)["artifacts"] = nil }, "must not be null"},
		{"null bindings", func(value map[string]any) { value["bindings"] = nil }, "must be an object"},
		{"null methodology", func(value map[string]any) { value["measurement_methodology"] = nil }, "must be an object"},
		{"missing methodology sample count", func(value map[string]any) { delete(value["measurement_methodology"].(map[string]any), "sample_count") }, "missing required field \"sample_count\""},
		{"null measurements", func(value map[string]any) { value["measurements"] = nil }, "must be an array"},
		{"missing measurement unit", func(value map[string]any) { delete(value["measurements"].([]any)[0].(map[string]any), "unit") }, "missing required field \"unit\""},
	}
	for _, tt := range shapeTests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := mutateJSONRecord(t, data, tt.mutate)
			_, err := Parse(mutated)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want substring %q", err, tt.want)
			}
		})
	}

	clientData, err := json.Marshal(completeRecord(t, RecordClient, AttestationIndependent))
	if err != nil {
		t.Fatal(err)
	}
	clientWithNullBindings := mutateJSONRecord(t, clientData, func(value map[string]any) { value["bindings"] = nil })
	if _, err := Parse(clientWithNullBindings); err == nil || !strings.Contains(err.Error(), "must be an object") {
		t.Fatalf("null optional bindings err = %v", err)
	}

	if _, err := Parse(make([]byte, MaxRecordSize+1)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize err = %v", err)
	}
	deep := strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66)
	if _, err := Parse([]byte(deep)); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("deep nesting err = %v", err)
	}
}

func FuzzParse(f *testing.F) {
	record, err := NewTemplateWithRunID(RecordSession, "linux", "amd64", "fuzz-seed", "run-0123456789abcdef0123456789abcdef", testNow)
	if err != nil {
		f.Fatal(err)
	}
	valid, err := json.Marshal(record)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"$schema":"duplicate","$schema":"key"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxRecordSize+1 {
			return
		}
		parsed, err := Parse(data)
		if err != nil {
			return
		}
		if err := Validate(parsed); err != nil {
			t.Fatalf("Parse accepted a record rejected by Validate: %v", err)
		}
		canonical, err := json.Marshal(parsed)
		if err != nil {
			t.Fatalf("marshal accepted record: %v", err)
		}
		if _, err := Parse(canonical); err != nil {
			t.Fatalf("reparse accepted record: %v", err)
		}
	})
}

func TestValidateRejectsCriticalMutations(t *testing.T) {
	base := completeRecord(t, RecordSession, AttestationIndependent)
	tests := []struct {
		name   string
		mutate func(*Record)
		want   string
	}{
		{"schema", func(r *Record) { r.Schema = "attacker" }, "unknown evidence"},
		{"schema version", func(r *Record) { r.SchemaVersion++ }, "unsupported"},
		{"record id", func(r *Record) { r.RecordID = "session-not-random" }, "record_id"},
		{"record id type", func(r *Record) { r.RecordID = "host-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }, "record_id"},
		{"type", func(r *Record) { r.RecordType = "other" }, "record_id"},
		{"validation run id", func(r *Record) { r.ValidationRunID = "machine-identity" }, "validation_run_id"},
		{"route", func(r *Record) { r.RouteID = "physical-macos-remote" }, "route_id"},
		{"created timestamp", func(r *Record) { r.CreatedAt = "yesterday" }, "created_at"},
		{"expiration order", func(r *Record) { r.ExpiresAt = r.CreatedAt }, "expires_at"},
		{"expiration bound", func(r *Record) { r.ExpiresAt = testNow.Add(31 * 24 * time.Hour).Format(time.RFC3339) }, "expires_at"},
		{"manifest date", func(r *Record) { r.ManifestAsOf = "tomorrow" }, "manifest_as_of"},
		{"tool version", func(r *Record) { r.ToolVersion = " " }, "tool_version"},
		{"subject role", func(r *Record) { r.Subject.Role = RecordClient }, "subject.role"},
		{"subject platform", func(r *Record) { r.Subject.Platform = "windows" }, "platform"},
		{"subject architecture", func(r *Record) { r.Subject.Architecture = "arm64" }, "architecture"},
		{"subject environment", func(r *Record) { r.Subject.Environment = "" }, "environment"},
		{"attestation level", func(r *Record) { r.Attestation.Level = "trusted" }, "attestation"},
		{"reviewer missing", func(r *Record) { r.Attestation.Reviewer = "" }, "reviewer"},
		{"review time missing", func(r *Record) { r.Attestation.ReviewedAt = "" }, "reviewed_at"},
		{"review artifacts missing", func(r *Record) { r.Attestation.Artifacts = nil }, "artifacts"},
		{"review precedes record", func(r *Record) { r.Attestation.ReviewedAt = testNow.Add(-2 * time.Hour).Format(time.RFC3339) }, "cannot precede"},
		{"review at expiration", func(r *Record) { r.Attestation.ReviewedAt = r.ExpiresAt }, "must precede"},
		{"session bindings missing", func(r *Record) { r.Bindings = nil }, "bindings"},
		{"bad binding", func(r *Record) { r.Bindings.HostRecordSHA256 = "ABC" }, "SHA-256"},
		{"methodology missing", func(r *Record) { r.MeasurementMethodology = nil }, "measurement_methodology"},
		{"methodology version", func(r *Record) { r.MeasurementMethodology.Version = "future" }, "version"},
		{"methodology partial", func(r *Record) { r.MeasurementMethodology.CaptureStartedAt = "" }, "unverified measurement_methodology"},
		{"capture order", func(r *Record) { r.MeasurementMethodology.CaptureEndedAt = r.MeasurementMethodology.CaptureStartedAt }, "must follow"},
		{"capture starts before record", func(r *Record) {
			r.MeasurementMethodology.CaptureStartedAt = testNow.Add(-2 * time.Hour).Format(time.RFC3339)
		}, "cannot precede"},
		{"capture ends after review", func(r *Record) {
			r.MeasurementMethodology.CaptureEndedAt = testNow.Add(-4 * time.Minute).Format(time.RFC3339)
			r.MeasurementMethodology.SampleCount = 2160
		}, "after attestation"},
		{"sample count zero", func(r *Record) { r.MeasurementMethodology.SampleCount = 0 }, "sample_count"},
		{"sample count below one hertz", func(r *Record) { r.MeasurementMethodology.SampleCount = 1799 }, "common observations"},
		{"sample count above one kilohertz", func(r *Record) { r.MeasurementMethodology.SampleCount = 1_800_001 }, "common observations"},
		{"sample count absolute maximum", func(r *Record) { r.MeasurementMethodology.SampleCount = MaximumMeasurementSampleCount + 1 }, "sample_count"},
		{"collector id", func(r *Record) { r.MeasurementMethodology.CollectorID = "Fixture Collector" }, "collector_id"},
		{"collector version", func(r *Record) { r.MeasurementMethodology.CollectorVersion = "" }, "collector_version"},
		{"capture artifact hash", func(r *Record) { r.MeasurementMethodology.CaptureArtifactSHA256 = "ABC" }, "capture_artifact_sha256"},
		{"capture artifact unbound", func(r *Record) { r.MeasurementMethodology.CaptureArtifactSHA256 = strings.Repeat("e", 64) }, "session.latency"},
		{"check missing", func(r *Record) { r.Checks = r.Checks[1:] }, "checks"},
		{"check duplicate", func(r *Record) { r.Checks[1].ID = r.Checks[0].ID }, "duplicate"},
		{"check unexpected", func(r *Record) { r.Checks[0].ID = "session.other" }, "unexpected"},
		{"check status", func(r *Record) { r.Checks[0].Status = "maybe" }, "status"},
		{"check method", func(r *Record) { r.Checks[0].Method = "magic" }, "method"},
		{"check summary", func(r *Record) { r.Checks[0].Summary = "" }, "summary"},
		{"check observation", func(r *Record) { r.Checks[0].ObservedAt = "today" }, "observed_at"},
		{"check artifacts missing", func(r *Record) { r.Checks[0].Artifacts = nil }, "artifacts"},
		{"observation precedes record", func(r *Record) { r.Checks[0].ObservedAt = testNow.Add(-2 * time.Hour).Format(time.RFC3339) }, "cannot precede"},
		{"observation at expiration", func(r *Record) { r.Checks[0].ObservedAt = r.ExpiresAt }, "must precede"},
		{"observation after review", func(r *Record) { r.Checks[0].ObservedAt = testNow.Format(time.RFC3339) }, "cannot follow"},
		{"measurement duplicate", func(r *Record) { r.Measurements[1].ID = r.Measurements[0].ID }, "duplicate measurement"},
		{"measurement id", func(r *Record) { r.Measurements[0].ID = "Bad ID" }, "measurement id"},
		{"measurement negative", func(r *Record) { r.Measurements[0].Value = -1 }, "non-negative"},
		{"measurement NaN", func(r *Record) { r.Measurements[0].Value = math.NaN() }, "finite"},
		{"measurement unit", func(r *Record) { r.Measurements[0].Unit = "" }, "unit"},
		{"required session measurement", func(r *Record) { r.Measurements = r.Measurements[1:] }, "requires measurement"},
		{"session measurement unit", func(r *Record) { r.Measurements[0].Unit = "minutes" }, "must use unit"},
		{"dropped frames range", func(r *Record) { setMeasurement(r, "dropped-frames", 101) }, "cannot exceed 100"},
		{"duration does not match capture", func(r *Record) { setMeasurement(r, "session-duration", 1801) }, "does not match capture"},
		{"duration upper bound", func(r *Record) { setMeasurement(r, "session-duration", MaximumSessionDurationSeconds+1) }, "cannot exceed"},
		{"frame rate upper bound", func(r *Record) { setMeasurement(r, "average-frame-rate", MaximumAverageFrameRate+1) }, "cannot exceed"},
		{"stream dimension upper bound", func(r *Record) { r.StreamProfile.Width = MaximumStreamDimension + 1 }, "dimensions"},
		{"stream target upper bound", func(r *Record) { r.StreamProfile.TargetFrameRate = MaximumTargetFrameRate + 1 }, "target_frame_rate"},
		{"global artifact name collision", func(r *Record) { r.Checks[1].Artifacts[0].Name = strings.ToUpper(r.Checks[0].Artifacts[0].Name) }, "globally unique"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := cloneRecord(t, base)
			tt.mutate(&record)
			err := Validate(record)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want substring %q", err, tt.want)
			}
		})
	}

	unverified := cloneRecord(t, base)
	unverified.Checks[0].Status = StatusUnverified
	if err := Validate(unverified); err == nil || !strings.Contains(err.Error(), "must not claim") {
		t.Fatalf("unverified observation err = %v", err)
	}

	nonSession := completeRecord(t, RecordClient, AttestationLab)
	nonSession.Bindings = &Bindings{}
	if err := Validate(nonSession); err == nil || !strings.Contains(err.Error(), "only") {
		t.Fatalf("non-session bindings err = %v", err)
	}

	tooMany := cloneRecord(t, base)
	for len(tooMany.Measurements) <= 64 {
		tooMany.Measurements = append(tooMany.Measurements, Measurement{ID: "metric." + strings.Repeat("a", len(tooMany.Measurements)), Unit: "count"})
	}
	if err := Validate(tooMany); err == nil || !strings.Contains(err.Error(), "more than 64") {
		t.Fatalf("measurement limit err = %v", err)
	}
}

func TestEvaluateAt(t *testing.T) {
	t.Run("manual independent claim cannot auto-promote", func(t *testing.T) {
		evaluation, err := EvaluateAt(completeRecord(t, RecordClient, AttestationIndependent), testNow)
		if err != nil || evaluation.State != StateClaimsComplete || evaluation.PromotionSafe || !strings.Contains(evaluation.Reasons[0], "not authenticated") {
			t.Fatalf("evaluation=%+v err=%v", evaluation, err)
		}
	})

	t.Run("lab record is complete but not promotion safe", func(t *testing.T) {
		evaluation, err := EvaluateAt(completeRecord(t, RecordClient, AttestationLab), testNow)
		if err != nil || evaluation.State != StateClaimsComplete || evaluation.PromotionSafe || !strings.Contains(evaluation.Reasons[0], "not authenticated") {
			t.Fatalf("evaluation=%+v err=%v", evaluation, err)
		}
	})

	tests := []struct {
		name   string
		mutate func(*Record)
		now    time.Time
		state  State
		want   string
	}{
		{"self attested", func(r *Record) { makeSelfAttested(r) }, testNow, StatePending, "self-attested"},
		{"unbound session", func(r *Record) { r.Bindings.HostRecordSHA256 = "" }, testNow, StatePending, "not bound"},
		{"failed check", func(r *Record) { r.Checks[0].Status = StatusFail }, testNow, StatePending, "is fail"},
		{"stale manifest", func(r *Record) { r.ManifestAsOf = "2026-08-25" }, testNow, StatePending, "current embedded"},
		{"manifest content digest mismatch", func(r *Record) { r.ManifestSHA256 = strings.Repeat("a", 64) }, testNow, StatePending, "manifest content"},
		{"future creation", func(r *Record) {
			r.CreatedAt = testNow.Add(time.Hour).Format(time.RFC3339)
			r.ExpiresAt = testNow.Add(2 * time.Hour).Format(time.RFC3339)
			for index := range r.Checks {
				r.Checks[index].ObservedAt = testNow.Add(70 * time.Minute).Format(time.RFC3339)
			}
			r.MeasurementMethodology.CaptureStartedAt = testNow.Add(65 * time.Minute).Format(time.RFC3339)
			r.MeasurementMethodology.CaptureEndedAt = testNow.Add(95 * time.Minute).Format(time.RFC3339)
			r.Attestation.ReviewedAt = testNow.Add(100 * time.Minute).Format(time.RFC3339)
		}, testNow, StatePending, "creation time"},
		{"future review", func(r *Record) { r.Attestation.ReviewedAt = testNow.Add(time.Hour).Format(time.RFC3339) }, testNow, StatePending, "review timestamp"},
		{"future observation", func(r *Record) {
			r.Checks[0].ObservedAt = testNow.Add(30 * time.Minute).Format(time.RFC3339)
			r.Attestation.ReviewedAt = testNow.Add(40 * time.Minute).Format(time.RFC3339)
		}, testNow, StatePending, "observation"},
		{"future failed observation", func(r *Record) {
			r.Checks[0].Status = StatusFail
			r.Checks[0].ObservedAt = testNow.Add(30 * time.Minute).Format(time.RFC3339)
			r.Attestation.ReviewedAt = testNow.Add(40 * time.Minute).Format(time.RFC3339)
		}, testNow, StatePending, "observation"},
		{"future capture", func(r *Record) {
			r.MeasurementMethodology.CaptureStartedAt = testNow.Add(10 * time.Minute).Format(time.RFC3339)
			r.MeasurementMethodology.CaptureEndedAt = testNow.Add(40 * time.Minute).Format(time.RFC3339)
			r.Attestation.ReviewedAt = testNow.Add(50 * time.Minute).Format(time.RFC3339)
		}, testNow, StatePending, "capture"},
		{"zero latency placeholder", func(r *Record) {
			setMeasurement(r, "end-to-end-latency", 0)
		}, testNow, StatePending, "zero placeholder"},
		{"short session", func(r *Record) {
			setMeasurement(r, "session-duration", 1799)
			r.MeasurementMethodology.CaptureEndedAt = testNow.Add(-10*time.Minute - time.Second).Format(time.RFC3339)
		}, testNow, StatePending, "minimum"},
		{"low frame rate", func(r *Record) { setMeasurement(r, "average-frame-rate", 54) }, testNow, StatePending, "minimum"},
		{"slow encode", func(r *Record) { setMeasurement(r, "encode-latency", 31) }, testNow, StatePending, "maximum"},
		{"slow network", func(r *Record) { setMeasurement(r, "network-latency", 81) }, testNow, StatePending, "maximum"},
		{"slow decode", func(r *Record) { setMeasurement(r, "decode-latency", 31) }, testNow, StatePending, "maximum"},
		{"slow end to end", func(r *Record) { setMeasurement(r, "end-to-end-latency", 151) }, testNow, StatePending, "maximum"},
		{"dropped frames acceptance", func(r *Record) { setMeasurement(r, "dropped-frames", 1.1) }, testNow, StatePending, "maximum"},
		{"expired", func(r *Record) {}, testNow.Add(7 * 24 * time.Hour), StateExpired, "expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := completeRecord(t, RecordSession, AttestationIndependent)
			tt.mutate(&record)
			evaluation, err := EvaluateAt(record, tt.now)
			if err != nil || evaluation.State != tt.state || evaluation.PromotionSafe || !strings.Contains(strings.Join(evaluation.Reasons, " "), tt.want) {
				t.Fatalf("evaluation=%+v err=%v", evaluation, err)
			}
		})
	}

	if _, err := EvaluateAt(completeRecord(t, RecordHost, AttestationLab), time.Time{}); err == nil {
		t.Fatal("zero evaluation time was accepted")
	}

	t.Run("embedded compatibility evidence becomes stale", func(t *testing.T) {
		record := completeRecord(t, RecordClient, AttestationIndependent)
		created := time.Date(2026, time.September, 24, 8, 0, 0, 0, time.UTC)
		record.CreatedAt = created.Format(time.RFC3339)
		record.ExpiresAt = created.Add(7 * 24 * time.Hour).Format(time.RFC3339)
		for index := range record.Checks {
			record.Checks[index].ObservedAt = created.Add(time.Minute).Format(time.RFC3339)
		}
		record.Attestation.ReviewedAt = created.Add(2 * time.Minute).Format(time.RFC3339)
		evaluation, err := EvaluateAt(record, time.Date(2026, time.September, 26, 12, 0, 0, 0, time.UTC))
		if err != nil || evaluation.State != StatePending || !strings.Contains(strings.Join(evaluation.Reasons, " "), "embedded compatibility evidence is stale") {
			t.Fatalf("evaluation=%+v err=%v", evaluation, err)
		}
	})
}

func TestEvaluateSetAt(t *testing.T) {
	makeSet := func(t *testing.T, level AttestationLevel) (Record, Record, Record, string, string) {
		t.Helper()
		host := completeRecord(t, RecordHost, level)
		client := completeRecord(t, RecordClient, level)
		client.ValidationRunID = host.ValidationRunID
		hostDigest := recordDigest(t, host)
		clientDigest := recordDigest(t, client)
		session := completeRecord(t, RecordSession, level)
		session.ValidationRunID = host.ValidationRunID
		session.Bindings.HostRecordSHA256 = hostDigest
		session.Bindings.ClientRecordSHA256 = clientDigest
		return host, client, session, hostDigest, clientDigest
	}

	t.Run("independent claims remain non-promotable without authentication", func(t *testing.T) {
		host, client, session, hostDigest, clientDigest := makeSet(t, AttestationIndependent)
		evaluation, err := EvaluateSetAt(host, client, session, hostDigest, clientDigest, testNow)
		if err != nil || evaluation.State != StateClaimsComplete || evaluation.PromotionSafe || !strings.Contains(evaluation.Reasons[0], "unauthenticated") {
			t.Fatalf("evaluation=%+v err=%v", evaluation, err)
		}
		if evaluation.Session.PromotionSafe {
			t.Fatal("standalone session evaluation unexpectedly claimed verified linkage")
		}
	})

	t.Run("lab set completes without promotion", func(t *testing.T) {
		host, client, session, hostDigest, clientDigest := makeSet(t, AttestationLab)
		evaluation, err := EvaluateSetAt(host, client, session, hostDigest, clientDigest, testNow)
		if err != nil || evaluation.State != StateClaimsComplete || evaluation.PromotionSafe || !strings.Contains(evaluation.Reasons[0], "unauthenticated") {
			t.Fatalf("evaluation=%+v err=%v", evaluation, err)
		}
	})

	t.Run("verified artifacts complete but cannot promote", func(t *testing.T) {
		host, client, session, _, _ := makeSet(t, AttestationIndependent)
		hostDirectory := materializeArtifactBundle(t, &host)
		clientDirectory := materializeArtifactBundle(t, &client)
		hostDigest := recordDigest(t, host)
		clientDigest := recordDigest(t, client)
		session.Bindings.HostRecordSHA256 = hostDigest
		session.Bindings.ClientRecordSHA256 = clientDigest
		sessionDirectory := materializeArtifactBundle(t, &session)
		hostVerification, err := VerifyArtifactBundle(host, hostDirectory)
		if err != nil {
			t.Fatal(err)
		}
		clientVerification, err := VerifyArtifactBundle(client, clientDirectory)
		if err != nil {
			t.Fatal(err)
		}
		sessionVerification, err := VerifyArtifactBundle(session, sessionDirectory)
		if err != nil {
			t.Fatal(err)
		}
		evaluation, err := EvaluateVerifiedSetAt(host, client, session, hostDigest, clientDigest, ArtifactVerificationSet{
			Host: hostVerification, Client: clientVerification, Session: sessionVerification,
		}, testNow)
		if err != nil || evaluation.State != StateComplete || evaluation.PromotionSafe || !strings.Contains(evaluation.Reasons[0], "every declared artifact") {
			t.Fatalf("evaluation=%+v err=%v", evaluation, err)
		}
	})

	tests := []struct {
		name   string
		mutate func(*Record, *Record, *Record, *string, *string)
		state  State
		want   string
	}{
		{"host binding mismatch", func(_, _, _ *Record, hostDigest, _ *string) { *hostDigest = strings.Repeat("c", 64) }, StatePending, "host binding"},
		{"client binding mismatch", func(_, _, _ *Record, _, clientDigest *string) { *clientDigest = strings.Repeat("d", 64) }, StatePending, "client binding"},
		{"client subject mismatch", func(_, _ *Record, session *Record, _, _ *string) { session.Subject.Platform = "freebsd" }, StatePending, "subject does not match"},
		{"validation run mismatch", func(_, _ *Record, session *Record, _, _ *string) {
			session.ValidationRunID = "run-ffffffffffffffffffffffffffffffff"
		}, StatePending, "validation_run_id"},
		{"host review after capture start", func(host, _, _ *Record, _, _ *string) {
			host.Attestation.ReviewedAt = testNow.Add(-39 * time.Minute).Format(time.RFC3339)
		}, StatePending, "host review"},
		{"client review after capture start", func(_, client, _ *Record, _, _ *string) {
			client.Attestation.ReviewedAt = testNow.Add(-39 * time.Minute).Format(time.RFC3339)
		}, StatePending, "client review"},
		{"session outlives host", func(host, _, _ *Record, _, _ *string) {
			host.ExpiresAt = testNow.Add(24 * time.Hour).Format(time.RFC3339)
		}, StatePending, "expires after the bound host"},
		{"pending client", func(_, client, _ *Record, _, _ *string) { makeSelfAttested(client) }, StatePending, "client: self-attested"},
		{"expired host", func(host, _, _ *Record, _, _ *string) { host.ExpiresAt = testNow.Format(time.RFC3339) }, StateExpired, "host: evidence record has expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, client, session, hostDigest, clientDigest := makeSet(t, AttestationIndependent)
			tt.mutate(&host, &client, &session, &hostDigest, &clientDigest)
			evaluation, err := EvaluateSetAt(host, client, session, hostDigest, clientDigest, testNow)
			if err != nil || evaluation.State != tt.state || evaluation.PromotionSafe || !strings.Contains(strings.Join(evaluation.Reasons, " "), tt.want) {
				t.Fatalf("evaluation=%+v err=%v", evaluation, err)
			}
		})
	}

	host, client, session, hostDigest, clientDigest := makeSet(t, AttestationIndependent)
	if _, err := EvaluateSetAt(client, client, session, hostDigest, clientDigest, testNow); err == nil || !strings.Contains(err.Error(), "host record") {
		t.Fatalf("wrong type err=%v", err)
	}
	if _, err := EvaluateSetAt(host, client, session, "bad", clientDigest, testNow); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("bad digest err=%v", err)
	}
}

func TestReadFile(t *testing.T) {
	record := completeRecord(t, RecordClient, AttestationLab)
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	regular := filepath.Join(directory, "record.json")
	if err := os.WriteFile(regular, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(regular); err != nil {
		t.Fatalf("regular file: %v", err)
	}
	if _, err := ReadFile(directory); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory err = %v", err)
	}
	link := filepath.Join(directory, "record-link.json")
	if err := os.Symlink(regular, link); err == nil {
		if _, err := ReadFile(link); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("symlink err = %v", err)
		}
	}
	oversize := filepath.Join(directory, "oversize.json")
	if err := os.WriteFile(oversize, make([]byte, MaxRecordSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(oversize); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize err = %v", err)
	}
}

func completeRecord(t *testing.T, recordType RecordType, level AttestationLevel) Record {
	t.Helper()
	platform := "linux"
	if recordType == RecordHost {
		platform = "windows"
	}
	record, err := NewTemplate(recordType, platform, "amd64", "test", testNow.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	record.Subject.Environment = "redacted test fixture"
	reviewedAt := testNow.Add(-50 * time.Minute)
	observedAt := testNow.Add(-52 * time.Minute)
	if recordType == RecordSession {
		reviewedAt = testNow.Add(-5 * time.Minute)
		observedAt = testNow.Add(-10 * time.Minute)
	}
	record.Attestation = Attestation{
		Level:      level,
		Reviewer:   "fixture-reviewer",
		ReviewedAt: reviewedAt.Format(time.RFC3339),
		Artifacts:  []Artifact{fixtureArtifact("review-bundle.json", "c")},
		Notes:      "Fixture only.",
	}
	for index := range record.Checks {
		record.Checks[index].Status = StatusPass
		record.Checks[index].ObservedAt = observedAt.Format(time.RFC3339)
		record.Checks[index].Summary = "Observed fixture result for " + record.Checks[index].ID + "."
		record.Checks[index].Artifacts = []Artifact{fixtureArtifact(record.Checks[index].ID+".json", "d")}
	}
	if record.Bindings != nil {
		record.Bindings.HostRecordSHA256 = strings.Repeat("a", 64)
		record.Bindings.ClientRecordSHA256 = strings.Repeat("b", 64)
	}
	if record.StreamProfile != nil {
		*record.StreamProfile = StreamProfile{Width: 1920, Height: 1080, TargetFrameRate: 60, Codec: "h264", Transport: "wired-lan"}
	}
	if record.MeasurementMethodology != nil {
		*record.MeasurementMethodology = MeasurementMethodology{
			Version:               SessionMetricsV1,
			CaptureStartedAt:      testNow.Add(-40 * time.Minute).Format(time.RFC3339),
			CaptureEndedAt:        testNow.Add(-10 * time.Minute).Format(time.RFC3339),
			SampleCount:           1800,
			CollectorID:           "fixture-collector",
			CollectorVersion:      "1.0.0",
			CaptureArtifactSHA256: strings.Repeat("d", 64),
		}
	}
	setMeasurement(&record, "session-duration", 1800)
	setMeasurement(&record, "average-frame-rate", 60)
	setMeasurement(&record, "encode-latency", 10)
	setMeasurement(&record, "network-latency", 20)
	setMeasurement(&record, "decode-latency", 10)
	setMeasurement(&record, "end-to-end-latency", 50)
	setMeasurement(&record, "dropped-frames", 0.2)
	if err := Validate(record); err != nil {
		t.Fatalf("complete fixture is invalid: %v", err)
	}
	return record
}

func cloneRecord(t *testing.T, record Record) Record {
	t.Helper()
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var clone Record
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func makeSelfAttested(record *Record) {
	record.Attestation.Level = AttestationSelf
	record.Attestation.Reviewer = ""
	record.Attestation.ReviewedAt = ""
	record.Attestation.Artifacts = []Artifact{}
}

func setMeasurement(record *Record, id string, value float64) {
	for index := range record.Measurements {
		if record.Measurements[index].ID == id {
			record.Measurements[index].Value = value
			return
		}
	}
}

func fixtureArtifact(name, hexDigit string) Artifact {
	return Artifact{Name: name, SHA256: strings.Repeat(hexDigit, 64), SizeBytes: 128, MediaType: "application/json"}
}

func recordDigest(t *testing.T, record Record) string {
	t.Helper()
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest)
}

func mutateJSONRecord(t *testing.T, data []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	mutated, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return mutated
}
