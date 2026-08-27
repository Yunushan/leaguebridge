package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/evidence"
)

func TestEvidenceTemplateCommand(t *testing.T) {
	t.Run("client template", func(t *testing.T) {
		a, out, errOut, _, _ := newTestApp(t)
		code := a.Run(context.Background(), []string{"evidence", "template", "--type", "client"})
		if code != ExitOK || errOut.Len() != 0 {
			t.Fatalf("code=%d stderr=%q", code, errOut.String())
		}
		record, err := evidence.Parse(out.Bytes())
		if err != nil {
			t.Fatalf("parse template: %v\n%s", err, out.String())
		}
		if record.RecordType != evidence.RecordClient || record.Subject.Platform != "linux" || record.Subject.Architecture != "amd64" || !strings.HasPrefix(record.ValidationRunID, "run-") {
			t.Fatalf("record = %+v", record)
		}
		evaluation, err := evidence.EvaluateAt(record, fixedNow)
		if err != nil || evaluation.State != evidence.StatePending || evaluation.PromotionSafe {
			t.Fatalf("evaluation=%+v err=%v", evaluation, err)
		}
	})

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing subcommand", []string{"evidence"}, "expected template, validate, verify-set, or v2"},
		{"unknown subcommand", []string{"evidence", "other"}, "unknown subcommand"},
		{"missing type", []string{"evidence", "template"}, "--type is required"},
		{"invalid type", []string{"evidence", "template", "--type", "other"}, "unsupported evidence type"},
		{"invalid target", []string{"evidence", "template", "--type", "host", "--platform", "linux"}, "host evidence platform"},
		{"unimplemented macOS route", []string{"evidence", "template", "--type", "host", "--platform", "darwin", "--arch", "arm64"}, "platform must be windows"},
		{"invalid run id", []string{"evidence", "template", "--type", "client", "--run-id", "host-name"}, "validation run id"},
		{"unexpected argument", []string{"evidence", "template", "--type", "client", "extra"}, "unexpected arguments"},
	}

	t.Run("shared run id", func(t *testing.T) {
		const runID = "run-0123456789abcdef0123456789abcdef"
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"evidence", "template", "--type", "client", "--run-id", runID}); code != ExitOK {
			t.Fatalf("code=%d output=%q", code, out.String())
		}
		record, err := evidence.Parse(out.Bytes())
		if err != nil || record.ValidationRunID != runID {
			t.Fatalf("record=%+v err=%v", record, err)
		}
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _, errOut, _, _ := newTestApp(t)
			if code := a.Run(context.Background(), tt.args); code != ExitUsage {
				t.Fatalf("code=%d stderr=%q", code, errOut.String())
			}
			if !strings.Contains(errOut.String(), tt.want) {
				t.Fatalf("stderr=%q, want %q", errOut.String(), tt.want)
			}
		})
	}

	t.Run("zero time", func(t *testing.T) {
		a, _, errOut, _, _ := newTestApp(t)
		a.Now = func() time.Time { return time.Time{} }
		if code := a.Run(context.Background(), []string{"evidence", "template", "--type", "client"}); code != ExitUsage || !strings.Contains(errOut.String(), "time is required") {
			t.Fatalf("code=%d stderr=%q", code, errOut.String())
		}
	})

	t.Run("write failure", func(t *testing.T) {
		a, _, errOut, _, _ := newTestApp(t)
		a.Stdout = failingWriter{errors.New("closed")}
		if code := a.Run(context.Background(), []string{"evidence", "template", "--type", "client"}); code != ExitInternal || !strings.Contains(errOut.String(), "write template") {
			t.Fatalf("code=%d stderr=%q", code, errOut.String())
		}
	})
}

func TestEvidenceValidateCommand(t *testing.T) {
	t.Run("pending template returns blocked with digest", func(t *testing.T) {
		record, err := evidence.NewTemplate(evidence.RecordClient, "linux", "amd64", "test", fixedNow)
		if err != nil {
			t.Fatal(err)
		}
		path, data := writeEvidenceRecord(t, record)
		a, out, errOut, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"evidence", "validate", "--file", path}); code != ExitBlocked {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		wantDigest := fmt.Sprintf("%x", sha256.Sum256(data))
		if !strings.Contains(out.String(), "state=pending") || !strings.Contains(out.String(), wantDigest) || !strings.Contains(out.String(), "self-attested") {
			t.Fatalf("stdout=%q", out.String())
		}
	})

	t.Run("manual independent completion remains blocked", func(t *testing.T) {
		path, _ := writeEvidenceRecord(t, completeAppEvidence(t, evidence.AttestationIndependent))
		a, out, errOut, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"evidence", "validate", "--file", path, "--json"}); code != ExitBlocked {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		if !envelope.OK || envelope.Command != "evidence validate" {
			t.Fatalf("envelope=%+v", envelope)
		}
		data := envelope.Data.(map[string]any)
		evaluation := data["evaluation"].(map[string]any)
		if evaluation["state"] != "claims-complete" || evaluation["promotion_safe"] != false || data["artifacts_verified"] != false || len(data["record_sha256"].(string)) != 64 {
			t.Fatalf("data=%+v", data)
		}
	})

	t.Run("lab completion is valid but not promotion safe", func(t *testing.T) {
		path, _ := writeEvidenceRecord(t, completeAppEvidence(t, evidence.AttestationLab))
		a, out, _, _, _ := newTestApp(t)
		if code := a.Run(context.Background(), []string{"evidence", "validate", "--file", path}); code != ExitBlocked {
			t.Fatalf("code=%d output=%q", code, out.String())
		}
		if !strings.Contains(out.String(), "state=claims-complete") || !strings.Contains(out.String(), "artifacts_verified=false") || !strings.Contains(out.String(), "promotion_safe=false") || !strings.Contains(out.String(), "not authenticated") {
			t.Fatalf("output=%q", out.String())
		}
	})

	t.Run("verified artifact bundle completes but remains blocked", func(t *testing.T) {
		record := completeAppEvidence(t, evidence.AttestationIndependent)
		artifactDirectory := materializeAppArtifactBundle(t, &record)
		path, _ := writeEvidenceRecord(t, record)
		a, out, errOut, _, _ := newTestApp(t)
		code := a.Run(context.Background(), []string{"evidence", "validate", "--file", path, "--artifacts", artifactDirectory, "--json"})
		if code != ExitBlocked || errOut.Len() != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		data := decodeEnvelope(t, out.Bytes()).Data.(map[string]any)
		evaluation := data["evaluation"].(map[string]any)
		if evaluation["state"] != "complete" || evaluation["promotion_safe"] != false || data["artifacts_verified"] != true {
			t.Fatalf("data=%+v", data)
		}
	})

	t.Run("artifact bundle mismatch is blocked", func(t *testing.T) {
		record := completeAppEvidence(t, evidence.AttestationLab)
		artifactDirectory := materializeAppArtifactBundle(t, &record)
		if err := os.WriteFile(filepath.Join(artifactDirectory, "unexpected.txt"), []byte("unexpected"), 0o600); err != nil {
			t.Fatal(err)
		}
		path, _ := writeEvidenceRecord(t, record)
		a, out, _, _, _ := newTestApp(t)
		code := a.Run(context.Background(), []string{"evidence", "validate", "--file", path, "--artifacts", artifactDirectory, "--json"})
		if code != ExitBlocked || !strings.Contains(decodeEnvelope(t, out.Bytes()).Error, "unexpected") {
			t.Fatalf("code=%d output=%q", code, out.String())
		}
	})

	t.Run("evaluation failure", func(t *testing.T) {
		path, _ := writeEvidenceRecord(t, completeAppEvidence(t, evidence.AttestationLab))
		a, out, _, _, _ := newTestApp(t)
		a.Now = func() time.Time { return time.Time{} }
		if code := a.Run(context.Background(), []string{"evidence", "validate", "--file", path, "--json"}); code != ExitBlocked {
			t.Fatalf("code=%d output=%q", code, out.String())
		}
		if envelope := decodeEnvelope(t, out.Bytes()); envelope.OK || !strings.Contains(envelope.Error, "cannot be evaluated") {
			t.Fatalf("envelope=%+v", envelope)
		}
	})

	directory := t.TempDir()
	invalid := filepath.Join(directory, "invalid.json")
	writeFile(t, invalid, []byte(`{"not":"evidence"}`))
	tests := []struct {
		name     string
		args     []string
		wantCode int
		want     string
		json     bool
	}{
		{"missing file flag", []string{"evidence", "validate"}, ExitUsage, "--file is required", false},
		{"missing file", []string{"evidence", "validate", "--file", filepath.Join(directory, "missing")}, ExitUsage, "read evidence", false},
		{"invalid evidence", []string{"evidence", "validate", "--file", invalid}, ExitBlocked, "evidence is invalid", false},
		{"invalid evidence JSON response", []string{"evidence", "validate", "--file", invalid, "--json"}, ExitBlocked, "evidence is invalid", true},
		{"unexpected argument", []string{"evidence", "validate", "extra"}, ExitUsage, "unexpected arguments", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, out, errOut, _, _ := newTestApp(t)
			if code := a.Run(context.Background(), tt.args); code != tt.wantCode {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			got := errOut.String()
			if tt.json {
				got = decodeEnvelope(t, out.Bytes()).Error
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("output=%q, want %q", got, tt.want)
			}
		})
	}

	t.Run("JSON write failure", func(t *testing.T) {
		path, _ := writeEvidenceRecord(t, completeAppEvidence(t, evidence.AttestationIndependent))
		a, _, errOut, _, _ := newTestApp(t)
		a.Stdout = failingWriter{errors.New("closed")}
		if code := a.Run(context.Background(), []string{"evidence", "validate", "--file", path, "--json"}); code != ExitInternal || !strings.Contains(errOut.String(), "encode output") {
			t.Fatalf("code=%d stderr=%q", code, errOut.String())
		}
	})
}

func TestEvidenceVerifySetCommand(t *testing.T) {
	t.Run("independent claims remain blocked without authentication", func(t *testing.T) {
		hostPath, clientPath, sessionPath := writeAppEvidenceSet(t, evidence.AttestationIndependent)
		a, out, errOut, _, _ := newTestApp(t)
		code := a.Run(context.Background(), []string{"evidence", "verify-set", "--host", hostPath, "--client", clientPath, "--session", sessionPath, "--json"})
		if code != ExitBlocked || errOut.Len() != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		envelope := decodeEnvelope(t, out.Bytes())
		data := envelope.Data.(map[string]any)
		evaluation := data["evaluation"].(map[string]any)
		if envelope.Command != "evidence verify-set" || evaluation["state"] != "claims-complete" || evaluation["promotion_safe"] != false || data["artifacts_verified"] != false {
			t.Fatalf("envelope=%+v", envelope)
		}
		for _, key := range []string{"host_record_sha256", "client_record_sha256", "session_record_sha256"} {
			if len(data[key].(string)) != 64 {
				t.Fatalf("%s=%v", key, data[key])
			}
		}
	})

	t.Run("lab set", func(t *testing.T) {
		hostPath, clientPath, sessionPath := writeAppEvidenceSet(t, evidence.AttestationLab)
		a, out, _, _, _ := newTestApp(t)
		code := a.Run(context.Background(), []string{"evidence", "verify-set", "--host", hostPath, "--client", clientPath, "--session", sessionPath})
		if code != ExitBlocked || !strings.Contains(out.String(), "state=claims-complete") || !strings.Contains(out.String(), "artifacts_verified=false") || !strings.Contains(out.String(), "promotion_safe=false") {
			t.Fatalf("code=%d output=%q", code, out.String())
		}
	})

	t.Run("verified artifact set completes but remains blocked", func(t *testing.T) {
		hostPath, clientPath, sessionPath, hostArtifacts, clientArtifacts, sessionArtifacts := writeVerifiedAppEvidenceSet(t, evidence.AttestationIndependent)
		a, out, errOut, _, _ := newTestApp(t)
		code := a.Run(context.Background(), []string{
			"evidence", "verify-set", "--host", hostPath, "--client", clientPath, "--session", sessionPath,
			"--host-artifacts", hostArtifacts, "--client-artifacts", clientArtifacts, "--session-artifacts", sessionArtifacts, "--json",
		})
		if code != ExitBlocked || errOut.Len() != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		data := decodeEnvelope(t, out.Bytes()).Data.(map[string]any)
		evaluation := data["evaluation"].(map[string]any)
		if evaluation["state"] != "complete" || evaluation["promotion_safe"] != false || data["artifacts_verified"] != true {
			t.Fatalf("data=%+v", data)
		}
	})

	t.Run("partial artifact directories are usage error", func(t *testing.T) {
		hostPath, clientPath, sessionPath := writeAppEvidenceSet(t, evidence.AttestationLab)
		a, _, errOut, _, _ := newTestApp(t)
		code := a.Run(context.Background(), []string{"evidence", "verify-set", "--host", hostPath, "--client", clientPath, "--session", sessionPath, "--host-artifacts", t.TempDir()})
		if code != ExitUsage || !strings.Contains(errOut.String(), "must be supplied together") {
			t.Fatalf("code=%d stderr=%q", code, errOut.String())
		}
	})

	t.Run("binding mismatch", func(t *testing.T) {
		hostPath, clientPath, sessionPath := writeAppEvidenceSet(t, evidence.AttestationIndependent)
		host := completeAppEvidenceOf(t, evidence.RecordHost, evidence.AttestationIndependent)
		writeEvidenceAtPath(t, hostPath, host)
		a, out, _, _, _ := newTestApp(t)
		code := a.Run(context.Background(), []string{"evidence", "verify-set", "--host", hostPath, "--client", clientPath, "--session", sessionPath})
		if code != ExitBlocked || !strings.Contains(out.String(), "host binding does not match") {
			t.Fatalf("code=%d output=%q", code, out.String())
		}
	})

	directory := t.TempDir()
	invalid := filepath.Join(directory, "invalid.json")
	writeFile(t, invalid, []byte(`{}`))
	_, clientPath, sessionPath := writeAppEvidenceSet(t, evidence.AttestationIndependent)
	tests := []struct {
		name     string
		args     []string
		wantCode int
		want     string
		json     bool
	}{
		{"missing host flag", []string{"evidence", "verify-set"}, ExitUsage, "--host is required", false},
		{"missing client flag", []string{"evidence", "verify-set", "--host", invalid}, ExitUsage, "--client is required", false},
		{"missing session flag", []string{"evidence", "verify-set", "--host", invalid, "--client", clientPath}, ExitUsage, "--session is required", false},
		{"missing host file", []string{"evidence", "verify-set", "--host", filepath.Join(directory, "missing"), "--client", clientPath, "--session", sessionPath}, ExitUsage, "read host evidence", false},
		{"invalid host", []string{"evidence", "verify-set", "--host", invalid, "--client", clientPath, "--session", sessionPath}, ExitBlocked, "host evidence is invalid", false},
		{"invalid host JSON", []string{"evidence", "verify-set", "--host", invalid, "--client", clientPath, "--session", sessionPath, "--json"}, ExitBlocked, "host evidence is invalid", true},
		{"unexpected argument", []string{"evidence", "verify-set", "extra"}, ExitUsage, "unexpected arguments", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, out, errOut, _, _ := newTestApp(t)
			code := a.Run(context.Background(), tt.args)
			if code != tt.wantCode {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			got := errOut.String()
			if tt.json {
				got = decodeEnvelope(t, out.Bytes()).Error
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("output=%q, want %q", got, tt.want)
			}
		})
	}

	t.Run("evaluation error", func(t *testing.T) {
		hostPath, clientPath, sessionPath := writeAppEvidenceSet(t, evidence.AttestationIndependent)
		a, out, _, _, _ := newTestApp(t)
		a.Now = func() time.Time { return time.Time{} }
		code := a.Run(context.Background(), []string{"evidence", "verify-set", "--host", hostPath, "--client", clientPath, "--session", sessionPath, "--json"})
		if code != ExitBlocked || !strings.Contains(decodeEnvelope(t, out.Bytes()).Error, "cannot be evaluated") {
			t.Fatalf("code=%d output=%q", code, out.String())
		}
	})

	t.Run("JSON write failure", func(t *testing.T) {
		hostPath, clientPath, sessionPath := writeAppEvidenceSet(t, evidence.AttestationIndependent)
		a, _, errOut, _, _ := newTestApp(t)
		a.Stdout = failingWriter{errors.New("closed")}
		code := a.Run(context.Background(), []string{"evidence", "verify-set", "--host", hostPath, "--client", clientPath, "--session", sessionPath, "--json"})
		if code != ExitInternal || !strings.Contains(errOut.String(), "encode output") {
			t.Fatalf("code=%d stderr=%q", code, errOut.String())
		}
	})
}

func completeAppEvidence(t *testing.T, level evidence.AttestationLevel) evidence.Record {
	t.Helper()
	return completeAppEvidenceOf(t, evidence.RecordClient, level)
}

func completeAppEvidenceOf(t *testing.T, recordType evidence.RecordType, level evidence.AttestationLevel) evidence.Record {
	t.Helper()
	platform := "linux"
	if recordType == evidence.RecordHost {
		platform = "windows"
	}
	record, err := evidence.NewTemplate(recordType, platform, "amd64", "test", fixedNow.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	record.Subject.Environment = "redacted test fixture"
	reviewedAt := fixedNow.Add(-50 * time.Minute)
	observedAt := fixedNow.Add(-52 * time.Minute)
	if recordType == evidence.RecordSession {
		reviewedAt = fixedNow.Add(-5 * time.Minute)
		observedAt = fixedNow.Add(-10 * time.Minute)
	}
	record.Attestation = evidence.Attestation{
		Level:      level,
		Reviewer:   "fixture-reviewer",
		ReviewedAt: reviewedAt.Format(time.RFC3339),
		Artifacts:  []evidence.Artifact{appFixtureArtifact("review-bundle.json", "c")},
		Notes:      "Fixture only.",
	}
	for index := range record.Checks {
		record.Checks[index].Status = evidence.StatusPass
		record.Checks[index].ObservedAt = observedAt.Format(time.RFC3339)
		record.Checks[index].Summary = "Observed " + record.Checks[index].ID
		record.Checks[index].Artifacts = []evidence.Artifact{appFixtureArtifact(record.Checks[index].ID+".json", "d")}
	}
	if record.Bindings != nil {
		record.Bindings.HostRecordSHA256 = strings.Repeat("a", 64)
		record.Bindings.ClientRecordSHA256 = strings.Repeat("b", 64)
	}
	if record.StreamProfile != nil {
		*record.StreamProfile = evidence.StreamProfile{Width: 1920, Height: 1080, TargetFrameRate: 60, Codec: "h264", Transport: "wired-lan"}
	}
	if record.MeasurementMethodology != nil {
		*record.MeasurementMethodology = evidence.MeasurementMethodology{
			Version:               evidence.SessionMetricsV1,
			CaptureStartedAt:      fixedNow.Add(-40 * time.Minute).Format(time.RFC3339),
			CaptureEndedAt:        fixedNow.Add(-10 * time.Minute).Format(time.RFC3339),
			SampleCount:           1800,
			CollectorID:           "fixture-collector",
			CollectorVersion:      "1.0.0",
			CaptureArtifactSHA256: strings.Repeat("d", 64),
		}
	}
	setAppMeasurement(&record, "session-duration", 1800)
	setAppMeasurement(&record, "average-frame-rate", 60)
	setAppMeasurement(&record, "encode-latency", 10)
	setAppMeasurement(&record, "network-latency", 20)
	setAppMeasurement(&record, "decode-latency", 10)
	setAppMeasurement(&record, "end-to-end-latency", 50)
	setAppMeasurement(&record, "dropped-frames", 0.2)
	if err := evidence.Validate(record); err != nil {
		t.Fatal(err)
	}
	return record
}

func setAppMeasurement(record *evidence.Record, id string, value float64) {
	for index := range record.Measurements {
		if record.Measurements[index].ID == id {
			record.Measurements[index].Value = value
			return
		}
	}
}

func appFixtureArtifact(name, hexDigit string) evidence.Artifact {
	return evidence.Artifact{Name: name, SHA256: strings.Repeat(hexDigit, 64), SizeBytes: 128, MediaType: "application/json"}
}

func writeAppEvidenceSet(t *testing.T, level evidence.AttestationLevel) (string, string, string) {
	t.Helper()
	host := completeAppEvidenceOf(t, evidence.RecordHost, level)
	client := completeAppEvidenceOf(t, evidence.RecordClient, level)
	client.ValidationRunID = host.ValidationRunID
	hostPath, hostData := writeEvidenceRecord(t, host)
	clientPath, clientData := writeEvidenceRecord(t, client)
	session := completeAppEvidenceOf(t, evidence.RecordSession, level)
	session.ValidationRunID = host.ValidationRunID
	session.Bindings.HostRecordSHA256 = fmt.Sprintf("%x", sha256.Sum256(hostData))
	session.Bindings.ClientRecordSHA256 = fmt.Sprintf("%x", sha256.Sum256(clientData))
	sessionPath, _ := writeEvidenceRecord(t, session)
	return hostPath, clientPath, sessionPath
}

func writeVerifiedAppEvidenceSet(t *testing.T, level evidence.AttestationLevel) (string, string, string, string, string, string) {
	t.Helper()
	host := completeAppEvidenceOf(t, evidence.RecordHost, level)
	client := completeAppEvidenceOf(t, evidence.RecordClient, level)
	client.ValidationRunID = host.ValidationRunID
	session := completeAppEvidenceOf(t, evidence.RecordSession, level)
	session.ValidationRunID = host.ValidationRunID

	hostArtifacts := materializeAppArtifactBundle(t, &host)
	clientArtifacts := materializeAppArtifactBundle(t, &client)
	hostPath, hostData := writeEvidenceRecord(t, host)
	clientPath, clientData := writeEvidenceRecord(t, client)
	session.Bindings.HostRecordSHA256 = fmt.Sprintf("%x", sha256.Sum256(hostData))
	session.Bindings.ClientRecordSHA256 = fmt.Sprintf("%x", sha256.Sum256(clientData))
	sessionArtifacts := materializeAppArtifactBundle(t, &session)
	sessionPath, _ := writeEvidenceRecord(t, session)
	return hostPath, clientPath, sessionPath, hostArtifacts, clientArtifacts, sessionArtifacts
}

func materializeAppArtifactBundle(t *testing.T, record *evidence.Record) string {
	t.Helper()
	directory := t.TempDir()
	write := func(artifact *evidence.Artifact) {
		data := []byte("fixture artifact " + artifact.Name + "\n")
		digest := sha256.Sum256(data)
		artifact.SHA256 = fmt.Sprintf("%x", digest)
		artifact.SizeBytes = int64(len(data))
		if err := os.WriteFile(filepath.Join(directory, artifact.Name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for index := range record.Attestation.Artifacts {
		write(&record.Attestation.Artifacts[index])
	}
	for checkIndex := range record.Checks {
		for artifactIndex := range record.Checks[checkIndex].Artifacts {
			write(&record.Checks[checkIndex].Artifacts[artifactIndex])
		}
	}
	if record.MeasurementMethodology != nil && record.MeasurementMethodology.CaptureStartedAt != "" {
		for _, check := range record.Checks {
			if check.ID == "session.latency" {
				record.MeasurementMethodology.CaptureArtifactSHA256 = check.Artifacts[0].SHA256
			}
		}
	}
	if err := evidence.Validate(*record); err != nil {
		t.Fatalf("materialized app fixture is invalid: %v", err)
	}
	return directory
}

func writeEvidenceAtPath(t *testing.T, path string, record evidence.Record) {
	t.Helper()
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, append(data, '\n'))
}

func writeEvidenceRecord(t *testing.T, record evidence.Record) (string, []byte) {
	t.Helper()
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := filepath.Join(t.TempDir(), "evidence.json")
	writeFile(t, path, data)
	return path, data
}
