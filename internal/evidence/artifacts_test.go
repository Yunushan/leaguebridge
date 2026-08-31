package evidence

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyArtifactBundleAndVerifiedEvaluation(t *testing.T) {
	record := completeRecord(t, RecordClient, AttestationIndependent)
	directory := materializeArtifactBundle(t, &record)

	claims, err := EvaluateAt(record, testNow)
	if err != nil || claims.State != StateClaimsComplete || claims.PromotionSafe {
		t.Fatalf("claims evaluation=%+v err=%v", claims, err)
	}
	verification, err := VerifyArtifactBundle(record, directory)
	if err != nil || !verification.Verified() {
		t.Fatalf("verification=%+v err=%v", verification, err)
	}
	verified, err := EvaluateVerifiedAt(record, verification, testNow)
	if err != nil || verified.State != StateComplete || verified.PromotionSafe {
		t.Fatalf("verified evaluation=%+v err=%v", verified, err)
	}

	mutated := cloneRecord(t, record)
	mutated.Subject.Environment += " changed"
	if _, err := EvaluateVerifiedAt(mutated, verification, testNow); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("stale verification err=%v", err)
	}
	if _, err := EvaluateVerifiedAt(record, ArtifactVerification{}, testNow); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("forged verification err=%v", err)
	}
}

func TestVerifyArtifactBundleRejectsInvalidEntries(t *testing.T) {
	newFixture := func(t *testing.T) (Record, string, string, []byte) {
		t.Helper()
		record := completeRecord(t, RecordClient, AttestationLab)
		directory := materializeArtifactBundle(t, &record)
		name := record.Checks[0].Artifacts[0].Name
		path := filepath.Join(directory, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return record, directory, path, data
	}

	t.Run("missing", func(t *testing.T) {
		record, directory, path, _ := newFixture(t)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyArtifactBundle(record, directory); err == nil || !strings.Contains(err.Error(), "missing") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("unexpected", func(t *testing.T) {
		record, directory, _, _ := newFixture(t)
		if err := os.WriteFile(filepath.Join(directory, "unexpected.txt"), []byte("unexpected"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyArtifactBundle(record, directory); err == nil || !strings.Contains(err.Error(), "unexpected") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("case-colliding", func(t *testing.T) {
		record, directory, _, _ := newFixture(t)
		name := record.Checks[0].Artifacts[0].Name
		variant := toggleArtifactNameCase(name)
		if variant == name {
			t.Fatalf("fixture artifact name %q has no ASCII letter", name)
		}
		file, err := os.OpenFile(filepath.Join(directory, variant), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if os.IsExist(err) {
			t.Skip("filesystem does not permit case-distinct colliding entries")
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("case collision")); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyArtifactBundle(record, directory); err == nil || !strings.Contains(err.Error(), "case-colliding") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("size", func(t *testing.T) {
		record, directory, path, data := newFixture(t)
		if err := os.WriteFile(path, append(data, 'x'), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyArtifactBundle(record, directory); err == nil || !strings.Contains(err.Error(), "size") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("digest", func(t *testing.T) {
		record, directory, path, data := newFixture(t)
		data[0] ^= 1
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyArtifactBundle(record, directory); err == nil || !strings.Contains(err.Error(), "SHA-256") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("non-regular", func(t *testing.T) {
		record, directory, path, _ := newFixture(t)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyArtifactBundle(record, directory); err == nil || !strings.Contains(err.Error(), "not a regular") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("symlink entry", func(t *testing.T) {
		record, directory, path, _ := newFixture(t)
		target := filepath.Join(t.TempDir(), "target-outside-bundle")
		if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := VerifyArtifactBundle(record, directory); err == nil || !strings.Contains(err.Error(), "not a regular") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("directory symlink", func(t *testing.T) {
		record, directory, _, _ := newFixture(t)
		link := filepath.Join(t.TempDir(), "bundle-link")
		if err := os.Symlink(directory, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := VerifyArtifactBundle(record, link); err == nil || !strings.Contains(err.Error(), "non-symlink directory") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("directory parent symlink", func(t *testing.T) {
		record, directory, _, _ := newFixture(t)
		link := filepath.Join(t.TempDir(), "bundle-parent-link")
		if err := os.Symlink(filepath.Dir(directory), link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		redirected := filepath.Join(link, filepath.Base(directory))
		if _, err := VerifyArtifactBundle(record, redirected); err == nil || !strings.Contains(err.Error(), "path parent") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestVerifyArtifactBundlePinsOpenedDirectory(t *testing.T) {
	record := completeRecord(t, RecordClient, AttestationLab)
	directory := materializeArtifactBundle(t, &record)
	movedDirectory := directory + "-opened"

	verification, err := verifyArtifactBundle(record, directory, func() {
		if err := os.Rename(directory, movedDirectory); err != nil {
			t.Skipf("filesystem cannot rename an opened directory: %v", err)
		}
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "replacement.txt"), []byte("untrusted replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if err != nil || !verification.Verified() {
		t.Fatalf("verification=%+v err=%v", verification, err)
	}
}

func TestVerifyArtifactBundleAcceptsEmptyTemplateBundle(t *testing.T) {
	record, err := NewTemplate(RecordClient, "linux", "amd64", "test", testNow)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := VerifyArtifactBundle(record, t.TempDir())
	if err != nil || !verification.Verified() {
		t.Fatalf("verification=%+v err=%v", verification, err)
	}
	evaluation, err := EvaluateVerifiedAt(record, verification, testNow)
	if err != nil || evaluation.State != StatePending || evaluation.PromotionSafe {
		t.Fatalf("evaluation=%+v err=%v", evaluation, err)
	}
}

func materializeArtifactBundle(t *testing.T, record *Record) string {
	t.Helper()
	directory := t.TempDir()
	write := func(artifact *Artifact) {
		t.Helper()
		data := []byte(fmt.Sprintf("fixture artifact %s\n", artifact.Name))
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
	if err := Validate(*record); err != nil {
		t.Fatalf("materialized record is invalid: %v", err)
	}
	return directory
}

func toggleArtifactNameCase(name string) string {
	bytes := []byte(name)
	for index, value := range bytes {
		switch {
		case value >= 'a' && value <= 'z':
			bytes[index] = value - ('a' - 'A')
			return string(bytes)
		case value >= 'A' && value <= 'Z':
			bytes[index] = value + ('a' - 'A')
			return string(bytes)
		}
	}
	return name
}
