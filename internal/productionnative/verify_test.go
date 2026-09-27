package productionnative

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/reviewercrypto"
)

type observationFixture struct {
	data      []byte
	artifacts []ArtifactInput
	expected  ExpectedObservation
	policy    TrustPolicy
	payload   observation
	keys      []ed25519.PrivateKey
	now       time.Time
}

func TestVerifyObservationAuthenticatesSignedArtifactsAndFixedCell(t *testing.T) {
	for _, kind := range []Kind{KindNativeIntegration, KindPhysicalBSD, KindPackageLifecycle} {
		t.Run(string(kind), func(t *testing.T) {
			fixture := newFixture(t, kind, ExpectedCells(kind)[0], 1)
			verified, err := VerifyObservationAt(context.Background(), fixture.data, fixture.artifacts, fixture.expected, fixture.policy, fixture.now)
			if err != nil {
				t.Fatal(err)
			}
			if !verified.Valid() || verified.Kind() != kind || verified.Cell() != fixture.expected.Cell ||
				verified.Release() != fixture.expected.Release || verified.PayloadSHA256() == "" {
				t.Fatal("verified observation lost its authenticated binding")
			}
			if (VerifiedObservation{}).Valid() || ProductionTrustPolicy().Provisioned() {
				t.Fatal("zero observation or production policy must not authenticate")
			}
		})
	}
}

func TestVerifyObservationRejectsUntrustedAndMismatchedInputs(t *testing.T) {
	base := newFixture(t, KindPhysicalBSD, ExpectedCells(KindPhysicalBSD)[0], 1)
	verify := func(f observationFixture) error {
		_, err := VerifyObservationAt(context.Background(), f.data, f.artifacts, f.expected, f.policy, f.now)
		return err
	}
	if err := verify(base); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*observationFixture)
	}{
		{"unprovisioned policy", func(f *observationFixture) { f.policy = ProductionTrustPolicy() }},
		{"wrong executable digest", func(f *observationFixture) { f.expected.Release.ExecutableSHA256 = strings.Repeat("f", 64) }},
		{"mixed git object ID lengths", func(f *observationFixture) {
			f.expected.Release.Tree = strings.Repeat("b", 64)
			f.payload.Release.Tree = f.expected.Release.Tree
			f.data = signFixture(t, *f)
		}},
		{"wrong caller challenge", func(f *observationFixture) { f.expected.Challenge = "challenge-" + strings.Repeat("e", 64) }},
		{"expired observation", func(f *observationFixture) { f.now = f.now.Add(40 * 24 * time.Hour) }},
		{"revoked reviewer", func(f *observationFixture) { f.policy.policy.Keys[keyIndex(f.policy, roleReviewer)].Revoked = true }},
		{"out of scope observer", func(f *observationFixture) {
			f.policy.policy.Keys[keyIndex(f.policy, roleObserver)].Scopes = []string{scopeKey(KindPhysicalBSD, ExpectedCells(KindPhysicalBSD)[1])}
		}},
		{"duplicate organization", func(f *observationFixture) {
			f.policy.policy.Keys[keyIndex(f.policy, roleReviewer)].OrganizationID = "observer-lab"
		}},
		{"tampered raw artifact", func(f *observationFixture) {
			_ = os.WriteFile(f.artifacts[0].Path, []byte("different raw bytes"), 0o600)
		}},
		{"symlink artifact", func(f *observationFixture) {
			link := filepath.Join(t.TempDir(), "linked-artifact")
			if err := os.Symlink(f.artifacts[0].Path, link); err != nil {
				t.Fatal(err)
			}
			f.artifacts[0].Path = link
		}},
		{"symlink artifact parent", func(f *observationFixture) {
			link := filepath.Join(t.TempDir(), "linked-directory")
			if err := os.Symlink(filepath.Dir(f.artifacts[0].Path), link); err != nil {
				t.Fatal(err)
			}
			f.artifacts[0].Path = filepath.Join(link, filepath.Base(f.artifacts[0].Path))
		}},
		{"reused artifact bytes", func(f *observationFixture) {
			data, _ := os.ReadFile(f.artifacts[0].Path)
			_ = os.WriteFile(f.artifacts[1].Path, data, 0o600)
			f.payload.Artifacts[1].SizeBytes = int64(len(data))
			f.payload.Artifacts[1].SHA256 = sha256Hex(data)
			f.data = signFixture(t, *f)
		}},
		{"bad signature", func(f *observationFixture) {
			var envelopeValue envelope
			_ = json.Unmarshal(f.data, &envelopeValue)
			envelopeValue.Signatures[1].Signature = strings.Repeat("0", 128)
			f.data = canonicalJSON(t, envelopeValue)
		}},
		{"swapped signer roles", func(f *observationFixture) {
			var envelopeValue envelope
			_ = json.Unmarshal(f.data, &envelopeValue)
			envelopeValue.Signatures[0], envelopeValue.Signatures[1] = envelopeValue.Signatures[1], envelopeValue.Signatures[0]
			f.data = canonicalJSON(t, envelopeValue)
		}},
		{"future reviewer signature", func(f *observationFixture) {
			var envelopeValue envelope
			_ = json.Unmarshal(f.data, &envelopeValue)
			payloadData, _ := base64.RawURLEncoding.DecodeString(envelopeValue.Payload)
			item := &envelopeValue.Signatures[1]
			item.SignedAt = f.now.Add(time.Hour).Format(time.RFC3339)
			preimage := reviewercrypto.SignaturePreimage(signatureDomain, PayloadType, item.KeyID, item.SignedAt, payloadData)
			item.Signature = hex.EncodeToString(ed25519.Sign(f.keys[1], preimage))
			f.data = canonicalJSON(t, envelopeValue)
		}},
		{"reviewer did not follow observer", func(f *observationFixture) {
			var envelopeValue envelope
			_ = json.Unmarshal(f.data, &envelopeValue)
			payloadData, _ := base64.RawURLEncoding.DecodeString(envelopeValue.Payload)
			item := &envelopeValue.Signatures[1]
			item.SignedAt = envelopeValue.Signatures[0].SignedAt
			preimage := reviewercrypto.SignaturePreimage(signatureDomain, PayloadType, item.KeyID, item.SignedAt, payloadData)
			item.Signature = hex.EncodeToString(ed25519.Sign(f.keys[1], preimage))
			f.data = canonicalJSON(t, envelopeValue)
		}},
		{"duplicate envelope key", func(f *observationFixture) {
			f.data = bytes.Replace(f.data, []byte("\"envelope_version\": 1,"), []byte("\"envelope_version\": 1,\n  \"envelope_version\": 1,"), 1)
		}},
		{"duplicate signed payload key", func(f *observationFixture) {
			payloadData := canonicalJSON(t, f.payload)
			payloadData = bytes.Replace(payloadData, []byte("\"schema_version\": 1,"), []byte("\"schema_version\": 1,\n  \"schema_version\": 1,"), 1)
			f.data = signRawPayload(t, f.keys, f.payload.CreatedAt, payloadData)
		}},
		{"noncanonical signed payload", func(f *observationFixture) {
			var envelopeValue envelope
			_ = json.Unmarshal(f.data, &envelopeValue)
			payload, _ := base64.RawURLEncoding.DecodeString(envelopeValue.Payload)
			envelopeValue.Payload = base64.RawURLEncoding.EncodeToString(bytes.TrimSuffix(payload, []byte{'\n'}))
			f.data = canonicalJSON(t, envelopeValue)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t, KindPhysicalBSD, ExpectedCells(KindPhysicalBSD)[0], 1)
			test.mutate(&fixture)
			if err := verify(fixture); err == nil {
				t.Fatal("untrusted or mismatched input was accepted")
			}
		})
	}
}

func TestVerifyCompleteSetRequiresEveryFixedCellAndCurrentArtifacts(t *testing.T) {
	var observations []VerifiedObservation
	var policy TrustPolicy
	for i, cell := range ExpectedCells(KindPhysicalBSD) {
		fixture := newFixture(t, KindPhysicalBSD, cell, i+1)
		policy = fixture.policy
		verified, err := VerifyObservationAt(context.Background(), fixture.data, fixture.artifacts, fixture.expected, fixture.policy, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		observations = append(observations, verified)
	}
	now := time.Date(2026, 9, 27, 12, 30, 0, 0, time.UTC)
	set, err := VerifyCompleteSetAt(context.Background(), KindPhysicalBSD, observations, policy, now)
	if err != nil || !set.Valid() {
		t.Fatalf("complete set = %+v, %v", set, err)
	}
	// Both signatures were made at 12:01 and 12:02. The observations were
	// verified at 12:30; an earlier set verification must not time-travel.
	tooEarly := time.Date(2026, 9, 27, 12, 0, 30, 0, time.UTC)
	if _, err := VerifyCompleteSetAt(context.Background(), KindPhysicalBSD, observations, policy, tooEarly); err == nil {
		t.Fatal("set verification before reviewer signatures was accepted")
	}
	beforeObservationVerification := time.Date(2026, 9, 27, 12, 20, 0, 0, time.UTC)
	if _, err := VerifyCompleteSetAt(context.Background(), KindPhysicalBSD, observations, policy, beforeObservationVerification); err == nil {
		t.Fatal("set verification before authenticated observation verification was accepted")
	}
	if _, err := VerifyCompleteSetAt(context.Background(), KindPhysicalBSD, observations[:len(observations)-1], policy, now); err == nil {
		t.Fatal("incomplete fixed inventory was accepted")
	}
	duplicated := append([]VerifiedObservation(nil), observations...)
	duplicated[1] = duplicated[0]
	if _, err := VerifyCompleteSetAt(context.Background(), KindPhysicalBSD, duplicated, policy, now); err == nil {
		t.Fatal("repeated cell and run were accepted")
	}
	if err := os.WriteFile(observations[0].artifactInputs[0].Path, []byte("changed after first verification"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCompleteSetAt(context.Background(), KindPhysicalBSD, observations, policy, now); err == nil {
		t.Fatal("changed raw bytes were accepted by complete-set recheck")
	}
}

func TestKindSpecificExpectedBindings(t *testing.T) {
	for _, test := range []struct {
		name   string
		kind   Kind
		mutate func(*observationFixture)
	}{
		{"lifecycle package digest", KindPackageLifecycle, func(f *observationFixture) {
			f.expected.PackageSHA256 = strings.Repeat("f", 64)
		}},
		{"integration host route", KindNativeIntegration, func(f *observationFixture) {
			f.expected.HostRoute = "physical-macos-remote"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t, test.kind, ExpectedCells(test.kind)[0], 1)
			test.mutate(&fixture)
			if _, err := VerifyObservationAt(context.Background(), fixture.data, fixture.artifacts, fixture.expected, fixture.policy, fixture.now); err == nil {
				t.Fatal("payload selected its own package or host route")
			}
		})
	}
}

func TestIntegrationAndLifecycleSetsNeedAllCells(t *testing.T) {
	for _, kind := range []Kind{KindNativeIntegration, KindPackageLifecycle} {
		t.Run(string(kind), func(t *testing.T) {
			var observations []VerifiedObservation
			var policy TrustPolicy
			for i, cell := range ExpectedCells(kind) {
				fixture := newFixture(t, kind, cell, i+1)
				policy = fixture.policy
				verified, err := VerifyObservationAt(context.Background(), fixture.data, fixture.artifacts, fixture.expected, fixture.policy, fixture.now)
				if err != nil {
					t.Fatal(err)
				}
				observations = append(observations, verified)
			}
			now := time.Date(2026, 9, 27, 12, 30, 0, 0, time.UTC)
			set, err := VerifyCompleteSetAt(context.Background(), kind, observations, policy, now)
			if err != nil || !set.Valid() {
				t.Fatalf("full fixed inventory was rejected: %v", err)
			}
			if _, err := VerifyCompleteSetAt(context.Background(), kind, observations[:len(observations)-1], policy, now); err == nil {
				t.Fatal("incomplete fixed inventory was accepted")
			}
		})
	}
}

func TestFixedInventories(t *testing.T) {
	for _, item := range []struct {
		kind Kind
		want int
	}{{KindNativeIntegration, 9}, {KindPhysicalBSD, 7}, {KindPackageLifecycle, 11}} {
		cells := ExpectedCells(item.kind)
		if len(cells) != item.want {
			t.Fatalf("%s cells = %d, want %d", item.kind, len(cells), item.want)
		}
		cells[0] = Cell{}
		if ExpectedCells(item.kind)[0] == (Cell{}) {
			t.Fatalf("%s fixed cells were mutable", item.kind)
		}
	}
}

func newFixture(t *testing.T, kind Kind, cell Cell, sequence int) observationFixture {
	t.Helper()
	now := time.Date(2026, 9, 27, 12, 30, 0, 0, time.UTC)
	created := now.Add(-30 * time.Minute)
	expires := now.Add(24 * time.Hour)
	privateObserver := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	privateReviewer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, ed25519.SeedSize))
	keys := []ed25519.PrivateKey{privateObserver, privateReviewer}
	policyKeys := []trustedKey{
		fixtureKey(privateObserver, roleObserver, "observer-one", "observer-lab", kind),
		fixtureKey(privateReviewer, roleReviewer, "reviewer-one", "review-board", kind),
	}
	sort.Slice(policyKeys, func(i, j int) bool { return policyKeys[i].KeyID < policyKeys[j].KeyID })
	policy, err := newTrustPolicy(trustPolicy{
		ID: policyID, Status: policyActive,
		ValidFrom: now.Add(-7 * 24 * time.Hour).Format(time.RFC3339),
		ExpiresAt: now.Add(7 * 24 * time.Hour).Format(time.RFC3339), Keys: policyKeys,
	})
	if err != nil {
		t.Fatal(err)
	}
	version := "v1.2.3"
	release := ReleaseBinding{
		Version: version, Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), ReleaseID: 123,
		ArchiveFilename: "leaguebridge_1.2.3_" + cell.GOOS + "_" + cell.GOARCH + ".tar.gz",
		ArchiveSHA256:   strings.Repeat("c", 64), ExecutableSHA256: strings.Repeat("d", 64),
	}
	challenge := "challenge-" + hex.EncodeToString(bytes.Repeat([]byte{byte(sequence)}, 32))
	expected := ExpectedObservation{Kind: kind, Cell: cell, Release: release, Challenge: challenge}
	if kind == KindNativeIntegration {
		expected.HostRoute = "physical-windows-remote"
	}
	if kind == KindPackageLifecycle {
		expected.PackageSHA256 = sha256Hex([]byte(cell.Family + "/" + cell.GOOS + "/" + cell.GOARCH))
	}
	directory := t.TempDir()
	var artifactInputs []ArtifactInput
	var artifactDigests []artifact
	for _, artifactKind := range artifactSets[kind] {
		data := []byte("raw " + string(kind) + " " + cell.Family + "/" + cell.GOOS + "/" + cell.GOARCH + " " + artifactKind)
		path := filepath.Join(directory, artifactKind+".bin")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		artifactInputs = append(artifactInputs, ArtifactInput{Kind: artifactKind, Path: path})
		artifactDigests = append(artifactDigests, artifact{Kind: artifactKind, SizeBytes: int64(len(data)), SHA256: sha256Hex(data)})
	}
	payload := observation{
		Schema: PayloadSchemaID, SchemaVersion: PayloadVersion, ObservationType: PayloadType,
		Kind: kind, PolicyID: policyID,
		ObservationID: "observation-" + hex.EncodeToString(bytes.Repeat([]byte{byte(sequence)}, 16)),
		RunID:         "run-" + hex.EncodeToString(bytes.Repeat([]byte{byte(sequence)}, 16)),
		MachineID:     "machine-" + hex.EncodeToString(bytes.Repeat([]byte{byte(sequence)}, 16)),
		Challenge:     challenge, CreatedAt: created.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339),
		Cell: cell, Release: release, PackageSHA256: expected.PackageSHA256,
		HostRoute: expected.HostRoute, NativeKernel: nativeKernel(cell.GOOS),
		Assertions: append([]string(nil), assertionSets[kind]...), Artifacts: artifactDigests,
	}
	fixture := observationFixture{artifacts: artifactInputs, expected: expected, policy: policy, payload: payload, keys: keys, now: now}
	fixture.data = signFixture(t, fixture)
	return fixture
}

func signFixture(t *testing.T, fixture observationFixture) []byte {
	t.Helper()
	payloadData := canonicalJSON(t, fixture.payload)
	return signRawPayload(t, fixture.keys, fixture.payload.CreatedAt, payloadData)
}

func signRawPayload(t *testing.T, keys []ed25519.PrivateKey, createdAt string, payloadData []byte) []byte {
	t.Helper()
	envelopeValue := envelope{Schema: EnvelopeSchemaID, EnvelopeVersion: EnvelopeVersion, PayloadType: PayloadType,
		PayloadEncoding: PayloadEncoding, Payload: base64.RawURLEncoding.EncodeToString(payloadData)}
	created, _ := canonicalTime("created_at", createdAt)
	for i, privateKey := range keys {
		signedAt := created.Add(time.Duration(i+1) * time.Minute).Format(time.RFC3339)
		keyID := deriveKeyID(privateKey.Public().(ed25519.PublicKey))
		preimage := reviewercrypto.SignaturePreimage(signatureDomain, PayloadType, keyID, signedAt, payloadData)
		envelopeValue.Signatures = append(envelopeValue.Signatures, signature{
			Algorithm: Algorithm, KeyID: keyID, SignedAt: signedAt,
			Signature: hex.EncodeToString(ed25519.Sign(privateKey, preimage)),
		})
	}
	return canonicalJSON(t, envelopeValue)
}

func fixtureKey(private ed25519.PrivateKey, role, principal, organization string, kind Kind) trustedKey {
	public := private.Public().(ed25519.PublicKey)
	var scopes []string
	for _, allowed := range ExpectedCells(kind) {
		scopes = append(scopes, scopeKey(kind, allowed))
	}
	sort.Strings(scopes)
	return trustedKey{KeyID: deriveKeyID(public), PublicKey: hex.EncodeToString(public),
		PrincipalID: principal, OrganizationID: organization, Role: role,
		Scopes:    scopes,
		NotBefore: "2026-09-20T12:30:00Z", NotAfter: "2026-10-04T12:30:00Z"}
}

func keyIndex(policy TrustPolicy, role string) int {
	for i, key := range policy.policy.Keys {
		if key.Role == role {
			return i
		}
	}
	return -1
}

func canonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}
