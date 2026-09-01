package evidencev2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"github.com/Yunushan/leaguebridge/internal/evidence"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

var v2TestNow = time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)

type v2Fixture struct {
	envelope         []byte
	payload          []byte
	host             []byte
	client           []byte
	session          []byte
	hostArtifacts    string
	clientArtifacts  string
	sessionArtifacts string
	verifications    evidence.ArtifactVerificationSet
	policy           TrustPolicy
	expected         ExpectedCell
	privateKeys      map[string]ed25519.PrivateKey
}

func TestVerifySetAtAuthenticatesCompleteBoundSet(t *testing.T) {
	fixture := newV2Fixture(t)
	verified, err := VerifySetAt(fixture.envelope, fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Valid() || verified.SetID() != "set-0123456789abcdef0123456789abcdef" || verified.ValidationRunID() != "run-0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected verified identity: valid=%v set=%q run=%q", verified.Valid(), verified.SetID(), verified.ValidationRunID())
	}
	if verified.RouteID() != fixture.expected.RouteID || verified.ClientPlatform() != fixture.expected.ClientPlatform || verified.ClientArchitecture() != fixture.expected.ClientArchitecture {
		t.Fatalf("unexpected verified cell: %s/%s/%s", verified.RouteID(), verified.ClientPlatform(), verified.ClientArchitecture())
	}
	if verified.PayloadSHA256() != sha256Hex(fixture.payload) || verified.SessionRecordSHA256() != sha256Hex(fixture.session) {
		t.Fatal("verified token did not retain exact payload and session digests")
	}
	if len(verified.SignerKeyIDs()) != 2 || len(verified.SignerPrincipalIDs()) != 2 || len(verified.SignerOrganizationIDs()) != 2 {
		t.Fatalf("unexpected signer metadata: %+v", verified.SignerKeyIDs())
	}
	keyIDs := verified.SignerKeyIDs()
	keyIDs[0] = "mutated"
	if verified.SignerKeyIDs()[0] == "mutated" {
		t.Fatal("signer getter exposed mutable token state")
	}
	if (VerifiedSet{}).Valid() {
		t.Fatal("zero VerifiedSet is valid")
	}
}

func TestVerifySetAtAuthenticatesMacOSArm64HostRoute(t *testing.T) {
	fixture := newV2MacOSFixture(t)
	verified, err := VerifySetAt(fixture.envelope, fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Valid() || verified.RouteID() != RoutePhysicalMacOSRemote || verified.ClientPlatform() != "linux" || verified.ClientArchitecture() != "amd64" {
		t.Fatalf("unexpected macOS verified set: valid=%v route=%q client=%s/%s", verified.Valid(), verified.RouteID(), verified.ClientPlatform(), verified.ClientArchitecture())
	}
	prepared, err := PreparePayloadAt(PrepareRequest{
		HostData: fixture.host, ClientData: fixture.client, SessionData: fixture.session,
		Expected: fixture.expected, Verifications: fixture.verifications, PolicyID: fixture.policy.ID(),
	}, v2TestNow)
	if err != nil {
		t.Fatalf("prepare macOS payload: %v", err)
	}
	if parsed, err := parsePayload(prepared); err != nil || parsed.RouteID != RoutePhysicalMacOSRemote || parsed.HostPlatform != "macos" || parsed.HostArchitecture != "arm64" {
		t.Fatalf("prepared macOS payload=%+v err=%v", parsed, err)
	}
}

func TestVerifySetAtPreservesRFC3339RecordTimestampCompatibility(t *testing.T) {
	fixture := rewriteV2FixtureRecords(t, newV2Fixture(t), func(host, client, session *evidence.Record) {
		rewriteRecordTimestamps(t, host, 3*time.Hour, false)
		rewriteRecordTimestamps(t, client, 0, true)
		rewriteRecordTimestamps(t, session, -4*time.Hour, true)
	})

	verified, err := VerifySetAt(fixture.envelope, fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
	if err != nil {
		t.Fatalf("valid v1 RFC3339 offset/fraction timestamps were rejected: %v", err)
	}
	if !verified.Valid() {
		t.Fatal("compatible RFC3339 record timestamps did not produce a verified set")
	}
}

func TestVerifySetAtComparesRecordTimestampInstants(t *testing.T) {
	t.Run("session validity must denote payload instants", func(t *testing.T) {
		fixture := rewriteV2FixtureRecords(t, newV2Fixture(t), func(_, _ *evidence.Record, session *evidence.Record) {
			createdAt, err := time.Parse(time.RFC3339, session.CreatedAt)
			if err != nil {
				t.Fatal(err)
			}
			session.CreatedAt = createdAt.Add(time.Second).Format(time.RFC3339)
		})
		_, err := VerifySetAt(fixture.envelope, fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
		assertErrorContains(t, err, "must match the session record instants")
	})

	t.Run("signature must follow fractional offset review instant", func(t *testing.T) {
		fixture := rewriteV2FixtureRecords(t, newV2Fixture(t), func(_, _ *evidence.Record, session *evidence.Record) {
			session.Attestation.ReviewedAt = formatRFC3339Variant(v2TestNow.Add(-30*time.Second), 3*time.Hour, true)
		})
		_, err := VerifySetAt(fixture.envelope, fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
		assertErrorContains(t, err, "predates the session record review")
	})
}

func TestSignaturePreimageUsesUnambiguousBinaryFraming(t *testing.T) {
	got := signaturePreimage("p", "k", "t", []byte{0x00, 0xff})
	want := append([]byte(signatureDomain),
		0, 0, 0, 0, 0, 0, 0, 1, 'p',
		0, 0, 0, 0, 0, 0, 0, 1, 'k',
		0, 0, 0, 0, 0, 0, 0, 1, 't',
		0, 0, 0, 0, 0, 0, 0, 2, 0x00, 0xff,
	)
	if !bytes.Equal(got, want) {
		t.Fatalf("preimage = %x; want %x", got, want)
	}
	if bytes.Equal(signaturePreimage("ab", "c", "t", nil), signaturePreimage("a", "bc", "t", nil)) {
		t.Fatal("length framing did not distinguish adjacent fields")
	}
}

func TestProductionTrustPolicyIsValidButUnprovisioned(t *testing.T) {
	policy := ProductionTrustPolicy()
	if policy.ID() != productionPolicyID || policy.Provisioned() {
		t.Fatalf("production policy ID/provisioning = %q/%v", policy.ID(), policy.Provisioned())
	}
	if (TrustPolicy{}).ID() != "" || (TrustPolicy{}).Provisioned() {
		t.Fatal("zero TrustPolicy was treated as application trust")
	}

	fixture := newV2Fixture(t)
	var parsed payload
	if err := json.Unmarshal(fixture.payload, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.PolicyID = policy.ID()
	fixture.payload = mustJSON(t, parsed)
	fixture.envelope = makeSignedEnvelope(t, fixture.payload, fixture.privateKeys, v2TestNow.Add(-time.Minute))
	_, err := VerifySetAt(fixture.envelope, fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, policy, v2TestNow)
	if err == nil || !strings.Contains(err.Error(), "records and artifacts are valid") {
		t.Fatalf("unprovisioned production policy err = %v", err)
	}
}

func TestPreparePayloadAtEmitsExactVerifierCompatibleBytes(t *testing.T) {
	fixture := newV2Fixture(t)
	prepared, err := PreparePayloadAt(PrepareRequest{
		HostData:      fixture.host,
		ClientData:    fixture.client,
		SessionData:   fixture.session,
		Expected:      fixture.expected,
		Verifications: fixture.verifications,
		SetID:         "set-fedcba9876543210fedcba9876543210",
		PolicyID:      fixture.policy.ID(),
	}, v2TestNow)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(prepared, []byte("\n")) {
		t.Fatal("prepared payload is missing its stable trailing newline")
	}
	parsed, err := parsePayload(prepared)
	if err != nil {
		t.Fatalf("prepared payload did not parse: %v", err)
	}
	if parsed.SetID != "set-fedcba9876543210fedcba9876543210" || parsed.PolicyID != fixture.policy.ID() {
		t.Fatalf("unexpected prepared identity: set=%q policy=%q", parsed.SetID, parsed.PolicyID)
	}
	envelope := makeSignedEnvelope(t, prepared, fixture.privateKeys, v2TestNow.Add(-time.Minute))
	verified, err := VerifySetAt(envelope, fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
	if err != nil {
		t.Fatalf("prepared bytes were not accepted by the verifier: %v", err)
	}
	if verified.PayloadSHA256() != sha256Hex(prepared) {
		t.Fatalf("payload digest = %s; want %s", verified.PayloadSHA256(), sha256Hex(prepared))
	}
}

func TestPreparePayloadAtRejectsFractionalSessionInstants(t *testing.T) {
	fixture := rewriteV2FixtureRecords(t, newV2Fixture(t), func(_, _ *evidence.Record, session *evidence.Record) {
		session.CreatedAt = formatRFC3339Variant(v2TestNow.Add(-time.Hour).Add(500*time.Millisecond), 0, true)
	})
	_, err := PreparePayloadAt(PrepareRequest{
		HostData:      fixture.host,
		ClientData:    fixture.client,
		SessionData:   fixture.session,
		Expected:      fixture.expected,
		Verifications: fixture.verifications,
		PolicyID:      fixture.policy.ID(),
	}, v2TestNow)
	assertErrorContains(t, err, "whole-second precision")
}

func TestV2FixturesConformToPublicSchemas(t *testing.T) {
	fixture := newV2Fixture(t)
	for _, test := range []struct {
		name     string
		path     string
		schemaID string
		data     []byte
	}{
		{"payload", "validation-evidence-v2.schema.json", PayloadSchemaID, fixture.payload},
		{"envelope", "evidence-signature-envelope.schema.json", EnvelopeSchemaID, fixture.envelope},
		{"trust policy", "evidence-trust-policy.schema.json", TrustPolicySchemaID, mustJSON(t, fixture.policy.policy)},
		{"unprovisioned trust policy", "evidence-trust-policy.schema.json", TrustPolicySchemaID, mustJSON(t, ProductionTrustPolicy().policy)},
	} {
		t.Run(test.name, func(t *testing.T) {
			schema := compileV2Schema(t, test.path, test.schemaID)
			var instance any
			decoder := json.NewDecoder(bytes.NewReader(test.data))
			decoder.UseNumber()
			if err := decoder.Decode(&instance); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(instance); err != nil {
				t.Fatalf("public schema rejected generated fixture: %v", err)
			}
		})
	}
}

func TestVerifySetAtRejectsCryptographicAndBindingAttacks(t *testing.T) {
	fixture := newV2Fixture(t)
	verify := func(envelopeData, hostData, clientData, sessionData []byte, expected ExpectedCell, verifications evidence.ArtifactVerificationSet, policy TrustPolicy, now time.Time) error {
		t.Helper()
		_, err := VerifySetAt(envelopeData, hostData, clientData, sessionData, expected, verifications, policy, now)
		return err
	}

	t.Run("exact payload bytes are signed", func(t *testing.T) {
		envelope := decodeEnvelope(t, fixture.envelope)
		envelope.Payload = base64.RawURLEncoding.EncodeToString(append(append([]byte{}, fixture.payload...), '\n'))
		err := verify(mustJSON(t, envelope), fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
		assertErrorContains(t, err, "signature 0")
	})

	t.Run("tampered signature", func(t *testing.T) {
		envelope := decodeEnvelope(t, fixture.envelope)
		envelope.Signatures[0].Signature = strings.Repeat("0", 128)
		err := verify(mustJSON(t, envelope), fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
		assertErrorContains(t, err, "is invalid")
	})

	t.Run("all supplied signatures must be trusted", func(t *testing.T) {
		envelope := decodeEnvelope(t, fixture.envelope)
		envelope.Signatures[0].KeyID = "lbk1-" + strings.Repeat("0", 64)
		sort.Slice(envelope.Signatures, func(i, j int) bool { return envelope.Signatures[i].KeyID < envelope.Signatures[j].KeyID })
		err := verify(mustJSON(t, envelope), fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
		assertErrorContains(t, err, "untrusted key_id")
	})

	t.Run("signature ordering", func(t *testing.T) {
		envelope := decodeEnvelope(t, fixture.envelope)
		envelope.Signatures[0], envelope.Signatures[1] = envelope.Signatures[1], envelope.Signatures[0]
		err := verify(mustJSON(t, envelope), fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
		assertErrorContains(t, err, "strictly sorted")
	})

	t.Run("noncanonical payload encoding", func(t *testing.T) {
		envelope := decodeEnvelope(t, fixture.envelope)
		envelope.Payload += "="
		err := verify(mustJSON(t, envelope), fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
		assertErrorContains(t, err, "canonical base64url")
	})

	t.Run("caller expected cell", func(t *testing.T) {
		wrong := fixture.expected
		wrong.ClientPlatform = "freebsd"
		err := verify(fixture.envelope, fixture.host, fixture.client, fixture.session, wrong, fixture.verifications, fixture.policy, v2TestNow)
		assertErrorContains(t, err, "caller-expected cell")
	})

	t.Run("missing expected cell", func(t *testing.T) {
		err := verify(fixture.envelope, fixture.host, fixture.client, fixture.session, ExpectedCell{}, fixture.verifications, fixture.policy, v2TestNow)
		assertErrorContains(t, err, "expected route")
	})

	t.Run("raw record splice", func(t *testing.T) {
		err := verify(fixture.envelope, append(append([]byte{}, fixture.host...), '\n'), fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
		assertErrorContains(t, err, "host_record_sha256")
	})

	t.Run("forged artifact verification", func(t *testing.T) {
		forged := fixture.verifications
		forged.Session = evidence.ArtifactVerification{}
		err := verify(fixture.envelope, fixture.host, fixture.client, fixture.session, fixture.expected, forged, fixture.policy, v2TestNow)
		assertErrorContains(t, err, "artifact verification")
	})

	t.Run("unsupported route fails explicitly", func(t *testing.T) {
		var changed payload
		if err := json.Unmarshal(fixture.payload, &changed); err != nil {
			t.Fatal(err)
		}
		changed.RouteID = "unsupported-route"
		envelope := decodeEnvelope(t, fixture.envelope)
		envelope.Payload = base64.RawURLEncoding.EncodeToString(mustJSON(t, changed))
		err := verify(mustJSON(t, envelope), fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
		assertErrorContains(t, err, "unsupported validation-evidence v2 route_id")
	})

	t.Run("payload record digest", func(t *testing.T) {
		var changed payload
		if err := json.Unmarshal(fixture.payload, &changed); err != nil {
			t.Fatal(err)
		}
		changed.SessionRecordSHA256 = strings.Repeat("0", 64)
		envelope := decodeEnvelope(t, fixture.envelope)
		envelope.Payload = base64.RawURLEncoding.EncodeToString(mustJSON(t, changed))
		err := verify(mustJSON(t, envelope), fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
		assertErrorContains(t, err, "session_record_sha256")
	})

	t.Run("future signed_at even with valid signature", func(t *testing.T) {
		envelope := makeSignedEnvelope(t, fixture.payload, fixture.privateKeys, v2TestNow.Add(time.Hour))
		err := verify(envelope, fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
		assertErrorContains(t, err, "future")
	})
}

func TestVerifySetAtRejectsPolicyAndQuorumAttacks(t *testing.T) {
	fixture := newV2Fixture(t)
	verifyWithPolicy := func(policy TrustPolicy) error {
		t.Helper()
		_, err := VerifySetAt(fixture.envelope, fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, policy, v2TestNow)
		return err
	}

	if err := verifyWithPolicy(TrustPolicy{}); err == nil || !strings.Contains(err.Error(), "validated application trust policy") {
		t.Fatalf("zero policy err = %v", err)
	}

	t.Run("revoked key", func(t *testing.T) {
		raw := cloneTrustPolicy(fixture.policy.policy)
		raw.Keys[0].Revoked = true
		policy, err := newTrustPolicy(raw)
		if err != nil {
			t.Fatal(err)
		}
		assertErrorContains(t, verifyWithPolicy(policy), "revoked")
	})

	t.Run("distinct organizations", func(t *testing.T) {
		raw := cloneTrustPolicy(fixture.policy.policy)
		raw.Keys[1].OrganizationID = raw.Keys[0].OrganizationID
		policy, err := newTrustPolicy(raw)
		if err != nil {
			t.Fatal(err)
		}
		assertErrorContains(t, verifyWithPolicy(policy), "distinct organizations")
	})

	t.Run("distinct principals", func(t *testing.T) {
		raw := cloneTrustPolicy(fixture.policy.policy)
		raw.Keys[1].PrincipalID = raw.Keys[0].PrincipalID
		policy, err := newTrustPolicy(raw)
		if err != nil {
			t.Fatal(err)
		}
		assertErrorContains(t, verifyWithPolicy(policy), "distinct organizations")
	})

	t.Run("scope mismatch", func(t *testing.T) {
		raw := cloneTrustPolicy(fixture.policy.policy)
		raw.Keys[0].ClientPlatforms = []string{"freebsd"}
		policy, err := newTrustPolicy(raw)
		if err != nil {
			t.Fatal(err)
		}
		assertErrorContains(t, verifyWithPolicy(policy), "outside its")
	})

	t.Run("credential must cover payload lifetime", func(t *testing.T) {
		raw := cloneTrustPolicy(fixture.policy.policy)
		raw.Keys[0].NotAfter = v2TestNow.Add(24 * time.Hour).Format(time.RFC3339)
		policy, err := newTrustPolicy(raw)
		if err != nil {
			t.Fatal(err)
		}
		assertErrorContains(t, verifyWithPolicy(policy), "complete payload lifetime")
	})

	t.Run("derived key ID", func(t *testing.T) {
		raw := cloneTrustPolicy(fixture.policy.policy)
		raw.Keys[0].KeyID = "lbk1-" + strings.Repeat("0", 64)
		_, err := newTrustPolicy(raw)
		assertErrorContains(t, err, "derived public-key ID")
	})

	t.Run("unsorted keys", func(t *testing.T) {
		raw := cloneTrustPolicy(fixture.policy.policy)
		raw.Keys[0], raw.Keys[1] = raw.Keys[1], raw.Keys[0]
		_, err := newTrustPolicy(raw)
		assertErrorContains(t, err, "strictly sorted")
	})
}

func TestReviewerPublicKeyRequiresCanonicalPrimeOrderNonIdentityPoint(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	validPublicKey := privateKey.Public().(ed25519.PublicKey)
	if err := validateReviewerPublicKey(validPublicKey); err != nil {
		t.Fatalf("standard-library generated public key was rejected: %v", err)
	}

	identity := make([]byte, ed25519.PublicKeySize)
	identity[0] = 1
	orderFour := make([]byte, ed25519.PublicKeySize)
	nonCanonicalIdentity := append([]byte(nil), identity...)
	nonCanonicalIdentity[31] = 0x80

	validPoint, err := new(edwards25519.Point).SetBytes(validPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	torsionPoint, err := new(edwards25519.Point).SetBytes(orderFour)
	if err != nil {
		t.Fatal(err)
	}
	mixedOrder := new(edwards25519.Point).Add(validPoint, torsionPoint).Bytes()

	for _, test := range []struct {
		name      string
		publicKey []byte
		want      string
	}{
		{"identity", identity, "identity"},
		{"known order-four encoding", orderFour, "prime-order"},
		{"non-canonical identity", nonCanonicalIdentity, "canonical"},
		{"prime point with torsion component", mixedOrder, "prime-order"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateReviewerPublicKey(test.publicKey); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateReviewerPublicKey() error = %v; want %q", err, test.want)
			}
		})
	}

	fixture := newV2Fixture(t)
	raw := cloneTrustPolicy(fixture.policy.policy)
	raw.Keys[0].PublicKey = hex.EncodeToString(identity)
	raw.Keys[0].KeyID = deriveKeyID(identity)
	sort.Slice(raw.Keys, func(i, j int) bool { return raw.Keys[i].KeyID < raw.Keys[j].KeyID })
	if _, err := newTrustPolicy(raw); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("newTrustPolicy(identity key) error = %v", err)
	}
}

func TestStrictEnvelopeAndPayloadParsing(t *testing.T) {
	fixture := newV2Fixture(t)
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"duplicate key", []byte(strings.Replace(string(fixture.envelope), `"envelope_version":1`, `"envelope_version":1,"envelope_version":1`, 1)), "duplicate key"},
		{"unknown field", []byte(strings.Replace(string(fixture.envelope), `"envelope_version":1`, `"unknown":1,"envelope_version":1`, 1)), "unknown field"},
		{"null", []byte(strings.Replace(string(fixture.envelope), `"payload_type":"`+PayloadType+`"`, `"payload_type":null`, 1)), "must not be null"},
		{"trailing value", append(append([]byte{}, fixture.envelope...), []byte(` {}`)...), "trailing JSON value"},
		{"invalid UTF-8", append(append([]byte{}, fixture.envelope...), 0xff), "valid UTF-8"},
		{"oversize", make([]byte, MaxEnvelopeSize+1), "exceeds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, err := parseEnvelope(test.data)
			assertErrorContains(t, err, test.want)
		})
	}

	var parsed payload
	if err := json.Unmarshal(fixture.payload, &parsed); err != nil {
		t.Fatal(err)
	}
	noncanonical := parsed
	noncanonical.CreatedAt = strings.Replace(parsed.CreatedAt, "Z", "+00:00", 1)
	if _, err := parsePayload(mustJSON(t, noncanonical)); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("noncanonical timestamp err = %v", err)
	}
	unknownPayload := []byte(strings.Replace(string(fixture.payload), `"schema_version":2`, `"extra":true,"schema_version":2`, 1))
	if _, err := parsePayload(unknownPayload); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown payload field err = %v", err)
	}
	duplicatePayload := []byte(strings.Replace(string(fixture.payload), `"schema_version":2`, `"schema_version":2,"schema_version":2`, 1))
	if _, err := parsePayload(duplicatePayload); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate payload field err = %v", err)
	}
	if _, err := parsePayload(nil); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty payload err = %v", err)
	}
	if _, err := parsePayload(make([]byte, MaxPayloadSize+1)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize payload err = %v", err)
	}
	deep := []byte(strings.Repeat("[", maxJSONDepth+2) + "0" + strings.Repeat("]", maxJSONDepth+2))
	if _, err := parsePayload(deep); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("deep payload err = %v", err)
	}
}

func FuzzParseEnvelope(f *testing.F) {
	fixture := newV2Fixture(f)
	f.Add(fixture.envelope)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"$schema":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxEnvelopeSize+1 {
			return
		}
		_, _, _, _ = parseEnvelope(data)
	})
}

func newV2Fixture(t testing.TB) v2Fixture {
	t.Helper()
	const runID = "run-0123456789abcdef0123456789abcdef"
	base := v2TestNow.Add(-time.Hour)
	host := completeV1Record(t, evidence.RecordHost, "windows", runID, "host-11111111111111111111111111111111", base)
	client := completeV1Record(t, evidence.RecordClient, "linux", runID, "client-22222222222222222222222222222222", base)
	hostDir := materializeV1Artifacts(t, &host)
	clientDir := materializeV1Artifacts(t, &client)
	hostData := mustJSON(t, host)
	clientData := mustJSON(t, client)

	session := completeV1Record(t, evidence.RecordSession, "linux", runID, "session-33333333333333333333333333333333", base)
	session.Bindings.HostRecordSHA256 = sha256Hex(hostData)
	session.Bindings.ClientRecordSHA256 = sha256Hex(clientData)
	sessionDir := materializeV1Artifacts(t, &session)
	sessionData := mustJSON(t, session)

	hostVerification, err := evidence.VerifyArtifactBundle(host, hostDir)
	if err != nil {
		t.Fatal(err)
	}
	clientVerification, err := evidence.VerifyArtifactBundle(client, clientDir)
	if err != nil {
		t.Fatal(err)
	}
	sessionVerification, err := evidence.VerifyArtifactBundle(session, sessionDir)
	if err != nil {
		t.Fatal(err)
	}

	policy, privateKeys := deterministicTrustPolicy(t)
	payloadData := mustJSON(t, payload{
		Schema:              PayloadSchemaID,
		SchemaVersion:       PayloadVersion,
		SetID:               "set-0123456789abcdef0123456789abcdef",
		ValidationRunID:     runID,
		RouteID:             RoutePhysicalWindowsRemote,
		TestProfileID:       TestProfileRemotePlayV1,
		PolicyID:            policy.ID(),
		CreatedAt:           session.CreatedAt,
		ExpiresAt:           session.ExpiresAt,
		ManifestAsOf:        session.ManifestAsOf,
		ManifestSHA256:      session.ManifestSHA256,
		HostPlatform:        "windows",
		HostArchitecture:    "amd64",
		ClientPlatform:      "linux",
		ClientArchitecture:  "amd64",
		HostRecordSHA256:    sha256Hex(hostData),
		ClientRecordSHA256:  sha256Hex(clientData),
		SessionRecordSHA256: sha256Hex(sessionData),
	})
	return v2Fixture{
		envelope:         makeSignedEnvelope(t, payloadData, privateKeys, v2TestNow.Add(-time.Minute)),
		payload:          payloadData,
		host:             hostData,
		client:           clientData,
		session:          sessionData,
		hostArtifacts:    hostDir,
		clientArtifacts:  clientDir,
		sessionArtifacts: sessionDir,
		verifications: evidence.ArtifactVerificationSet{
			Host: hostVerification, Client: clientVerification, Session: sessionVerification,
		},
		policy:      policy,
		expected:    ExpectedCell{RouteID: RoutePhysicalWindowsRemote, ClientPlatform: "linux", ClientArchitecture: "amd64"},
		privateKeys: privateKeys,
	}
}

func newV2MacOSFixture(t testing.TB) v2Fixture {
	t.Helper()
	fixture := newV2Fixture(t)
	var host, client, session evidence.Record
	if err := json.Unmarshal(fixture.host, &host); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fixture.client, &client); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fixture.session, &session); err != nil {
		t.Fatal(err)
	}
	for _, record := range []*evidence.Record{&host, &client, &session} {
		record.RouteID = evidence.RoutePhysicalMacOSRemote
	}
	host.Subject.Platform = "macos"
	host.Subject.Architecture = "arm64"
	if err := evidence.Validate(host); err != nil {
		t.Fatalf("validate macOS host fixture: %v", err)
	}
	if err := evidence.Validate(client); err != nil {
		t.Fatalf("validate macOS client fixture: %v", err)
	}
	if err := evidence.Validate(session); err != nil {
		t.Fatalf("validate macOS session fixture: %v", err)
	}
	hostData := mustJSON(t, host)
	clientData := mustJSON(t, client)
	session.Bindings.HostRecordSHA256 = sha256Hex(hostData)
	session.Bindings.ClientRecordSHA256 = sha256Hex(clientData)
	sessionData := mustJSON(t, session)
	hostVerification, err := evidence.VerifyArtifactBundle(host, fixture.hostArtifacts)
	if err != nil {
		t.Fatal(err)
	}
	clientVerification, err := evidence.VerifyArtifactBundle(client, fixture.clientArtifacts)
	if err != nil {
		t.Fatal(err)
	}
	sessionVerification, err := evidence.VerifyArtifactBundle(session, fixture.sessionArtifacts)
	if err != nil {
		t.Fatal(err)
	}
	rawPolicy := cloneTrustPolicy(fixture.policy.policy)
	for index := range rawPolicy.Keys {
		rawPolicy.Keys[index].RouteIDs = []string{RoutePhysicalMacOSRemote}
	}
	policy, err := newTrustPolicy(rawPolicy)
	if err != nil {
		t.Fatalf("macOS fixture policy: %v", err)
	}
	var payloadValue payload
	if err := json.Unmarshal(fixture.payload, &payloadValue); err != nil {
		t.Fatal(err)
	}
	payloadValue.RouteID = RoutePhysicalMacOSRemote
	payloadValue.HostPlatform = "macos"
	payloadValue.HostArchitecture = "arm64"
	payloadValue.HostRecordSHA256 = sha256Hex(hostData)
	payloadValue.ClientRecordSHA256 = sha256Hex(clientData)
	payloadValue.SessionRecordSHA256 = sha256Hex(sessionData)
	payloadValue.PolicyID = policy.ID()
	payloadData := mustJSON(t, payloadValue)
	fixture.host, fixture.client, fixture.session, fixture.payload = hostData, clientData, sessionData, payloadData
	fixture.envelope = makeSignedEnvelope(t, payloadData, fixture.privateKeys, v2TestNow.Add(-time.Minute))
	fixture.verifications = evidence.ArtifactVerificationSet{Host: hostVerification, Client: clientVerification, Session: sessionVerification}
	fixture.policy = policy
	fixture.expected = ExpectedCell{RouteID: RoutePhysicalMacOSRemote, ClientPlatform: "linux", ClientArchitecture: "amd64"}
	return fixture
}

func rewriteV2FixtureRecords(t testing.TB, fixture v2Fixture, mutate func(host, client, session *evidence.Record)) v2Fixture {
	t.Helper()
	var host, client, session evidence.Record
	for _, item := range []struct {
		name string
		data []byte
		out  *evidence.Record
	}{
		{"host", fixture.host, &host},
		{"client", fixture.client, &client},
		{"session", fixture.session, &session},
	} {
		if err := json.Unmarshal(item.data, item.out); err != nil {
			t.Fatalf("decode %s fixture: %v", item.name, err)
		}
	}
	mutate(&host, &client, &session)

	hostData := mustJSON(t, host)
	clientData := mustJSON(t, client)
	session.Bindings.HostRecordSHA256 = sha256Hex(hostData)
	session.Bindings.ClientRecordSHA256 = sha256Hex(clientData)
	sessionData := mustJSON(t, session)

	hostVerification, err := evidence.VerifyArtifactBundle(host, fixture.hostArtifacts)
	if err != nil {
		t.Fatalf("reverify host artifacts: %v", err)
	}
	clientVerification, err := evidence.VerifyArtifactBundle(client, fixture.clientArtifacts)
	if err != nil {
		t.Fatalf("reverify client artifacts: %v", err)
	}
	sessionVerification, err := evidence.VerifyArtifactBundle(session, fixture.sessionArtifacts)
	if err != nil {
		t.Fatalf("reverify session artifacts: %v", err)
	}

	var payloadValue payload
	if err := json.Unmarshal(fixture.payload, &payloadValue); err != nil {
		t.Fatalf("decode payload fixture: %v", err)
	}
	payloadValue.HostRecordSHA256 = sha256Hex(hostData)
	payloadValue.ClientRecordSHA256 = sha256Hex(clientData)
	payloadValue.SessionRecordSHA256 = sha256Hex(sessionData)
	payloadData := mustJSON(t, payloadValue)

	fixture.host = hostData
	fixture.client = clientData
	fixture.session = sessionData
	fixture.payload = payloadData
	fixture.envelope = makeSignedEnvelope(t, payloadData, fixture.privateKeys, v2TestNow.Add(-time.Minute))
	fixture.verifications = evidence.ArtifactVerificationSet{
		Host: hostVerification, Client: clientVerification, Session: sessionVerification,
	}
	return fixture
}

func rewriteRecordTimestamps(t testing.TB, record *evidence.Record, offset time.Duration, fractional bool) {
	t.Helper()
	convert := func(value string) string {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			t.Fatalf("parse fixture timestamp %q: %v", value, err)
		}
		return formatRFC3339Variant(parsed, offset, fractional)
	}
	record.CreatedAt = convert(record.CreatedAt)
	record.ExpiresAt = convert(record.ExpiresAt)
	record.Attestation.ReviewedAt = convert(record.Attestation.ReviewedAt)
	for index := range record.Checks {
		record.Checks[index].ObservedAt = convert(record.Checks[index].ObservedAt)
	}
	if record.MeasurementMethodology != nil {
		record.MeasurementMethodology.CaptureStartedAt = convert(record.MeasurementMethodology.CaptureStartedAt)
		record.MeasurementMethodology.CaptureEndedAt = convert(record.MeasurementMethodology.CaptureEndedAt)
	}
}

func formatRFC3339Variant(value time.Time, offset time.Duration, fractional bool) string {
	zone := time.FixedZone("fixture-offset", int(offset/time.Second))
	if fractional {
		return value.In(zone).Format("2006-01-02T15:04:05.000Z07:00")
	}
	return value.In(zone).Format(time.RFC3339)
}

func deterministicTrustPolicy(t testing.TB) (TrustPolicy, map[string]ed25519.PrivateKey) {
	t.Helper()
	type identity struct {
		seed         byte
		principal    string
		organization string
		role         string
	}
	identities := []identity{
		{0x11, "fixture-lab-reviewer", "fixture-lab", roleLabObserver},
		{0x22, "fixture-independent-reviewer", "fixture-auditor", roleIndependentReviewer},
	}
	keys := make([]trustedKey, 0, len(identities))
	privateKeys := make(map[string]ed25519.PrivateKey, len(identities))
	for _, identity := range identities {
		privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{identity.seed}, ed25519.SeedSize))
		publicKey := privateKey.Public().(ed25519.PublicKey)
		keyID := deriveKeyID(publicKey)
		keys = append(keys, trustedKey{
			KeyID:           keyID,
			Algorithm:       Algorithm,
			PublicKey:       hex.EncodeToString(publicKey),
			PrincipalID:     identity.principal,
			OrganizationID:  identity.organization,
			Role:            identity.role,
			RouteIDs:        []string{RoutePhysicalWindowsRemote},
			ClientPlatforms: []string{"linux"},
			Architectures:   []string{"amd64"},
			TestProfileIDs:  []string{TestProfileRemotePlayV1},
			NotBefore:       v2TestNow.Add(-2 * time.Hour).Format(time.RFC3339),
			NotAfter:        v2TestNow.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		})
		privateKeys[keyID] = privateKey
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID < keys[j].KeyID })
	policy, err := newTrustPolicy(trustPolicy{
		Schema:                       TrustPolicySchemaID,
		SchemaVersion:                PolicyVersion,
		PolicyID:                     "fixture-reviewers-v1",
		Status:                       policyProvisioned,
		ValidFrom:                    v2TestNow.Add(-2 * time.Hour).Format(time.RFC3339),
		ExpiresAt:                    v2TestNow.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		RequiredRoles:                []string{roleLabObserver, roleIndependentReviewer},
		MinSignatures:                MinSignatures,
		RequireDistinctPrincipals:    true,
		RequireDistinctOrganizations: true,
		Keys:                         keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy, privateKeys
}

func makeSignedEnvelope(t testing.TB, payloadData []byte, privateKeys map[string]ed25519.PrivateKey, signedAt time.Time) []byte {
	t.Helper()
	timestamp := signedAt.UTC().Format(time.RFC3339)
	keyIDs := make([]string, 0, len(privateKeys))
	for keyID := range privateKeys {
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)
	signatures := make([]signature, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		preimage := signaturePreimage(PayloadType, keyID, timestamp, payloadData)
		signatures = append(signatures, signature{
			Algorithm: Algorithm,
			KeyID:     keyID,
			SignedAt:  timestamp,
			Signature: hex.EncodeToString(ed25519.Sign(privateKeys[keyID], preimage)),
		})
	}
	return mustJSON(t, signatureEnvelope{
		Schema:          EnvelopeSchemaID,
		EnvelopeVersion: EnvelopeVersion,
		PayloadType:     PayloadType,
		PayloadEncoding: PayloadEncoding,
		Payload:         base64.RawURLEncoding.EncodeToString(payloadData),
		Signatures:      signatures,
	})
}

func completeV1Record(t testing.TB, recordType evidence.RecordType, platform, runID, recordID string, createdAt time.Time) evidence.Record {
	t.Helper()
	record, err := evidence.NewTemplateWithRunID(recordType, platform, "amd64", "v2-test", runID, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	record.RecordID = recordID
	record.Subject.Environment = "redacted deterministic v2 fixture"
	reviewedAt := v2TestNow.Add(-50 * time.Minute)
	observedAt := v2TestNow.Add(-52 * time.Minute)
	level := evidence.AttestationLab
	if recordType == evidence.RecordSession {
		reviewedAt = v2TestNow.Add(-5 * time.Minute)
		observedAt = v2TestNow.Add(-10 * time.Minute)
		level = evidence.AttestationIndependent
	}
	record.Attestation = evidence.Attestation{
		Level: level, Reviewer: "fixture-reviewer", ReviewedAt: reviewedAt.Format(time.RFC3339),
		Artifacts: []evidence.Artifact{placeholderArtifact("review-bundle.json")}, Notes: "Deterministic fixture only.",
	}
	for index := range record.Checks {
		record.Checks[index].Status = evidence.StatusPass
		record.Checks[index].ObservedAt = observedAt.Format(time.RFC3339)
		record.Checks[index].Summary = "Observed deterministic fixture result."
		record.Checks[index].Artifacts = []evidence.Artifact{placeholderArtifact(record.Checks[index].ID + ".json")}
	}
	if record.Bindings != nil {
		record.Bindings.HostRecordSHA256 = strings.Repeat("a", 64)
		record.Bindings.ClientRecordSHA256 = strings.Repeat("b", 64)
		*record.StreamProfile = evidence.StreamProfile{Width: 1920, Height: 1080, TargetFrameRate: 60, Codec: "h264", Transport: "wired-lan"}
		*record.MeasurementMethodology = evidence.MeasurementMethodology{
			Version: evidence.SessionMetricsV1, CaptureStartedAt: v2TestNow.Add(-40 * time.Minute).Format(time.RFC3339),
			CaptureEndedAt: v2TestNow.Add(-10 * time.Minute).Format(time.RFC3339), SampleCount: 1800,
			CollectorID: "fixture-collector", CollectorVersion: "1.0.0", CaptureArtifactSHA256: strings.Repeat("0", 64),
		}
		setV1Measurement(&record, "session-duration", 1800)
		setV1Measurement(&record, "average-frame-rate", 60)
		setV1Measurement(&record, "encode-latency", 10)
		setV1Measurement(&record, "network-latency", 20)
		setV1Measurement(&record, "decode-latency", 10)
		setV1Measurement(&record, "end-to-end-latency", 50)
		setV1Measurement(&record, "dropped-frames", 0.2)
	}
	if err := evidence.Validate(record); err != nil {
		t.Fatalf("complete v1 fixture: %v", err)
	}
	return record
}

func placeholderArtifact(name string) evidence.Artifact {
	return evidence.Artifact{Name: name, SHA256: strings.Repeat("0", 64), SizeBytes: 1, MediaType: "application/json"}
}

func materializeV1Artifacts(t testing.TB, record *evidence.Record) string {
	t.Helper()
	directory := t.TempDir()
	write := func(artifact *evidence.Artifact) {
		data := []byte("deterministic artifact for " + artifact.Name + "\n")
		digest := sha256.Sum256(data)
		artifact.SHA256 = hex.EncodeToString(digest[:])
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
	if record.MeasurementMethodology != nil {
		for _, check := range record.Checks {
			if check.ID == "session.latency" {
				record.MeasurementMethodology.CaptureArtifactSHA256 = check.Artifacts[0].SHA256
			}
		}
	}
	if err := evidence.Validate(*record); err != nil {
		t.Fatalf("materialized v1 fixture: %v", err)
	}
	return directory
}

func setV1Measurement(record *evidence.Record, id string, value float64) {
	for index := range record.Measurements {
		if record.Measurements[index].ID == id {
			record.Measurements[index].Value = value
			return
		}
	}
}

func decodeEnvelope(t testing.TB, data []byte) signatureEnvelope {
	t.Helper()
	var envelope signatureEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func mustJSON(t testing.TB, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertErrorContains(t testing.TB, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v; want substring %q", err, want)
	}
}

func compileV2Schema(t testing.TB, name, schemaID string) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "schemas", name))
	if err != nil {
		t.Fatal(err)
	}
	var document any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(schemaID, document); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(schemaID)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}
