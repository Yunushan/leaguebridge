package evidencev2

import (
	"strings"
	"testing"
	"time"
)

func TestPromoteRemoteSetAtDerivesWindowsRemoteCell(t *testing.T) {
	fixture := newV2Fixture(t)
	verified, err := VerifySetAt(fixture.envelope, fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
	if err != nil {
		t.Fatal(err)
	}

	promotion, err := PromoteRemoteSetAt(verified, v2TestNow)
	if err != nil {
		t.Fatal(err)
	}
	if promotion.Schema != ReadinessPromotionSchemaID || promotion.SchemaVersion != ReadinessPromotionVersion || promotion.EvidenceType != ReadinessPromotionType {
		t.Fatalf("unexpected promotion identity: %+v", promotion)
	}
	if promotion.RouteID != RoutePhysicalWindowsRemote || promotion.HostPlatform != "windows" || promotion.HostArchitecture != "amd64" || promotion.ClientPlatform != "linux" || promotion.ClientArchitecture != "amd64" {
		t.Fatalf("unexpected Windows route cell: %+v", promotion)
	}
	if promotion.Score != 100 || promotion.State != ReadinessPromotionState || !promotion.PromotionSafe || promotion.PromotionBoundary != ReadinessPromotionBoundary {
		t.Fatalf("unexpected promotion state: %+v", promotion)
	}
	if len(promotion.Gates) != 4 {
		t.Fatalf("gate count = %d, want 4", len(promotion.Gates))
	}
	for index, gate := range promotion.Gates {
		if gate.ID != readinessGateIDs[index] || gate.Weight != ReadinessGateWeight || !gate.Passed {
			t.Fatalf("gate %d = %+v", index, gate)
		}
	}
	if promotion.PayloadSHA256 != verified.PayloadSHA256() || promotion.SessionRecordSHA256 != verified.SessionRecordSHA256() {
		t.Fatal("promotion did not retain proof digest bindings")
	}
	if len(promotion.SignerKeyIDs) != 2 || len(promotion.SignerPrincipalIDs) != 2 || len(promotion.SignerOrganizationIDs) != 2 {
		t.Fatalf("promotion signer metadata = %+v", promotion)
	}

	promotion.SignerKeyIDs[0] = "mutated"
	promotionAgain, err := PromoteRemoteSetAt(verified, v2TestNow)
	if err != nil {
		t.Fatal(err)
	}
	if promotionAgain.SignerKeyIDs[0] == "mutated" {
		t.Fatal("promotion exposed mutable proof signer state")
	}
}

func TestPromoteRemoteSetAtDerivesMacOSRemoteCell(t *testing.T) {
	fixture := newV2MacOSFixture(t)
	verified, err := VerifySetAt(fixture.envelope, fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
	if err != nil {
		t.Fatal(err)
	}

	promotion, err := PromoteRemoteSetAt(verified, v2TestNow)
	if err != nil {
		t.Fatal(err)
	}
	if promotion.RouteID != RoutePhysicalMacOSRemote || promotion.HostPlatform != "macos" || promotion.HostArchitecture != "arm64" {
		t.Fatalf("unexpected macOS route cell: %+v", promotion)
	}
	if promotion.Score != 100 || !promotion.PromotionSafe || len(promotion.Gates) != 4 {
		t.Fatalf("unexpected macOS promotion: %+v", promotion)
	}
}

func TestPromoteRemoteSetAtRejectsInvalidOrExpiredProofs(t *testing.T) {
	if _, err := PromoteRemoteSetAt(VerifiedSet{}, v2TestNow); err == nil || !strings.Contains(err.Error(), "valid authenticated") {
		t.Fatalf("zero proof error = %v", err)
	}

	fixture := newV2Fixture(t)
	verified, err := VerifySetAt(fixture.envelope, fixture.host, fixture.client, fixture.session, fixture.expected, fixture.verifications, fixture.policy, v2TestNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PromoteRemoteSetAt(verified, verified.CreatedAt().Add(-time.Second)); err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("future promotion error = %v", err)
	}
	if _, err := PromoteRemoteSetAt(verified, verified.ExpiresAt()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired promotion error = %v", err)
	}
}
