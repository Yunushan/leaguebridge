package reviewercrypto

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"filippo.io/edwards25519"
)

func TestValidateEd25519PublicKeyRejectsUnsafeReviewerIdentities(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	validPublicKey := privateKey.Public().(ed25519.PublicKey)
	if err := ValidateEd25519PublicKey(validPublicKey); err != nil {
		t.Fatalf("standard-library public key rejected: %v", err)
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
		name string
		key  []byte
		want string
	}{
		{"short encoding", []byte{1}, "valid Edwards25519 point"},
		{"identity", identity, "identity"},
		{"order-four encoding", orderFour, "prime-order"},
		{"non-canonical identity", nonCanonicalIdentity, "canonical"},
		{"prime point with torsion", mixedOrder, "prime-order"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateEd25519PublicKey(test.key); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateEd25519PublicKey error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestSignaturePreimageMatchesExistingEvidenceV2Bytes(t *testing.T) {
	const domain = "LeagueBridge/validation-evidence-set/v2\x00"
	got := SignaturePreimage(domain, "p", "k", "t", []byte{0x00, 0xff})
	want := append([]byte(domain),
		0, 0, 0, 0, 0, 0, 0, 1, 'p',
		0, 0, 0, 0, 0, 0, 0, 1, 'k',
		0, 0, 0, 0, 0, 0, 0, 1, 't',
		0, 0, 0, 0, 0, 0, 0, 2, 0x00, 0xff,
	)
	if !bytes.Equal(got, want) {
		t.Fatalf("preimage = %x; want %x", got, want)
	}
	if bytes.Equal(SignaturePreimage(domain, "ab", "c", "t", nil), SignaturePreimage(domain, "a", "bc", "t", nil)) {
		t.Fatal("length framing did not distinguish adjacent fields")
	}
	if bytes.Equal(SignaturePreimage(domain, "p", "k", "t", nil), SignaturePreimage("LeagueBridge/physical-bsd/v1\x00", "p", "k", "t", nil)) {
		t.Fatal("distinct domains produced an identical preimage")
	}
}
