// Package reviewercrypto contains deterministic primitives shared by
// independently reviewed Ed25519 evidence envelopes. It does not define a
// trust policy or decide whether an observation proves physical hardware.
package reviewercrypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"
)

// ValidateEd25519PublicKey rejects encodings that crypto/ed25519 deliberately
// accepts for ecosystem compatibility but that are unsafe reviewer identities.
// In particular, a low-order key can admit signatures without knowledge of a
// private scalar, and a point with a torsion component is not a prime-subgroup
// identity even when its encoding is unique at the byte level.
func ValidateEd25519PublicKey(publicKey []byte) error {
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return errors.New("public_key must encode a valid Edwards25519 point")
	}
	if !bytes.Equal(point.Bytes(), publicKey) {
		return errors.New("public_key must use the canonical Edwards25519 encoding")
	}
	if point.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("public_key must not be the Edwards25519 identity")
	}

	// Decompose A = P + T into its prime-order and torsion components without
	// implementing curve arithmetic locally. Multiplication by eight removes T;
	// multiplying that result by 8^-1 modulo the prime subgroup order recovers P.
	// The original point is in the prime-order subgroup exactly when A == P.
	eightEncoding := make([]byte, ed25519.PublicKeySize)
	eightEncoding[0] = 8
	eight, err := new(edwards25519.Scalar).SetCanonicalBytes(eightEncoding)
	if err != nil {
		return errors.New("initialize Edwards25519 subgroup validation")
	}
	inverseEight := new(edwards25519.Scalar).Invert(eight)
	primeComponent := new(edwards25519.Point).ScalarMult(
		inverseEight,
		new(edwards25519.Point).MultByCofactor(point),
	)
	if point.Equal(primeComponent) != 1 {
		return errors.New("public_key must be in the prime-order Edwards25519 subgroup")
	}
	return nil
}

// SignaturePreimage prefixes a pinned, NUL-terminated application domain to
// four length-framed envelope fields. The caller owns and pins the domain and
// field semantics; this helper does not authenticate keys or evidence.
func SignaturePreimage(domain, payloadType, keyID, signedAt string, payloadBytes []byte) []byte {
	preimage := make([]byte, 0, len(domain)+32+len(payloadType)+len(keyID)+len(signedAt)+len(payloadBytes))
	preimage = append(preimage, domain...)
	preimage = appendLengthPrefixed(preimage, []byte(payloadType))
	preimage = appendLengthPrefixed(preimage, []byte(keyID))
	preimage = appendLengthPrefixed(preimage, []byte(signedAt))
	preimage = appendLengthPrefixed(preimage, payloadBytes)
	return preimage
}

func appendLengthPrefixed(destination, value []byte) []byte {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	destination = append(destination, length[:]...)
	return append(destination, value...)
}
