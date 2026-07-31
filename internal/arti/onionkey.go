package arti

// Onion service identity keys and addresses.
//
// A v3 onion address is just the service's ed25519 public key, a checksum and a
// version byte, base32-encoded. Callers that persist a service key need to turn
// it back into an address, and to sign with it, without depending on a Tor
// controller library - so those primitives live here.
//
// Private keys use the same 64-byte "expanded" representation as C tor's
// ED25519-V3 control-port blobs: the clamped scalar followed by the hash
// prefix. That is deliberately the format existing callers already have on
// disk, so a saved key keeps its address.

import (
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/base32"
	"fmt"
	"strings"
)

const (
	// PublicKeySize is the size of an onion service public key.
	PublicKeySize = ed25519.PublicKeySize
	// PrivateKeySize is the size of an expanded onion service private key.
	PrivateKeySize = 64
	// SignatureSize is the size of an ed25519 signature.
	SignatureSize = ed25519.SignatureSize

	// onionChecksumPrefix is the domain separator from rend-spec-v3 §6.
	onionChecksumPrefix = ".onion checksum"
	// onionVersion is the v3 onion address version byte.
	onionVersion = 0x03
)

// serviceIDEncoding is unpadded base32, which is what onion addresses use.
var serviceIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// OnionIDFromPublicKey returns the onion service ID for a public key.
//
// The result excludes the ".onion" suffix, matching what [OnionService.ID]
// reports.
func OnionIDFromPublicKey(key ed25519.PublicKey) (string, error) {
	if len(key) != PublicKeySize {
		return "", fmt.Errorf("arti: public key must be %d bytes, got %d", PublicKeySize, len(key))
	}
	var raw [35]byte
	copy(raw[:32], key)
	sum := onionChecksum(key)
	raw[32], raw[33] = sum[0], sum[1]
	raw[34] = onionVersion
	return strings.ToLower(serviceIDEncoding.EncodeToString(raw[:])), nil
}

// PublicKeyFromOnionID recovers the public key from an onion service ID.
//
// A ".onion" suffix is accepted and ignored. The checksum and version are
// verified, so a typo in an address is rejected here rather than becoming a
// signature failure later.
func PublicKeyFromOnionID(id string) (ed25519.PublicKey, error) {
	id = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(id)), ".onion")

	raw, err := serviceIDEncoding.DecodeString(strings.ToUpper(id))
	if err != nil {
		return nil, fmt.Errorf("arti: malformed onion id: %w", err)
	}
	if len(raw) != 35 {
		return nil, fmt.Errorf("arti: onion id decodes to %d bytes, want 35", len(raw))
	}
	if raw[34] != onionVersion {
		return nil, fmt.Errorf("arti: unsupported onion address version %d", raw[34])
	}

	key := ed25519.PublicKey(raw[:32])
	sum := onionChecksum(key)
	if raw[32] != sum[0] || raw[33] != sum[1] {
		return nil, fmt.Errorf("arti: onion id checksum mismatch")
	}
	return key, nil
}

// PublicKeyFromPrivate derives the public half of an expanded private key.
func PublicKeyFromPrivate(key []byte) (ed25519.PublicKey, error) {
	if len(key) != PrivateKeySize {
		return nil, fmt.Errorf("arti: private key must be %d bytes, got %d", PrivateKeySize, len(key))
	}
	return publicFromExpanded(key)
}

// Sign signs a message with an expanded onion service private key.
//
// [crypto/ed25519] cannot do this: its Sign takes a seed-derived key and
// re-expands it, whereas an onion service key is only ever available already
// expanded - for vanity addresses the scalar is chosen directly and no seed
// exists. The signature is produced by the same code Arti uses.
func Sign(key []byte, message []byte) ([]byte, error) {
	if len(key) != PrivateKeySize {
		return nil, fmt.Errorf("arti: private key must be %d bytes, got %d", PrivateKeySize, len(key))
	}
	return signExpanded(key, message)
}

// Verify reports whether sig is a valid signature of message by key.
func Verify(key ed25519.PublicKey, message, sig []byte) bool {
	if len(key) != PublicKeySize || len(sig) != SignatureSize {
		return false
	}
	return ed25519.Verify(key, message, sig)
}

// onionChecksum computes the two checksum bytes of a v3 onion address.
func onionChecksum(key ed25519.PublicKey) [2]byte {
	h := sha3.New256()
	h.Write([]byte(onionChecksumPrefix))
	h.Write(key)
	h.Write([]byte{onionVersion})
	var out [2]byte
	copy(out[:], h.Sum(nil))
	return out
}
