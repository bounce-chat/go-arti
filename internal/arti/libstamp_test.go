package arti

import "testing"

// TestRustFingerprintIsUsed guards the one property that makes `make stamp`
// work at all.
//
// The fingerprint forces a relink after `make lib` by changing this package's
// source. That only has an effect if something references the constant: Go does
// not emit an unreferenced constant into the package object, so the object —
// and therefore the link action ID, and therefore the binary — stays identical
// no matter what the fingerprint says. The mechanism silently did nothing until
// RustFingerprint() existed.
//
// So this test is not checking a value. It exists so that deleting the
// accessor as "unused" breaks the build instead of quietly reintroducing stale
// binaries that disagree with the library they were linked against.
func TestRustFingerprintIsUsed(t *testing.T) {
	if RustFingerprint() == "" {
		t.Fatal("rustFingerprint is empty: run `make stamp`")
	}
}
