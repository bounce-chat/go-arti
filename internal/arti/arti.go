// Package arti implements the Tor client exposed by the root package.
//
// It holds the cgo boundary and everything that crosses it. The root package
// re-exports the parts that are public API; nothing else should import this
// directly, which is what keeping it under internal/ enforces.
package arti

import (
	"encoding/json"
	"fmt"
)

// ProviderVersion returns the Tor provider name and version.
func ProviderVersion() string {
	return providerVersion()
}

// RustFingerprint reports which Rust sources the linked libarti_ffi.a was
// built from. `make stamp` generates the value; see libstamp.go.
//
// This accessor is load-bearing, not decoration. Go does not hash the static
// library named in #cgo LDFLAGS, so rewriting the fingerprint is what forces a
// relink after `make lib` - but only if something refers to it. An
// unreferenced constant is never emitted into the package object, so the
// object stays byte-identical whatever the fingerprint says and the stale
// binary is reused anyway. Keep this reference, and keep it in a hand-written
// file so that regenerating libstamp.go cannot remove it.
func RustFingerprint() string {
	return rustFingerprint
}

// encodeJSON renders a value for the FFI boundary.
func encodeJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("arti: cannot encode %T: %w", v, err)
	}
	return string(raw), nil
}
