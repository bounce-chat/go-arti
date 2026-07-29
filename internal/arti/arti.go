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

// encodeJSON renders a value for the FFI boundary.
func encodeJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("arti: cannot encode %T: %w", v, err)
	}
	return string(raw), nil
}
