// Package arti is a self-contained Tor library backed by Arti, the Tor
// Project's Rust implementation.
//
// The primary interface is [Open], which returns a [Client] speaking to Arti
// directly: bootstrap is a call, connectivity is an event stream, and onion
// services are [net.Listener]s.
//
//	client, err := arti.Open(arti.Config{DataDir: dir})
//	defer client.Close()
//	if err := client.Bootstrap(ctx); err != nil { ... }
//
//	svc, err := client.Listen(ctx, arti.OnionConfig{Ports: []int{80}})
//	http.Serve(svc, handler)
//
//	conn, err := client.DialContext(ctx, "tcp", "example.onion:80")
package arti

// The implementation lives in internal/arti; it is aliased here because this
// package shares its name.
import (
	"crypto/ed25519"

	backend "github.com/bounce-chat/go-arti/internal/arti"
)

// Client is a running Tor client. See [Open].
type Client = backend.Client

// Config describes a Tor client. See [Open].
type Config = backend.Config

// Status describes how far along a [Client] is.
type Status = backend.Status

// OnionConfig describes an onion service to publish.
type OnionConfig = backend.OnionConfig

// OnionService is a published onion service, and a [net.Listener].
type OnionService = backend.OnionService

// LogRecord is one message from Arti. See [EnableLogging].
type LogRecord = backend.LogRecord

// EnableLogging starts collecting Arti's log records and returns a channel of
// them, for routing into an application's logger.
//
// The level is a tracing EnvFilter directive, such as "info" or
// "info,tor_dirmgr=debug". This affects the whole process rather than a single
// [Client], because Arti permits one log subscriber. Records are dropped
// rather than queued for a consumer that falls behind.
func EnableLogging(level string) (<-chan LogRecord, error) {
	return backend.EnableLogging(level)
}

// StopLogging stops collecting Arti's log records and closes every channel
// returned by [EnableLogging].
func StopLogging() { backend.StopLogging() }

// Open creates a Tor client without touching the network.
func Open(cfg Config) (*Client, error) { return backend.Open(cfg) }

// OnionIDFromPublicKey returns the onion service ID for a public key, without
// the ".onion" suffix.
func OnionIDFromPublicKey(key ed25519.PublicKey) (string, error) {
	return backend.OnionIDFromPublicKey(key)
}

// PublicKeyFromOnionID recovers the public key from an onion service ID.
//
// A ".onion" suffix is accepted and ignored. The checksum is verified, so a
// mistyped address is rejected here rather than becoming a signature failure
// later.
func PublicKeyFromOnionID(id string) (ed25519.PublicKey, error) {
	return backend.PublicKeyFromOnionID(id)
}

// PublicKeyFromPrivate derives the public half of an expanded private key.
//
// This is how a caller derives its own address with no client running.
func PublicKeyFromPrivate(key []byte) (ed25519.PublicKey, error) {
	return backend.PublicKeyFromPrivate(key)
}

// Sign signs a message with an expanded onion service private key.
//
// [crypto/ed25519] cannot do this: its Sign expects a seed-derived key, while
// an onion service key is only ever available already expanded.
func Sign(key []byte, message []byte) ([]byte, error) {
	return backend.Sign(key, message)
}

// Verify reports whether sig is a valid signature of message by key.
func Verify(key ed25519.PublicKey, message, sig []byte) bool {
	return backend.Verify(key, message, sig)
}

// Sizes of the key material used by onion services.
const (
	PublicKeySize  = backend.PublicKeySize
	PrivateKeySize = backend.PrivateKeySize
	SignatureSize  = backend.SignatureSize
)

// ProviderVersion returns the Tor provider name and version, e.g. "Arti 0.45".
func ProviderVersion() string {
	return backend.ProviderVersion()
}
