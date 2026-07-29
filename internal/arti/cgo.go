package arti

// cgo bindings for the static Arti library built from rust/arti-ffi.
//
// The link flags point at the archives under lib/<goos>_<goarch>/ at the
// repository root, two levels up from this package.
// Run `make lib` to (re)build one for the host; see the README for the
// cross-compilation matrix.
//
// Windows must be built for the *-pc-windows-gnu targets: cgo links with
// MinGW, so an MSVC-target .lib will not resolve here.
//
// The `!android` and `!ios` exclusions are load-bearing rather than tidiness:
// Go sets the `linux` build tag for GOOS=android and the `darwin` tag for
// GOOS=ios, so without them an Android build would silently link the glibc
// archive, and an iOS build the macOS one.

/*
#cgo CFLAGS: -I${SRCDIR}

#cgo linux,amd64,!android  LDFLAGS: -L${SRCDIR}/../../lib/linux_amd64
#cgo linux,arm64,!android  LDFLAGS: -L${SRCDIR}/../../lib/linux_arm64
#cgo darwin,amd64,!ios     LDFLAGS: -L${SRCDIR}/../../lib/darwin_amd64
#cgo darwin,arm64,!ios     LDFLAGS: -L${SRCDIR}/../../lib/darwin_arm64
#cgo windows,amd64         LDFLAGS: -L${SRCDIR}/../../lib/windows_amd64
#cgo android,arm64         LDFLAGS: -L${SRCDIR}/../../lib/android_arm64
#cgo android,arm           LDFLAGS: -L${SRCDIR}/../../lib/android_arm
#cgo android,amd64         LDFLAGS: -L${SRCDIR}/../../lib/android_amd64
#cgo android,386           LDFLAGS: -L${SRCDIR}/../../lib/android_386
#cgo ios,arm64             LDFLAGS: -L${SRCDIR}/../../lib/ios_arm64

#cgo linux,!android LDFLAGS: -larti_ffi -lm -ldl -lpthread
// Bionic folds libpthread and librt into libc, and has no -lpthread to link.
#cgo android        LDFLAGS: -larti_ffi -lm -ldl -llog
#cgo darwin,!ios    LDFLAGS: -larti_ffi -framework CoreFoundation -framework Security
#cgo ios            LDFLAGS: -larti_ffi -framework CoreFoundation -framework Security
#cgo windows        LDFLAGS: -larti_ffi -lws2_32 -luserenv -lbcrypt -lntdll -ladvapi32 -lcrypt32 -lsecur32

#include <stdlib.h>
#include "arti_ffi.h"
*/
import "C"

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

// artiClient is a handle on the Rust-side client. It implements backend.
//
// The handle is guarded because it outlives a single goroutine: the control
// server calls into it (SIGNAL HALT) while Wait is free to release it. Every
// call therefore holds the lock for its duration, so a freed handle can never
// be passed back across the FFI boundary.
type artiClient struct {
	mu     sync.RWMutex
	handle *C.arti_client_t
}

// errClosed is returned once the client has been released.
var errClosed = errors.New("tor client is closed")

// providerVersion returns the Arti version this binary was linked against.
func providerVersion() string {
	return C.GoString(C.arti_version())
}

// newArtiClient creates a client from the JSON configuration blob.
func newArtiClient(configJSON string) (*artiClient, error) {
	cfg := C.CString(configJSON)
	defer C.free(unsafe.Pointer(cfg))

	var cerr *C.char
	handle := C.arti_client_new(cfg, &cerr)
	if handle == nil {
		return nil, takeErr(cerr, "failed to create tor client")
	}
	c := &artiClient{handle: handle}
	// A caller that drops the process without closing it should not leak the
	// Rust-side client and its runtime threads.
	runtime.SetFinalizer(c, func(c *artiClient) { c.free() })
	return c, nil
}

// start brings up the listeners and background tasks. It does not block.
func (c *artiClient) start() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.handle == nil {
		return errClosed
	}
	var cerr *C.char
	if C.arti_client_start(c.handle, &cerr) != 0 {
		return takeErr(cerr, "failed to start tor")
	}
	return nil
}

// wait blocks until the client shuts down.
//
// This holds the read lock for as long as it blocks, which is what keeps free
// from running underneath it.
//
// That relies on an ordering embeddedProcess enforces: free is only called
// after wait has returned. Calling free while wait is in flight would deadlock,
// because Go's RWMutex gives a waiting writer priority and would then also
// block the Shutdown that wait is waiting for.
func (c *artiClient) wait() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.handle == nil {
		return
	}
	C.arti_client_wait(c.handle)
}

// Shutdown asks the client to stop, unblocking wait.
func (c *artiClient) Shutdown() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.handle == nil {
		return
	}
	C.arti_client_shutdown(c.handle)
}

// free releases the handle. It is idempotent.
func (c *artiClient) free() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handle != nil {
		C.arti_client_free(c.handle)
		c.handle = nil
	}
	runtime.SetFinalizer(c, nil)
}

// Version implements backend.
func (c *artiClient) Version() string { return providerVersion() }

// BootstrapStatus implements backend.
func (c *artiClient) BootstrapStatus() (bootstrapStatus, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var status bootstrapStatus
	if c.handle == nil {
		return status, errClosed
	}
	raw := takeString(C.arti_bootstrap_status(c.handle))
	if raw == "" {
		return status, errors.New("no bootstrap status available")
	}
	if err := json.Unmarshal([]byte(raw), &status); err != nil {
		return status, fmt.Errorf("malformed bootstrap status: %w", err)
	}
	return status, nil
}

// SetNetworkEnabled implements backend.
func (c *artiClient) SetNetworkEnabled(enabled bool) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.handle == nil {
		return errClosed
	}
	var flag C.int
	if enabled {
		flag = 1
	}
	var cerr *C.char
	if C.arti_set_network_enabled(c.handle, flag, &cerr) != 0 {
		return takeErr(cerr, "failed to change network state")
	}
	return nil
}

// NetworkEnabled implements backend.
func (c *artiClient) NetworkEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.handle == nil {
		return false
	}
	return C.arti_network_enabled(c.handle) == 1
}

// SocksAddr implements backend.
func (c *artiClient) SocksAddr() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.handle == nil {
		return ""
	}
	return takeString(C.arti_socks_addr(c.handle))
}

// OnionAdd implements backend.
func (c *artiClient) OnionAdd(req onionAddRequest) (onionAddResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var resp onionAddResponse
	if c.handle == nil {
		return resp, errClosed
	}

	encoded, err := json.Marshal(req)
	if err != nil {
		return resp, fmt.Errorf("cannot encode onion request: %w", err)
	}
	creq := C.CString(string(encoded))
	defer C.free(unsafe.Pointer(creq))

	var cerr *C.char
	raw := takeString(C.arti_onion_add(c.handle, creq, &cerr))
	if raw == "" {
		return resp, takeErr(cerr, "failed to create onion service")
	}
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return resp, fmt.Errorf("malformed onion response: %w", err)
	}
	return resp, nil
}

// OnionDel implements backend.
func (c *artiClient) OnionDel(serviceID string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.handle == nil {
		return errClosed
	}
	cid := C.CString(serviceID)
	defer C.free(unsafe.Pointer(cid))

	var cerr *C.char
	if C.arti_onion_del(c.handle, cid, &cerr) != 0 {
		return takeErr(cerr, "failed to remove onion service")
	}
	return nil
}

// NextEvent implements backend.
func (c *artiClient) NextEvent(timeout time.Duration) (*artiEvent, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.handle == nil {
		return nil, errClosed
	}
	ms := timeout.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	raw := takeString(C.arti_next_event(c.handle, C.int(ms)))
	if raw == "" {
		return nil, nil
	}
	var ev artiEvent
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		return nil, fmt.Errorf("malformed event: %w", err)
	}
	return &ev, nil
}

// takeString converts an owned C string to Go and frees it.
func takeString(s *C.char) string {
	if s == nil {
		return ""
	}
	defer C.arti_string_free(s)
	return C.GoString(s)
}

// takeErr builds an error from an owned C string, falling back to fallback if
// the library did not supply a message.
func takeErr(cerr *C.char, fallback string) error {
	if msg := takeString(cerr); msg != "" {
		return errors.New(msg)
	}
	return errors.New(fallback)
}

// publicFromExpanded derives the public key for an expanded secret key.
func publicFromExpanded(secret []byte) (ed25519.PublicKey, error) {
	out := make([]byte, PublicKeySize)
	rc := C.arti_public_key(
		(*C.uchar)(unsafe.Pointer(&secret[0])),
		C.size_t(len(secret)),
		(*C.uchar)(unsafe.Pointer(&out[0])),
	)
	if rc != 0 {
		return nil, errors.New("arti: not a valid ed25519 secret key")
	}
	return ed25519.PublicKey(out), nil
}

// signExpanded signs a message with an expanded secret key.
func signExpanded(secret, message []byte) ([]byte, error) {
	// from_raw_parts needs a non-null pointer even for an empty message.
	msgPtr := (*C.uchar)(nil)
	if len(message) > 0 {
		msgPtr = (*C.uchar)(unsafe.Pointer(&message[0]))
	} else {
		msgPtr = (*C.uchar)(unsafe.Pointer(&emptyMessage[0]))
	}

	out := make([]byte, SignatureSize)
	rc := C.arti_sign(
		(*C.uchar)(unsafe.Pointer(&secret[0])),
		C.size_t(len(secret)),
		msgPtr,
		C.size_t(len(message)),
		(*C.uchar)(unsafe.Pointer(&out[0])),
	)
	if rc != 0 {
		return nil, errors.New("arti: not a valid ed25519 secret key")
	}
	return out, nil
}

// emptyMessage backs the pointer handed across for a zero-length message.
var emptyMessage = [1]byte{}

// enableLogging installs Arti's log subscriber at the given filter.
func enableLogging(directives string) error {
	cdir := C.CString(directives)
	defer C.free(unsafe.Pointer(cdir))

	if C.arti_log_enable(cdir) != 0 {
		return errors.New("arti: a log subscriber is already installed")
	}
	return nil
}

// nextLogRecord waits up to timeout for the next log record.
func nextLogRecord(timeout time.Duration) (*LogRecord, error) {
	ms := timeout.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	raw := takeString(C.arti_next_log(C.int(ms)))
	if raw == "" {
		return nil, nil
	}
	var record LogRecord
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		return nil, fmt.Errorf("arti: malformed log record: %w", err)
	}
	return &record, nil
}
