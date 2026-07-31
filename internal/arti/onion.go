package arti

// Onion services, presented as ordinary net.Listeners.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
)

// OnionConfig describes an onion service to publish.
type OnionConfig struct {
	// PrivateKey is the service identity. A nil key generates a new one,
	// which [OnionService.PrivateKey] then reports so it can be persisted.
	//
	// The format is the 64-byte expanded ed25519 secret used by C Tor's
	// ED25519-V3 control blobs, which is what existing callers have on disk.
	PrivateKey []byte

	// Ports are the virtual ports the service answers on. If empty, port 80
	// is published.
	Ports []int

	// NoWait returns as soon as the service is registered, rather than waiting
	// for it to become reachable.
	//
	// This is usually what you want. The returned listener accepts as soon as
	// it exists - connections simply do not arrive until the service is
	// published - whereas waiting can take minutes for reasons unrelated to
	// whether the descriptor is up. See [OnionService.WaitPublished].
	NoWait bool
}

// OnionService is a published onion service. It implements [net.Listener].
type OnionService struct {
	client     *Client
	id         string
	privateKey []byte
	ports      []int

	// local receives connections that Arti forwards to us.
	local net.Listener

	// published is closed once the service is reachable, or carries the
	// reason it failed.
	publishOnce sync.Once
	published   chan struct{}
	publishErr  error

	closeOnce sync.Once
}

// Listen publishes an onion service.
//
// Unless NoWait is set, this blocks until the service is reachable or ctx is
// done. The returned listener accepts connections made to the onion address.
func (c *Client) Listen(ctx context.Context, cfg OnionConfig) (*OnionService, error) {
	// An onion service needs a bootstrapped client; do it here rather than
	// failing deep inside Arti with a less obvious error.
	if err := c.Bootstrap(ctx); err != nil {
		return nil, err
	}

	ports := cfg.Ports
	if len(ports) == 0 {
		ports = []int{80}
	}

	// Arti forwards rendezvous connections to a local address. Binding port 0
	// on loopback keeps that detail out of the caller's way.
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("arti: cannot create local listener: %w", err)
	}
	localAddr := local.Addr().String()

	req := onionAddRequest{KeyType: "NEW", KeyBlob: "ED25519-V3"}
	if cfg.PrivateKey != nil {
		if len(cfg.PrivateKey) != PrivateKeySize {
			local.Close()
			return nil, fmt.Errorf("arti: private key must be %d bytes, got %d",
				PrivateKeySize, len(cfg.PrivateKey))
		}
		req.KeyType = "ED25519-V3"
		req.KeyBlob = base64.StdEncoding.EncodeToString(cfg.PrivateKey)
	}
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			local.Close()
			return nil, fmt.Errorf("arti: invalid virtual port %d", port)
		}
		req.Ports = append(req.Ports, onionPort{
			VirtualPort: uint16(port),
			Target:      localAddr,
		})
	}

	svc := &OnionService{
		client:    c,
		ports:     ports,
		local:     local,
		published: make(chan struct{}),
	}

	// Register before launching: publication can complete before the call
	// returns, and the event has to find a service to deliver to.
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		local.Close()
		return nil, errors.New("arti: client is closed")
	}
	pending := c.onions
	c.mu.Unlock()

	resp, err := c.backend.OnionAdd(req)
	if err != nil {
		local.Close()
		return nil, err
	}

	svc.id = resp.ServiceID
	if resp.SecretKey != "" {
		key, decodeErr := base64.StdEncoding.DecodeString(resp.SecretKey)
		if decodeErr != nil {
			local.Close()
			return nil, fmt.Errorf("arti: malformed key in response: %w", decodeErr)
		}
		svc.privateKey = key
	} else {
		svc.privateKey = cfg.PrivateKey
	}

	c.mu.Lock()
	pending[svc.id] = svc
	c.mu.Unlock()

	if cfg.NoWait {
		return svc, nil
	}
	if err := svc.WaitPublished(ctx); err != nil {
		svc.Close()
		return nil, err
	}
	return svc, nil
}

// WaitPublished blocks until Arti believes the service is fully reachable, or
// ctx is done.
//
// This is a stronger condition than "a descriptor has been uploaded", and can
// lag it by minutes. Arti aggregates its introduction point manager and its
// publisher into a single status and reports neither separately, so a service
// whose descriptor is up still reports as bootstrapping until the introduction
// points are settled. There is no public API for the publisher alone.
//
// Because of that, this is best used for reporting rather than gating: a
// service is accept-ready as soon as [Client.Listen] returns.
func (s *OnionService) WaitPublished(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("arti: publishing %s: %w", s.id, ctx.Err())
	case <-s.client.done:
		return errors.New("arti: client closed while publishing")
	case <-s.published:
		return s.publishErr
	}
}

// handleDescEvent records publication progress reported by the backend.
func (s *OnionService) handleDescEvent(ev *artiEvent) {
	switch ev.Action {
	case "UPLOADED":
		s.publishOnce.Do(func() { close(s.published) })
	case "FAILED":
		s.publishOnce.Do(func() {
			s.publishErr = fmt.Errorf("arti: onion service %s failed to publish: %s",
				s.id, ev.Reason)
			close(s.published)
		})
	}
}

// ID returns the service address, without the ".onion" suffix.
func (s *OnionService) ID() string { return s.id }

// PrivateKey returns the service identity key, for persisting.
//
// The 64-byte expanded format matches what C Tor controllers use, so a key
// saved by an older build is accepted by [Client.Listen] unchanged.
func (s *OnionService) PrivateKey() []byte { return s.privateKey }

// PublicKey returns the service identity public key.
func (s *OnionService) PublicKey() (ed25519.PublicKey, error) {
	return PublicKeyFromOnionID(s.id)
}

// Accept implements [net.Listener].
func (s *OnionService) Accept() (net.Conn, error) { return s.local.Accept() }

// Addr implements [net.Listener], reporting the onion address.
func (s *OnionService) Addr() net.Addr { return onionAddr{id: s.id, port: s.ports[0]} }

// Close unpublishes the service and stops accepting connections.
func (s *OnionService) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.client.mu.Lock()
		delete(s.client.onions, s.id)
		s.client.mu.Unlock()

		// Unpublish first, so no new connections arrive while we tear the
		// local listener down.
		if delErr := s.client.backend.OnionDel(s.id); delErr != nil && !errors.Is(delErr, errClosed) {
			err = delErr
		}
		if closeErr := s.local.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	})
	return err
}

// closeLocal tears down the local listener without touching the backend, for
// use when the client itself is going away.
func (s *OnionService) closeLocal() {
	s.closeOnce.Do(func() { s.local.Close() })
}

// onionAddr is the net.Addr of an onion service.
type onionAddr struct {
	id   string
	port int
}

// Network implements [net.Addr].
func (onionAddr) Network() string { return "tcp" }

// String implements [net.Addr].
func (a onionAddr) String() string { return fmt.Sprintf("%s.onion:%d", a.id, a.port) }
