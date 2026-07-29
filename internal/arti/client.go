package arti

// The Arti client.
//
// This talks to Arti on its own terms — bootstrap as a call, connectivity as
// an event stream, onion services as net.Listeners — rather than translating
// through a control protocol Arti does not have.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// eventPumpInterval bounds how long a single poll of the backend blocks, so
// closing the client stays responsive.
const eventPumpInterval = 250 * time.Millisecond

// statusBuffer is how many status updates a slow subscriber may fall behind
// before the oldest are discarded. Only the newest matters, so this is small.
const statusBuffer = 8

// Config describes a Tor client.
type Config struct {
	// DataDir is where Arti keeps its state and directory cache. Required.
	//
	// It is created if missing, with owner-only permissions. Arti refuses to
	// use a directory that others can write to.
	DataDir string

	// SocksPort is the port for the SOCKS listener that backs DialContext.
	// Zero picks a free port, which is almost always what you want. It is
	// bound on the loopback interface only.
	SocksPort int

	// Bridges are torrc-style bridge lines. Setting any enables bridge use.
	Bridges []string
}

// Status describes how far along the client is.
type Status struct {
	// Progress is bootstrap completion, 0-100.
	Progress int

	// Ready reports whether the client has bootstrapped far enough to carry
	// traffic.
	//
	// It does not retract. Arti derives it from timestamps that tor-chanmgr
	// writes on success and never clears, so once bootstrap has succeeded this
	// stays true for the life of the process even if the device loses its
	// network. Treat it as "has connected", not "is connected": there is
	// currently no equivalent of C tor's NETWORK_LIVENESS.
	Ready bool

	// Summary is a human-readable description of the current phase.
	Summary string

	// Problem describes why the client is stuck, if it is.
	Problem string
}

// Client is a running Tor client.
type Client struct {
	backend *artiClient

	// mu guards the subscriber list and closed.
	mu          sync.Mutex
	subscribers []chan Status
	onions      map[string]*OnionService
	closed      bool

	// status caches the most recent status for Status().
	status   Status
	statusMu sync.RWMutex

	// dialer is built lazily, once a SOCKS address is known.
	dialerOnce sync.Once
	dialer     proxy.Dialer
	dialerErr  error

	// done is closed when the client shuts down, stopping the event pump.
	done chan struct{}
}

// Open creates a Tor client without touching the network.
//
// Call [Client.Bootstrap] to connect. Separating the two lets a caller show
// progress, and makes the expensive step explicitly cancellable.
func Open(cfg Config) (*Client, error) {
	if cfg.DataDir == "" {
		return nil, errors.New("arti: DataDir is required")
	}

	socks := "auto"
	if cfg.SocksPort > 0 {
		socks = strconv.Itoa(cfg.SocksPort)
	}
	bridges := cfg.Bridges
	if bridges == nil {
		bridges = []string{}
	}

	encoded, err := artiConfig{
		DataDirectory:    cfg.DataDir,
		SocksPort:        socks,
		SocksBindAddress: "127.0.0.1",
		// Bootstrapping is what Bootstrap is for.
		DisableNetwork: true,
		UseBridges:     len(bridges) > 0,
		Bridges:        bridges,
	}.encode()
	if err != nil {
		return nil, err
	}

	backend, err := newArtiClient(encoded)
	if err != nil {
		return nil, err
	}
	if err := backend.start(); err != nil {
		backend.free()
		return nil, err
	}

	c := &Client{
		backend: backend,
		onions:  make(map[string]*OnionService),
		done:    make(chan struct{}),
	}
	go c.pumpEvents()
	return c, nil
}

// Bootstrap connects to the Tor network and blocks until the client can carry
// traffic, or until ctx is done.
//
// It is safe to call more than once; later calls return as soon as the client
// is ready.
func (c *Client) Bootstrap(ctx context.Context) error {
	if err := c.backend.SetNetworkEnabled(true); err != nil {
		return err
	}

	// Subscribe before checking, so a client that becomes ready between the
	// two does not leave us waiting for an update that already happened.
	updates := c.StatusUpdates()
	defer c.unsubscribe(updates)

	if c.Status().Ready {
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("arti: bootstrap: %w", ctx.Err())
		case <-c.done:
			return errors.New("arti: client closed during bootstrap")
		case st, ok := <-updates:
			if !ok {
				return errors.New("arti: client closed during bootstrap")
			}
			if st.Ready {
				return nil
			}
		}
	}
}

// Status returns the most recent status.
func (c *Client) Status() Status {
	c.statusMu.RLock()
	cached := c.status
	c.statusMu.RUnlock()

	// Before the first event arrives there is nothing cached, so ask directly.
	if cached.Summary == "" {
		if st, err := c.backend.BootstrapStatus(); err == nil {
			return statusFrom(st)
		}
	}
	return cached
}

// StatusUpdates returns a channel of status changes.
//
// This replaces polling for connectivity: an update arrives as soon as Arti's
// view changes, in either direction. The channel is closed when the client is
// closed. Updates are dropped rather than queued if a receiver falls behind,
// so a slow consumer cannot stall the client — only the newest status is
// meaningful anyway.
//
// Pass the channel to [Client.Unsubscribe] when finished with it.
func (c *Client) StatusUpdates() <-chan Status {
	ch := make(chan Status, statusBuffer)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		close(ch)
		return ch
	}
	c.subscribers = append(c.subscribers, ch)
	return ch
}

// Unsubscribe releases a channel from [Client.StatusUpdates].
func (c *Client) Unsubscribe(ch <-chan Status) { c.unsubscribe(ch) }

func (c *Client) unsubscribe(ch <-chan Status) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, sub := range c.subscribers {
		if (<-chan Status)(sub) == ch {
			c.subscribers = append(c.subscribers[:i], c.subscribers[i+1:]...)
			close(sub)
			return
		}
	}
}

// DialContext opens a connection through Tor.
//
// The address may be an onion address or an ordinary host:port. Only "tcp"
// networks are supported.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("arti: unsupported network %q", network)
	}
	dialer, err := c.socksDialer()
	if err != nil {
		return nil, err
	}
	if ctxDialer, ok := dialer.(proxy.ContextDialer); ok {
		return ctxDialer.DialContext(ctx, network, address)
	}
	return dialer.Dial(network, address)
}

// Dialer returns a dialer that routes through Tor, for APIs that want one.
func (c *Client) Dialer() (proxy.Dialer, error) { return c.socksDialer() }

// socksDialer builds the SOCKS dialer once the listener address is known.
func (c *Client) socksDialer() (proxy.Dialer, error) {
	c.dialerOnce.Do(func() {
		addr := c.backend.SocksAddr()
		if addr == "" {
			c.dialerErr = errors.New("arti: no SOCKS listener is running")
			return
		}
		c.dialer, c.dialerErr = proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	})
	return c.dialer, c.dialerErr
}

// Close shuts the client down and releases it.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	subscribers := c.subscribers
	c.subscribers = nil
	onions := make([]*OnionService, 0, len(c.onions))
	for _, svc := range c.onions {
		onions = append(onions, svc)
	}
	c.mu.Unlock()

	close(c.done)
	for _, svc := range onions {
		svc.closeLocal()
	}
	for _, sub := range subscribers {
		close(sub)
	}

	c.backend.Shutdown()
	c.backend.free()
	return nil
}

// pumpEvents relays backend events to status subscribers and onion services.
func (c *Client) pumpEvents() {
	for {
		select {
		case <-c.done:
			return
		default:
		}

		ev, err := c.backend.NextEvent(eventPumpInterval)
		if err != nil || ev == nil {
			continue
		}
		switch ev.Type {
		case "status_client":
			c.publishStatus(Status{
				Progress: ev.Progress,
				Ready:    ev.Tag == "done",
				Summary:  ev.Summary,
				Problem:  problemOf(ev),
			})
		case "hs_desc":
			c.mu.Lock()
			svc := c.onions[ev.Address]
			c.mu.Unlock()
			if svc != nil {
				svc.handleDescEvent(ev)
			}
		}
	}
}

// publishStatus caches a status and fans it out to subscribers.
func (c *Client) publishStatus(st Status) {
	c.statusMu.Lock()
	c.status = st
	c.statusMu.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, sub := range c.subscribers {
		select {
		case sub <- st:
		default:
			// The receiver is behind. Drop the oldest and try again, so it
			// still ends up with the newest status rather than a stale one.
			select {
			case <-sub:
			default:
			}
			select {
			case sub <- st:
			default:
			}
		}
	}
}

// statusFrom converts a backend bootstrap status.
func statusFrom(st bootstrapStatus) Status {
	return Status{
		Progress: st.Progress,
		Ready:    st.Liveness == "up",
		Summary:  st.Summary,
		Problem:  problemOfTag(st.Tag, st.Summary),
	}
}

// problemOf extracts a problem description from an event, if it is reporting one.
func problemOf(ev *artiEvent) string { return problemOfTag(ev.Tag, ev.Summary) }

// problemOfTag reports the summary only when the tag marks a real fault.
func problemOfTag(tag, summary string) string {
	if tag == "problem" {
		return summary
	}
	return ""
}
