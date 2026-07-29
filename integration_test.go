//go:build integration

// End-to-end tests against the live Tor network.
//
//	go test -tags integration -timeout 40m -v ./...
//
// Excluded from the default build: these bootstrap a real Tor client, which
// needs network access and takes minutes.
package arti_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	arti "github.com/bounce-chat/go-arti"
)

// openClient brings up a client in a temporary data directory.
func openClient(t *testing.T) *arti.Client {
	t.Helper()
	return openClientIn(t, t.TempDir())
}

func openClientIn(t *testing.T, dir string) *arti.Client {
	t.Helper()

	client, err := arti.Open(arti.Config{DataDir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// Bootstrap must block until traffic can actually flow, and status must move
// from not-ready to ready along the way.
func TestBootstrapAndDial(t *testing.T) {
	client := openClient(t)

	if client.Status().Ready {
		t.Error("a client that has not bootstrapped should not be ready")
	}

	updates := client.StatusUpdates()
	defer client.Unsubscribe(updates)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := client.Bootstrap(ctx); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if !client.Status().Ready {
		t.Error("client should be ready after Bootstrap returns")
	}

	// The subscriber should have seen progress, which is what drives a
	// connectivity indicator.
	select {
	case st := <-updates:
		t.Logf("status update: %d%% ready=%v %q", st.Progress, st.Ready, st.Summary)
	case <-time.After(5 * time.Second):
		t.Error("expected at least one status update during bootstrap")
	}

	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: client.DialContext},
		Timeout:   2 * time.Minute,
	}
	resp, err := httpClient.Get("https://check.torproject.org/api/ip")
	if err != nil {
		t.Fatalf("fetch over Tor: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	t.Logf("check.torproject.org says: %s", body)
	if !strings.Contains(string(body), `"IsTor":true`) {
		t.Errorf("traffic did not go over Tor: %s", body)
	}
}

// An onion service is just a net.Listener, so serving on one should need
// nothing more than http.Serve.
func TestOnionRoundTrip(t *testing.T) {
	client := openClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	svc, err := client.Listen(ctx, arti.OnionConfig{Ports: []int{80}})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer svc.Close()
	t.Logf("published %v", svc.Addr())

	if svc.PrivateKey() == nil {
		t.Error("a generated key should be returned so it can be persisted")
	}
	if pub, err := svc.PublicKey(); err != nil {
		t.Errorf("PublicKey: %v", err)
	} else if id, err := arti.OnionIDFromPublicKey(pub); err != nil || id != svc.ID() {
		t.Errorf("public key does not round trip to the service id")
	}

	const greeting = "Hello from the direct API"
	server := &http.Server{Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, greeting) })}
	defer server.Close()
	go server.Serve(svc)

	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: client.DialContext},
		Timeout:   3 * time.Minute,
	}

	var body []byte
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := httpClient.Get("http://" + svc.ID() + ".onion")
		if err != nil {
			t.Logf("attempt %d: %v", attempt, err)
			select {
			case <-ctx.Done():
				t.Fatal("timed out reaching the onion service")
			case <-time.After(20 * time.Second):
			}
			continue
		}
		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		break
	}
	if string(body) != greeting {
		t.Errorf("onion service returned %q, want %q", body, greeting)
	}
}

// A persisted key must reproduce the same address, which is what makes an
// onion address survive a restart.
func TestSavedKeyKeepsAddress(t *testing.T) {
	dir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	first := openClientIn(t, dir)
	svc, err := first.Listen(ctx, arti.OnionConfig{Ports: []int{80}, NoWait: true})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	id, key := svc.ID(), svc.PrivateKey()
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The address must also be derivable from the key alone, with no client
	// running at all.
	pub, err := arti.PublicKeyFromPrivate(key)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	offline, err := arti.OnionIDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("OnionIDFromPublicKey: %v", err)
	}
	if offline != id {
		t.Errorf("offline address %q does not match published %q", offline, id)
	}

	second := openClientIn(t, dir)
	republished, err := second.Listen(ctx, arti.OnionConfig{
		PrivateKey: key,
		Ports:      []int{80},
	})
	if err != nil {
		t.Fatalf("Listen with the saved key: %v", err)
	}
	defer republished.Close()

	if republished.ID() != id {
		t.Errorf("address changed across restarts: %q then %q", id, republished.ID())
	}
}

// Closing a client must unblock anything waiting on it rather than hanging.
func TestCloseUnblocksWaiters(t *testing.T) {
	client := openClientIn(t, t.TempDir())
	updates := client.StatusUpdates()

	done := make(chan error, 1)
	go func() {
		done <- client.Bootstrap(context.Background())
	}()

	time.Sleep(500 * time.Millisecond)
	client.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Bootstrap should report failure when the client is closed")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Bootstrap did not return after Close")
	}

	// Buffered updates are still delivered before the close is observed, so
	// drain rather than assuming the first receive reports closure.
	deadline := time.After(30 * time.Second)
	for {
		select {
		case _, ok := <-updates:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("the status channel was not closed with the client")
		}
	}
}

// Arti's log records must actually reach the caller, since that is the only
// window into a slow bootstrap.
func TestLogsReachTheCaller(t *testing.T) {
	records, err := arti.EnableLogging("info")
	if err != nil {
		t.Fatalf("EnableLogging: %v", err)
	}
	t.Cleanup(arti.StopLogging)

	client, err := arti.Open(arti.Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	go client.Bootstrap(ctx)

	deadline := time.After(5 * time.Minute)
	seen := 0
	for {
		select {
		case rec, ok := <-records:
			if !ok {
				t.Fatal("log channel closed unexpectedly")
			}
			seen++
			if seen <= 5 {
				t.Logf("%s", rec)
			}
			// tor_dirmgr narrates bootstrap; seeing it proves the pipeline.
			if rec.Target != "" && rec.Level != "" && rec.Message != "" && seen >= 3 {
				t.Logf("received %d records; pipeline works", seen)
				return
			}
		case <-deadline:
			t.Fatalf("only %d log records arrived", seen)
		}
	}
}
