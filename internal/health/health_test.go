package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"tsv-vpn/internal/crypto"
	"tsv-vpn/internal/db"
	"tsv-vpn/internal/tailnet"
)

type fakePinger struct {
	mu     sync.Mutex
	rtt    time.Duration
	err    error
	ifaces []string
}

func (p *fakePinger) Ping(ctx context.Context, addr netip.Addr, iface string) (time.Duration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ifaces = append(p.ifaces, iface)
	return p.rtt, p.err
}

type fakeTunnels struct {
	state     db.State
	iface     string
	unhealthy []string
}

func (t *fakeTunnels) Status(name string) (db.State, string) { return t.state, t.iface }

func (t *fakeTunnels) Unhealthy(ctx context.Context, name, reason string) {
	t.unhealthy = append(t.unhealthy, name)
	t.state = db.StateFailed
	t.iface = ""
}

func testStore(t *testing.T) *db.Store {
	t.Helper()
	key, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := crypto.New(key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(filepath.Join(t.TempDir(), "health.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func testConnection(t *testing.T, store *db.Store) db.Connection {
	t.Helper()
	id, err := store.CreateConnection(db.Connection{
		Name:          "office",
		GatewayHost:   "vpn.example.com",
		PPPUsername:   "user",
		RemoteSubnets: []string{"198.51.100.0/24"},
		HealthCheckIP: "198.51.100.10",
		Enabled:       true,
	}, db.Secrets{PSK: "psk", PPPPassword: "password"})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := store.Connection(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetStatus(db.Status{ConnectionID: id, State: db.StateUp, Iface: "ppp0"}); err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestCheckRecordsRTT(t *testing.T) {
	store := testStore(t)
	conn := testConnection(t, store)
	pinger := &fakePinger{rtt: 12500 * time.Microsecond}
	checker := &Checker{Store: store, Tunnels: &fakeTunnels{state: db.StateUp, iface: "ppp0"}, Pinger: pinger}

	checker.CheckAll(t.Context())

	status, err := store.Status(conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.LastRTTMS != 12.5 {
		t.Fatalf("got rtt %v, want 12.5", status.LastRTTMS)
	}
	if status.LastError != "" {
		t.Fatalf("got error %q", status.LastError)
	}
	if status.State != db.StateUp || status.Iface != "ppp0" {
		t.Fatalf("check overwrote the tunnel state: %+v", status)
	}
	if len(pinger.ifaces) != 1 || pinger.ifaces[0] != "ppp0" {
		t.Fatalf("pinged from %v", pinger.ifaces)
	}
}

func TestThreeFailuresTearDownTheTunnel(t *testing.T) {
	store := testStore(t)
	conn := testConnection(t, store)
	tunnels := &fakeTunnels{state: db.StateUp, iface: "ppp0"}
	checker := &Checker{Store: store, Tunnels: tunnels, Pinger: &fakePinger{err: errors.New("i/o timeout")}}

	for range failureLimit - 1 {
		checker.Check(t.Context(), conn)
	}
	if len(tunnels.unhealthy) != 0 {
		t.Fatalf("gave up after %d checks", failureLimit-1)
	}

	checker.Check(t.Context(), conn)
	if len(tunnels.unhealthy) != 1 || tunnels.unhealthy[0] != conn.Name {
		t.Fatalf("got %v", tunnels.unhealthy)
	}

	status, err := store.Status(conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.LastError == "" {
		t.Fatal("no error recorded")
	}
}

func TestSuccessResetsFailureCount(t *testing.T) {
	store := testStore(t)
	conn := testConnection(t, store)
	tunnels := &fakeTunnels{state: db.StateUp, iface: "ppp0"}
	pinger := &fakePinger{err: errors.New("i/o timeout")}
	checker := &Checker{Store: store, Tunnels: tunnels, Pinger: pinger}

	checker.Check(t.Context(), conn)
	checker.Check(t.Context(), conn)
	pinger.err = nil
	checker.Check(t.Context(), conn)
	pinger.err = errors.New("i/o timeout")
	checker.Check(t.Context(), conn)
	checker.Check(t.Context(), conn)

	if len(tunnels.unhealthy) != 0 {
		t.Fatalf("counted failures across a success: %v", tunnels.unhealthy)
	}
}

func TestTunnelsThatAreNotUpAreNotChecked(t *testing.T) {
	store := testStore(t)
	testConnection(t, store)
	pinger := &fakePinger{}
	checker := &Checker{Store: store, Tunnels: &fakeTunnels{state: db.StateConnecting}, Pinger: pinger}

	checker.CheckAll(t.Context())

	if len(pinger.ifaces) != 0 {
		t.Fatalf("pinged a connecting tunnel: %v", pinger.ifaces)
	}
}

func TestReportIsDegradedWhileATunnelIsDown(t *testing.T) {
	store := testStore(t)
	testConnection(t, store)
	reporter := Reporter{
		Store:   store,
		Tunnels: &fakeTunnels{state: db.StateConnecting},
		Backend: func(ctx context.Context) (string, error) { return tailnet.StateRunning, nil },
	}

	response := httptest.NewRecorder()
	reporter.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/healthz", nil))

	if response.Code != 200 {
		t.Fatalf("got status %d", response.Code)
	}
	var report Report
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "degraded" {
		t.Fatalf("got %q", report.Status)
	}
	if len(report.Connections) != 1 || report.Connections[0].State != db.StateConnecting {
		t.Fatalf("got %+v", report.Connections)
	}
}

func TestReportFailsWhenTailscaledIsNotRunning(t *testing.T) {
	store := testStore(t)
	reporter := Reporter{
		Store:   store,
		Tunnels: &fakeTunnels{},
		Backend: func(ctx context.Context) (string, error) { return "", errors.New("no socket") },
	}

	response := httptest.NewRecorder()
	reporter.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/healthz", nil))

	if response.Code != 503 {
		t.Fatalf("got status %d", response.Code)
	}
	var report Report
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Tailnet != "unreachable" || report.Status != "down" {
		t.Fatalf("got %+v", report)
	}
}
