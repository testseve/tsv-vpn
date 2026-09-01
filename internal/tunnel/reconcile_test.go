package tunnel

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tsv-vpn/internal/crypto"
	"tsv-vpn/internal/db"
	"tsv-vpn/internal/run"
)

type fakeRunner struct {
	mu       sync.Mutex
	calls    []string
	rules    map[string]bool
	failWith map[string]error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{rules: map[string]bool{}, failWith: map[string]error{}}
}

func (f *fakeRunner) Run(ctx context.Context, command run.Command) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := command.String()
	f.calls = append(f.calls, line)

	for match, err := range f.failWith {
		if strings.Contains(line, match) {
			return "", err
		}
	}
	if command.Path == "iptables" {
		return "", f.iptables(command.Args)
	}
	return "", nil
}

func (f *fakeRunner) iptables(args []string) error {
	key := strings.Join(args, " ")
	switch {
	case strings.Contains(key, " -C "):
		if !f.rules[strings.Replace(key, " -C ", " -A ", 1)] {
			return errors.New("iptables: Bad rule (does a matching rule exist in that chain?)")
		}
	case strings.Contains(key, " -A "):
		f.rules[key] = true
	case strings.Contains(key, " -D "):
		delete(f.rules, strings.Replace(key, " -D ", " -A ", 1))
	}
	return nil
}

func (f *fakeRunner) matching(substring string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var found []string
	for _, call := range f.calls {
		if strings.Contains(call, substring) {
			found = append(found, call)
		}
	}
	return found
}

func (f *fakeRunner) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

type fakeControl struct {
	mu   sync.Mutex
	sent []string
	err  error
}

func (f *fakeControl) Add(ctx context.Context, tunnel Tunnel, peersDir string) error {
	return f.record("add " + tunnel.Name)
}

func (f *fakeControl) Connect(ctx context.Context, name string) error {
	return f.record("connect " + name)
}

func (f *fakeControl) Disconnect(ctx context.Context, name string) error {
	return f.record("disconnect " + name)
}

func (f *fakeControl) Remove(ctx context.Context, name string) error {
	return f.record("remove " + name)
}

func (f *fakeControl) record(command string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, command)
	return nil
}

func (f *fakeControl) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sent...)
}

// LAC add/remove is bookkeeping, not a dial; the tests below are about the
// dialling sequence.
func (f *fakeControl) dials() []string {
	var dials []string
	for _, command := range f.commands() {
		if !strings.HasPrefix(command, "add ") && !strings.HasPrefix(command, "remove ") {
			dials = append(dials, command)
		}
	}
	return dials
}

type fakeAdvertiser struct {
	mu     sync.Mutex
	routes [][]string
}

func (f *fakeAdvertiser) SetRoutes(ctx context.Context, routes []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes = append(f.routes, routes)
	return nil
}

func (f *fakeAdvertiser) last() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.routes) == 0 {
		return nil
	}
	return f.routes[len(f.routes)-1]
}

type harness struct {
	manager *Manager
	store   *db.Store
	runner  *fakeRunner
	control *fakeControl
	tailnet *fakeAdvertiser
	dir     string
	now     time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	key, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := crypto.New(key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	h := &harness{
		store:   store,
		runner:  newFakeRunner(),
		control: &fakeControl{},
		tailnet: &fakeAdvertiser{},
		dir:     t.TempDir(),
		now:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	h.manager = New(Options{
		Store:   store,
		Dir:     h.dir,
		Runner:  h.runner,
		Control: h.control,
		Tailnet: h.tailnet,
		Resolve: func(ctx context.Context, host string) (string, error) { return "203.0.113.9", nil },
		Now:     func() time.Time { return h.now },
	})
	return h
}

func (h *harness) addConnection(t *testing.T, name, subnet string) int64 {
	t.Helper()
	id, err := h.store.CreateConnection(db.Connection{
		Name:          name,
		GatewayHost:   name + ".example.com",
		PPPUsername:   "user",
		RemoteSubnets: []string{subnet},
		Enabled:       true,
	}, db.Secrets{PSK: "psk", PPPPassword: "password"})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (h *harness) advance(d time.Duration) { h.now = h.now.Add(d) }

func TestReconcileRendersAndDials(t *testing.T) {
	h := newHarness(t)
	id := h.addConnection(t, "alpha", "198.51.100.0/24")

	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}

	if loads := h.runner.matching("swanctl --load-all"); len(loads) != 1 {
		t.Fatalf("swanctl loads: %v", loads)
	}
	if got := h.control.dials(); len(got) != 2 || got[0] != "disconnect alpha" || got[1] != "connect alpha" {
		t.Fatalf("control commands: %v", got)
	}
	if _, err := readFile(filepath.Join(h.dir, "swanctl.conf")); err != nil {
		t.Fatal(err)
	}

	status, err := h.store.Status(id)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != db.StateConnecting {
		t.Fatalf("status: %+v", status)
	}
	if got := h.tailnet.last(); len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("advertised: %v", got)
	}
}

func TestReconcileIsQuietWhenNothingChanged(t *testing.T) {
	h := newHarness(t)
	h.addConnection(t, "alpha", "198.51.100.0/24")
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.PPPUp(t.Context(), "alpha", "ppp0", "10.0.9.2", "10.0.9.1"); err != nil {
		t.Fatal(err)
	}

	h.runner.reset()
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls := h.runner.matching("swanctl"); len(calls) != 0 {
		t.Fatalf("reloaded an unchanged config: %v", calls)
	}
	if got := h.control.dials(); len(got) != 2 {
		t.Fatalf("redialed a live tunnel: %v", got)
	}
	if len(h.tailnet.routes) != 1 {
		t.Fatalf("re-advertised an unchanged route set: %v", h.tailnet.routes)
	}
}

func TestPPPUpInstallsRoutesAndNAT(t *testing.T) {
	h := newHarness(t)
	id := h.addConnection(t, "alpha", "198.51.100.0/24")
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}

	if err := h.manager.PPPUp(t.Context(), "alpha", "ppp0", "10.0.9.2", "10.0.9.1"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip route replace 198.51.100.0/24 dev ppp0",
		"iptables -t nat -A POSTROUTING -o ppp0 -j MASQUERADE",
		"iptables -t mangle -A FORWARD -o ppp0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
	} {
		if calls := h.runner.matching(want); len(calls) != 1 {
			t.Fatalf("want one %q, got %v", want, calls)
		}
	}

	status, err := h.store.Status(id)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != db.StateUp || status.Iface != "ppp0" || status.ConnectedAt.IsZero() {
		t.Fatalf("status: %+v", status)
	}
	if phase, iface := h.manager.Status("alpha"); phase != db.StateUp || iface != "ppp0" {
		t.Fatalf("got %s on %q", phase, iface)
	}
}

func TestPPPUpSkipsExistingNATRules(t *testing.T) {
	h := newHarness(t)
	h.addConnection(t, "alpha", "198.51.100.0/24")
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.PPPUp(t.Context(), "alpha", "ppp0", "10.0.9.2", "10.0.9.1"); err != nil {
		t.Fatal(err)
	}
	h.runner.reset()
	if err := h.manager.PPPUp(t.Context(), "alpha", "ppp0", "10.0.9.2", "10.0.9.1"); err != nil {
		t.Fatal(err)
	}
	if calls := h.runner.matching("-A POSTROUTING"); len(calls) != 0 {
		t.Fatalf("duplicated a nat rule: %v", calls)
	}
}

func TestPPPDownTearsDownAndSchedulesRedial(t *testing.T) {
	h := newHarness(t)
	id := h.addConnection(t, "alpha", "198.51.100.0/24")
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.PPPUp(t.Context(), "alpha", "ppp0", "10.0.9.2", "10.0.9.1"); err != nil {
		t.Fatal(err)
	}

	h.runner.reset()
	if err := h.manager.PPPDown(t.Context(), "alpha", "ppp0"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip route del 198.51.100.0/24 dev ppp0",
		"iptables -t nat -D POSTROUTING -o ppp0 -j MASQUERADE",
	} {
		if calls := h.runner.matching(want); len(calls) != 1 {
			t.Fatalf("want one %q, got %v", want, calls)
		}
	}
	status, err := h.store.Status(id)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != db.StateDisconnected {
		t.Fatalf("status: %+v", status)
	}

	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := len(h.control.dials()); got != 2 {
		t.Fatalf("redialed before the delay elapsed: %d commands", got)
	}

	h.advance(minRedialDelay)
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := h.control.dials(); len(got) != 4 || got[3] != "connect alpha" {
		t.Fatalf("control commands: %v", got)
	}
}

func TestDialTimeoutBacksOff(t *testing.T) {
	h := newHarness(t)
	id := h.addConnection(t, "alpha", "198.51.100.0/24")
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}

	h.advance(defaultDialTimeout + time.Second)
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, err := h.store.Status(id)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != db.StateFailed || !strings.Contains(status.LastError, "timed out") {
		t.Fatalf("status: %+v", status)
	}
	if got := len(h.control.dials()); got != 2 {
		t.Fatalf("redialed immediately after a timeout: %d commands", got)
	}

	h.advance(redialDelay(1))
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := len(h.control.dials()); got != 4 {
		t.Fatalf("want a redial once the backoff elapsed, got %d commands", got)
	}
}

func TestRedialDelayGrowsAndIsCapped(t *testing.T) {
	if got := redialDelay(1); got != minRedialDelay {
		t.Fatalf("got %s", got)
	}
	if got := redialDelay(2); got != 2*minRedialDelay {
		t.Fatalf("got %s", got)
	}
	if got := redialDelay(50); got != maxRedialDelay {
		t.Fatalf("got %s", got)
	}
}

func TestDisablingConnectionTearsItDown(t *testing.T) {
	h := newHarness(t)
	id := h.addConnection(t, "alpha", "198.51.100.0/24")
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.PPPUp(t.Context(), "alpha", "ppp0", "10.0.9.2", "10.0.9.1"); err != nil {
		t.Fatal(err)
	}

	conn, err := h.store.Connection(id)
	if err != nil {
		t.Fatal(err)
	}
	conn.Enabled = false
	if err := h.store.UpdateConnection(conn, db.Secrets{}); err != nil {
		t.Fatal(err)
	}

	h.runner.reset()
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls := h.runner.matching("ip route del 198.51.100.0/24 dev ppp0"); len(calls) != 1 {
		t.Fatalf("route teardown: %v", calls)
	}
	if calls := h.runner.matching("swanctl --terminate --ike alpha"); len(calls) != 1 {
		t.Fatalf("ike teardown: %v", calls)
	}
	status, err := h.store.Status(id)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != db.StateDisconnected {
		t.Fatalf("status: %+v", status)
	}
	if got := h.tailnet.last(); len(got) != 0 {
		t.Fatalf("still advertising %v", got)
	}
}

func TestSecondTunnelDoesNotDisturbTheFirst(t *testing.T) {
	h := newHarness(t)
	h.addConnection(t, "alpha", "198.51.100.0/24")
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.PPPUp(t.Context(), "alpha", "ppp0", "10.0.9.2", "10.0.9.1"); err != nil {
		t.Fatal(err)
	}

	h.addConnection(t, "beta", "203.0.113.0/24")
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.PPPUp(t.Context(), "beta", "ppp1", "10.0.9.2", "10.0.9.1"); err != nil {
		t.Fatal(err)
	}

	if phase, iface := h.manager.Status("alpha"); phase != db.StateUp || iface != "ppp0" {
		t.Fatalf("alpha: %s on %q", phase, iface)
	}
	if phase, iface := h.manager.Status("beta"); phase != db.StateUp || iface != "ppp1" {
		t.Fatalf("beta: %s on %q", phase, iface)
	}
	dials := 0
	for _, command := range h.control.commands() {
		if command == "connect alpha" {
			dials++
		}
	}
	if dials != 1 {
		t.Fatalf("alpha was redialed: %v", h.control.commands())
	}
	if got := h.tailnet.last(); len(got) != 2 {
		t.Fatalf("advertised: %v", got)
	}
	swanctl, err := readFile(filepath.Join(h.dir, "swanctl.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(swanctl, "ike-alpha") || !strings.Contains(swanctl, "ike-beta") {
		t.Fatalf("swanctl.conf: %s", swanctl)
	}
}

func TestHookEndpoints(t *testing.T) {
	h := newHarness(t)
	h.addConnection(t, "alpha", "198.51.100.0/24")
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(h.manager.Handler())
	defer server.Close()

	response, err := server.Client().Post(server.URL+"/internal/ppp/up?peer=alpha&iface=ppp0", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatalf("up: %s", response.Status)
	}
	if phase, iface := h.manager.Status("alpha"); phase != db.StateUp || iface != "ppp0" {
		t.Fatalf("got %s on %q", phase, iface)
	}

	response, err = server.Client().Post(server.URL+"/internal/ppp/down?peer=alpha&iface=ppp0", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatalf("down: %s", response.Status)
	}

	response, err = server.Client().Post(server.URL+"/internal/ppp/up?peer=ghost&iface=ppp3", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 500 {
		t.Fatalf("unknown peer: %s", response.Status)
	}
}

func TestInstallHooksAndCHAPLink(t *testing.T) {
	pppDir := t.TempDir()
	if err := InstallHooks(pppDir, "127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"ip-up.d", "ip-down.d"} {
		script, err := readFile(filepath.Join(pppDir, dir, "tsv-vpn"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(script, "peer=$6") || !strings.Contains(script, "iface=$1") {
			t.Fatalf("%s: %s", dir, script)
		}
	}

	runDir := t.TempDir()
	if err := LinkCHAPSecrets(pppDir, runDir); err != nil {
		t.Fatal(err)
	}
	if err := LinkCHAPSecrets(pppDir, runDir); err != nil {
		t.Fatal(err)
	}
	target, err := readLink(filepath.Join(pppDir, "chap-secrets"))
	if err != nil {
		t.Fatal(err)
	}
	if target != filepath.Join(runDir, "chap-secrets") {
		t.Fatalf("link points at %s", target)
	}
}

func TestPrerenderWritesConfigsBeforeAnyDaemonRuns(t *testing.T) {
	h := newHarness(t)
	h.addConnection(t, "alpha", "198.51.100.0/24")

	if err := h.manager.Prerender(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"swanctl.conf", "xl2tpd.conf", "chap-secrets"} {
		if _, err := readFile(filepath.Join(h.dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if calls := h.runner.matching(""); len(calls) != 0 {
		t.Fatalf("prerender touched the daemons: %v", calls)
	}
	if got := h.control.commands(); len(got) != 0 {
		t.Fatalf("prerender dialed: %v", got)
	}

	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls := h.runner.matching("swanctl --load-all"); len(calls) != 1 {
		t.Fatalf("want the first reconcile to load configs, got %v", calls)
	}
}

func TestRestartReplaysDesiredStateFromTheDatabase(t *testing.T) {
	h := newHarness(t)
	h.addConnection(t, "alpha", "198.51.100.0/24")
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.PPPUp(t.Context(), "alpha", "ppp0", "10.0.9.2", "10.0.9.1"); err != nil {
		t.Fatal(err)
	}

	restarted := New(Options{
		Store:   h.store,
		Dir:     h.dir,
		Runner:  h.runner,
		Control: h.control,
		Tailnet: h.tailnet,
		Resolve: func(ctx context.Context, host string) (string, error) { return "203.0.113.9", nil },
		Now:     func() time.Time { return h.now },
	})
	if err := restarted.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if phase, _ := restarted.Status("alpha"); phase != db.StateConnecting {
		t.Fatalf("got %s, want the tunnel redialed after a restart", phase)
	}
	if got := h.control.commands(); got[len(got)-1] != "connect alpha" {
		t.Fatalf("control commands: %v", got)
	}
}

func TestInvalidateReloadsConfigsAfterADaemonRestart(t *testing.T) {
	h := newHarness(t)
	h.addConnection(t, "alpha", "198.51.100.0/24")
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.PPPUp(t.Context(), "alpha", "ppp0", "10.0.9.2", "10.0.9.1"); err != nil {
		t.Fatal(err)
	}

	h.runner.reset()
	h.manager.Invalidate()
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls := h.runner.matching("swanctl --load-all"); len(calls) != 1 {
		t.Fatalf("want the configs loaded again, got %v", calls)
	}
}

func TestUnhealthyTearsDownAndRedials(t *testing.T) {
	h := newHarness(t)
	id := h.addConnection(t, "alpha", "198.51.100.0/24")
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.PPPUp(t.Context(), "alpha", "ppp0", "10.0.9.2", "10.0.9.1"); err != nil {
		t.Fatal(err)
	}

	h.runner.reset()
	h.manager.Unhealthy(t.Context(), "alpha", "198.51.100.10 unreachable after 3 checks")

	for _, want := range []string{
		"ip route del 198.51.100.0/24 dev ppp0",
		"iptables -t nat -D POSTROUTING -o ppp0 -j MASQUERADE",
	} {
		if calls := h.runner.matching(want); len(calls) != 1 {
			t.Fatalf("want one %q, got %v", want, calls)
		}
	}
	status, err := h.store.Status(id)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != db.StateFailed || !strings.Contains(status.LastError, "unreachable") {
		t.Fatalf("status: %+v", status)
	}

	h.advance(minRedialDelay)
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := h.control.dials(); len(got) != 4 || got[3] != "connect alpha" {
		t.Fatalf("control commands: %v", got)
	}
}

func TestEditingALiveConnectionRedialsOnlyThatTunnel(t *testing.T) {
	h := newHarness(t)
	alpha := h.addConnection(t, "alpha", "198.51.100.0/24")
	h.addConnection(t, "beta", "203.0.113.0/24")
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "beta"} {
		if err := h.manager.PPPUp(t.Context(), name, "ppp0", "10.0.9.2", "10.0.9.1"); err != nil {
			t.Fatal(err)
		}
	}

	conn, err := h.store.Connection(alpha)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.UpdateConnection(conn, db.Secrets{PSK: "a-new-psk"}); err != nil {
		t.Fatal(err)
	}

	h.control.mu.Lock()
	h.control.sent = nil
	h.control.mu.Unlock()
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}

	if got := h.control.dials(); len(got) != 3 || got[0] != "disconnect alpha" || got[2] != "connect alpha" {
		t.Fatalf("control commands: %v", got)
	}
	if state, _ := h.manager.Status("beta"); state != db.StateUp {
		t.Fatalf("beta was disturbed: %s", state)
	}
}

func TestDialInitiatesIKEBeforeL2TP(t *testing.T) {
	h := newHarness(t)
	h.addConnection(t, "alpha", "198.51.100.0/24")

	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}

	if calls := h.runner.matching("swanctl --initiate --ike alpha --child alpha"); len(calls) != 1 {
		t.Fatalf("ike was not initiated: %v", h.runner.calls)
	}
	if got := h.control.dials(); len(got) != 2 || got[1] != "connect alpha" {
		t.Fatalf("control commands: %v", got)
	}
}

func TestAFailedIKEIsSurfacedAndBackedOff(t *testing.T) {
	h := newHarness(t)
	id := h.addConnection(t, "alpha", "198.51.100.0/24")
	h.runner.failWith["--initiate"] = errors.New("establishing CHILD_SA alpha failed")

	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}

	if got := h.control.dials(); len(got) != 1 {
		t.Fatalf("dialled l2tp without ipsec: %v", got)
	}
	status, err := h.store.Status(id)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != db.StateFailed || !strings.Contains(status.LastError, "CHILD_SA") {
		t.Fatalf("status: %+v", status)
	}

	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls := h.runner.matching("--initiate"); len(calls) != 1 {
		t.Fatalf("retried before the backoff elapsed: %v", calls)
	}
	h.advance(minRedialDelay)
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls := h.runner.matching("--initiate"); len(calls) != 2 {
		t.Fatalf("did not retry after the backoff: %v", calls)
	}
}

func TestEditingAFailedConnectionClearsItsBackoff(t *testing.T) {
	h := newHarness(t)
	id := h.addConnection(t, "alpha", "198.51.100.0/24")
	h.runner.failWith["--initiate"] = errors.New("establishing CHILD_SA alpha failed")
	for range 3 {
		if err := h.manager.Reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
		h.advance(maxRedialDelay)
	}

	delete(h.runner.failWith, "--initiate")
	conn, err := h.store.Connection(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.UpdateConnection(conn, db.Secrets{PSK: "the-corrected-psk"}); err != nil {
		t.Fatal(err)
	}

	before := len(h.runner.matching("--initiate"))
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := len(h.runner.matching("--initiate")) - before; got != 1 {
		t.Fatalf("waited out the backoff after a fix: %d dials", got)
	}
}

func TestPPPUpRecordsTheAssignedAddresses(t *testing.T) {
	h := newHarness(t)
	id := h.addConnection(t, "alpha", "198.51.100.0/24")
	if err := h.manager.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}

	if err := h.manager.PPPUp(t.Context(), "alpha", "ppp0", "10.0.9.2", "10.0.9.1"); err != nil {
		t.Fatal(err)
	}

	status, err := h.store.Status(id)
	if err != nil {
		t.Fatal(err)
	}
	if status.LocalIP != "10.0.9.2" || status.PeerIP != "10.0.9.1" {
		t.Fatalf("got local %q peer %q", status.LocalIP, status.PeerIP)
	}
}
