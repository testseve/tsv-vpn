package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"tsv-vpn/internal/db"
	"tsv-vpn/internal/logbuf"
	"tsv-vpn/internal/run"
)

const (
	defaultTick        = 30 * time.Second
	retryTick          = 5 * time.Second
	defaultDialTimeout = 60 * time.Second
	minRedialDelay     = 10 * time.Second
	initiateTimeout    = 20
	maxRedialDelay     = 5 * time.Minute
)

type Advertiser interface {
	SetRoutes(ctx context.Context, routes []string) error
}

type Options struct {
	Store       *db.Store
	Dir         string
	Runner      run.Runner
	Control     Control
	Logs        *logbuf.Ring
	Tailnet     Advertiser
	Resolve     func(ctx context.Context, host string) (string, error)
	Now         func() time.Time
	Tick        time.Duration
	DialTimeout time.Duration
}

type Manager struct {
	options Options
	network network
	nudge   chan struct{}

	mu         sync.Mutex
	tunnels    map[string]*state
	advertised string
	rendered   map[string]string
}

type state struct {
	id       int64
	name     string
	subnets  []string
	iface    string
	phase    db.State
	failures int
	dialedAt time.Time
	retryAt  time.Time
}

func New(options Options) *Manager {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Resolve == nil {
		options.Resolve = resolveHost
	}
	if options.Tick <= 0 {
		options.Tick = defaultTick
	}
	if options.DialTimeout <= 0 {
		options.DialTimeout = defaultDialTimeout
	}
	return &Manager{
		options:  options,
		network:  network{runner: options.Runner},
		nudge:    make(chan struct{}, 1),
		tunnels:  map[string]*state{},
		rendered: map[string]string{},
	}
}

func (m *Manager) Nudge() {
	select {
	case m.nudge <- struct{}{}:
	default:
	}
}

func (m *Manager) Run(ctx context.Context) {
	for {
		// A just-restarted daemon is not listening yet; retry in seconds,
		// not at the next slow tick.
		wait := m.options.Tick
		if err := m.Reconcile(ctx); err != nil && ctx.Err() == nil {
			m.logf("reconcile: %v", err)
			wait = retryTick
		}
		wait = min(wait, m.nextRetry())

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-m.nudge:
			timer.Stop()
		}
	}
}

// The shortest pending backoff decides the next wake; otherwise a failed
// dial waits for the slow tick.
func (m *Manager) nextRetry() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()

	wait := m.options.Tick
	now := m.options.Now()
	for _, tunnel := range m.tunnels {
		if tunnel.retryAt.IsZero() || !tunnel.retryAt.After(now) {
			continue
		}
		wait = min(wait, tunnel.retryAt.Sub(now))
	}
	return max(wait, time.Second)
}

func (m *Manager) Reconcile(ctx context.Context) error {
	conns, err := m.options.Store.ListConnections()
	if err != nil {
		return err
	}

	desired := map[string]db.Connection{}
	var enabled []db.Connection
	for _, conn := range conns {
		if conn.Enabled {
			desired[conn.Name] = conn
			enabled = append(enabled, conn)
		}
	}

	for _, stale := range m.staleTunnels(desired) {
		m.disconnect(ctx, stale)
	}
	changed, err := m.writeConfigs(ctx, enabled)
	if err != nil {
		return err
	}
	// Connections whose rendered configs changed are re-pushed to xl2tpd,
	// dropped, and redialled below.
	for _, tunnel := range changed {
		m.drop(ctx, tunnel.Name)
		// xl2tpd ignores a second add for a LAC it already has; remove the
		// old definition first.
		_ = m.options.Control.Remove(ctx, tunnel.Name)
		if err := m.options.Control.Add(ctx, tunnel, m.peersDir()); err != nil {
			m.logf("%s: %v", tunnel.Name, err)
		}
	}
	for _, conn := range enabled {
		m.step(ctx, conn)
	}
	return m.advertise(ctx)
}

func (m *Manager) staleTunnels(desired map[string]db.Connection) []*state {
	m.mu.Lock()
	defer m.mu.Unlock()

	var stale []*state
	for name, tunnel := range m.tunnels {
		if _, ok := desired[name]; !ok {
			stale = append(stale, tunnel)
			delete(m.tunnels, name)
		}
	}
	return stale
}

func (m *Manager) desiredTunnels(ctx context.Context, conns []db.Connection) ([]Tunnel, error) {
	tunnels := make([]Tunnel, 0, len(conns))
	for _, conn := range conns {
		secrets, err := m.options.Store.ConnectionSecrets(conn.ID)
		if err != nil {
			return nil, err
		}
		address, err := m.options.Resolve(ctx, conn.GatewayHost)
		if err != nil {
			m.logf("%s: resolve %s: %v", conn.Name, conn.GatewayHost, err)
		}
		tunnels = append(tunnels, FromConnection(conn, secrets, address))
	}
	return tunnels, nil
}

// Rendered files must reach disk before the daemons start loading them.
func (m *Manager) Prerender(ctx context.Context) error {
	conns, err := m.options.Store.ListConnections()
	if err != nil {
		return err
	}
	var enabled []db.Connection
	for _, conn := range conns {
		if conn.Enabled {
			enabled = append(enabled, conn)
		}
	}
	tunnels, err := m.desiredTunnels(ctx, enabled)
	if err != nil {
		return err
	}
	return Write(m.options.Dir, tunnels)
}

func (m *Manager) peersDir() string {
	return filepath.Join(m.options.Dir, "peers")
}

func (m *Manager) writeConfigs(ctx context.Context, conns []db.Connection) ([]Tunnel, error) {
	tunnels, err := m.desiredTunnels(ctx, conns)
	if err != nil {
		return nil, err
	}

	fingerprints := fingerprintsOf(tunnels)
	m.mu.Lock()
	changed := changedTunnels(m.rendered, fingerprints, tunnels)
	stale := len(m.rendered) != len(fingerprints)
	m.mu.Unlock()
	if len(changed) == 0 && !stale {
		return nil, nil
	}

	if err := Write(m.options.Dir, tunnels); err != nil {
		return nil, err
	}
	if _, err := m.options.Runner.Run(ctx, run.Command{
		Path: "swanctl",
		Args: []string{"--load-all", "--noprompt"},
		Env:  []string{"SWANCTL_DIR=" + m.options.Dir},
	}); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.rendered = fingerprints
	m.mu.Unlock()
	return changed, nil
}

// An edit means the operator fixed whatever was failing: backoff resets and
// the old IKE_SA goes with the old configuration.
func (m *Manager) drop(ctx context.Context, name string) {
	m.mu.Lock()
	tunnel, ok := m.tunnels[name]
	if !ok {
		m.mu.Unlock()
		return
	}
	iface, subnets := tunnel.iface, append([]string(nil), tunnel.subnets...)
	tunnel.phase = db.StateDisconnected
	tunnel.iface = ""
	tunnel.failures = 0
	tunnel.retryAt = time.Time{}
	m.mu.Unlock()

	if iface != "" {
		m.tearDownInterface(ctx, name, iface, subnets)
	}
	_ = m.options.Control.Disconnect(ctx, name)
	m.terminate(ctx, name)
	m.setStatus(tunnel.id, db.StateDisconnected, "")
}

func (m *Manager) step(ctx context.Context, conn db.Connection) {
	m.mu.Lock()
	tunnel, ok := m.tunnels[conn.Name]
	if !ok {
		tunnel = &state{id: conn.ID, name: conn.Name, phase: db.StateDisconnected}
		m.tunnels[conn.Name] = tunnel
	}
	tunnel.id = conn.ID
	tunnel.subnets = conn.RemoteSubnets
	phase, dialedAt, retryAt, iface := tunnel.phase, tunnel.dialedAt, tunnel.retryAt, tunnel.iface
	m.mu.Unlock()

	now := m.options.Now()
	switch phase {
	case db.StateUp:
		return
	case db.StateConnecting:
		if now.Sub(dialedAt) < m.options.DialTimeout {
			return
		}
		m.fail(ctx, conn.Name, iface, "timed out waiting for a ppp interface")
		return
	default:
		if now.Before(retryAt) {
			return
		}
	}
	m.dial(ctx, conn.Name)
}

func (m *Manager) dial(ctx context.Context, name string) {
	m.mu.Lock()
	tunnel, ok := m.tunnels[name]
	m.mu.Unlock()
	if !ok {
		return
	}

	// Disconnect first so the dial starts from a known state; xl2tpd errors
	// when there was no session.
	_ = m.options.Control.Disconnect(ctx, name)

	// L2TP is only protected once the IPsec SA exists; gateways drop bare
	// L2TP until then.
	if _, err := m.options.Runner.Run(ctx, run.Command{
		Path: "swanctl",
		Args: []string{"--initiate", "--ike", name, "--child", name, "--timeout", strconv.Itoa(initiateTimeout)},
		Env:  []string{"SWANCTL_DIR=" + m.options.Dir},
	}); err != nil {
		m.dialFailed(tunnel, err)
		return
	}

	if err := m.options.Control.Connect(ctx, name); err != nil {
		m.dialFailed(tunnel, err)
		return
	}

	m.mu.Lock()
	tunnel.phase = db.StateConnecting
	tunnel.dialedAt = m.options.Now()
	m.mu.Unlock()
	m.setStatus(tunnel.id, db.StateConnecting, "")
}

func (m *Manager) dialFailed(tunnel *state, err error) {
	m.mu.Lock()
	tunnel.phase = db.StateFailed
	tunnel.failures++
	tunnel.retryAt = m.options.Now().Add(redialDelay(tunnel.failures))
	m.mu.Unlock()
	m.logf("%s: dial: %v", tunnel.name, err)
	m.setStatus(tunnel.id, db.StateFailed, err.Error())
}

func (m *Manager) fail(ctx context.Context, name, iface, reason string) {
	m.mu.Lock()
	tunnel, ok := m.tunnels[name]
	if !ok {
		m.mu.Unlock()
		return
	}
	subnets := append([]string(nil), tunnel.subnets...)
	m.mu.Unlock()

	if iface != "" {
		m.tearDownInterface(ctx, name, iface, subnets)
	}

	m.mu.Lock()
	tunnel.phase = db.StateFailed
	tunnel.iface = ""
	tunnel.failures++
	tunnel.retryAt = m.options.Now().Add(redialDelay(tunnel.failures))
	m.mu.Unlock()
	m.setStatus(tunnel.id, db.StateFailed, reason)
}

func (m *Manager) disconnect(ctx context.Context, tunnel *state) {
	// Hook goroutines may still write iface/subnets under the lock, so
	// snapshot the same way.
	m.mu.Lock()
	iface, subnets := tunnel.iface, append([]string(nil), tunnel.subnets...)
	m.mu.Unlock()

	if iface != "" {
		m.tearDownInterface(ctx, tunnel.name, iface, subnets)
	}
	_ = m.options.Control.Disconnect(ctx, tunnel.name)
	_ = m.options.Control.Remove(ctx, tunnel.name)
	m.terminate(ctx, tunnel.name)
	m.setStatus(tunnel.id, db.StateDisconnected, "")
}

func (m *Manager) terminate(ctx context.Context, name string) {
	if _, err := m.options.Runner.Run(ctx, run.Command{
		Path: "swanctl",
		Args: []string{"--terminate", "--ike", name},
		Env:  []string{"SWANCTL_DIR=" + m.options.Dir},
	}); err != nil && !strings.Contains(err.Error(), "no matching SAs") {
		m.logf("%s: terminate: %v", name, err)
	}
}

func (m *Manager) tearDownInterface(ctx context.Context, name, iface string, subnets []string) {
	if err := m.network.removeRoutes(ctx, iface, subnets); err != nil {
		m.logf("%s: remove routes: %v", name, err)
	}
	if err := m.network.disableNAT(ctx, iface); err != nil {
		m.logf("%s: remove nat: %v", name, err)
	}
}

// pppd assigns interfaces and addresses at tunnel-up; this is where the
// connection learns them and its routes and NAT rules go in.
func (m *Manager) PPPUp(ctx context.Context, name, iface, localIP, peerIP string) error {
	m.mu.Lock()
	tunnel, ok := m.tunnels[name]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("unknown connection %q", name)
	}
	subnets := append([]string(nil), tunnel.subnets...)
	m.mu.Unlock()

	if err := m.network.addRoutes(ctx, iface, subnets); err != nil {
		m.fail(ctx, name, iface, err.Error())
		return err
	}
	if err := m.network.enableNAT(ctx, iface); err != nil {
		m.fail(ctx, name, iface, err.Error())
		return err
	}

	m.mu.Lock()
	tunnel.iface = iface
	tunnel.phase = db.StateUp
	tunnel.failures = 0
	tunnel.retryAt = time.Time{}
	id := tunnel.id
	m.mu.Unlock()

	m.logf("%s: up on %s as %s", name, iface, localIP)
	return m.options.Store.SetStatus(db.Status{
		ConnectionID: id,
		State:        db.StateUp,
		Iface:        iface,
		LocalIP:      localIP,
		PeerIP:       peerIP,
		ConnectedAt:  m.options.Now(),
	})
}

func (m *Manager) PPPDown(ctx context.Context, name, iface string) error {
	m.mu.Lock()
	tunnel, ok := m.tunnels[name]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("unknown connection %q", name)
	}
	if iface == "" {
		iface = tunnel.iface
	}
	subnets := append([]string(nil), tunnel.subnets...)
	m.mu.Unlock()

	if iface != "" {
		m.tearDownInterface(ctx, name, iface, subnets)
	}

	m.mu.Lock()
	tunnel.iface = ""
	tunnel.phase = db.StateDisconnected
	tunnel.retryAt = m.options.Now().Add(minRedialDelay)
	m.mu.Unlock()

	m.logf("%s: down", name)
	m.setStatus(tunnel.id, db.StateDisconnected, "")
	m.Nudge()
	return nil
}

// A tunnel that stops answering its health check is torn down fully so the
// next reconcile redials from scratch.
func (m *Manager) Unhealthy(ctx context.Context, name, reason string) {
	m.mu.Lock()
	tunnel, ok := m.tunnels[name]
	var iface string
	if ok {
		iface = tunnel.iface
	}
	m.mu.Unlock()
	if !ok {
		return
	}

	m.logf("%s: %s", name, reason)
	m.fail(ctx, name, iface, reason)
	m.Nudge()
}

func (m *Manager) advertise(ctx context.Context) error {
	routes, err := m.options.Store.AdvertisedRoutes()
	if err != nil {
		return err
	}
	sort.Strings(routes)
	joined := strings.Join(routes, ",")

	m.mu.Lock()
	unchanged := joined == m.advertised
	m.mu.Unlock()
	if unchanged || m.options.Tailnet == nil {
		return nil
	}
	if err := m.options.Tailnet.SetRoutes(ctx, routes); err != nil {
		return err
	}

	m.mu.Lock()
	m.advertised = joined
	m.mu.Unlock()
	m.logf("advertising %s", joined)
	return nil
}

// A restarted charon or xl2tpd comes back empty; the next reconcile must
// render and load again rather than trust its fingerprint.
func (m *Manager) Invalidate() {
	m.mu.Lock()
	m.rendered = map[string]string{}
	m.mu.Unlock()
	m.Nudge()
}

func (m *Manager) Status(name string) (db.State, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tunnel, ok := m.tunnels[name]; ok {
		return tunnel.phase, tunnel.iface
	}
	return db.StateDisconnected, ""
}

func (m *Manager) setStatus(id int64, phase db.State, reason string) {
	if err := m.options.Store.SetStatus(db.Status{ConnectionID: id, State: phase, LastError: reason}); err != nil {
		m.logf("connection %d: record status: %v", id, err)
	}
}

func (m *Manager) logf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if m.options.Logs != nil {
		m.options.Logs.Add("reconciler", message)
	}
	slog.Info("reconciler", "msg", message)
}

func redialDelay(failures int) time.Duration {
	delay := minRedialDelay << min(failures-1, 16)
	return min(delay, maxRedialDelay)
}

func fingerprintsOf(tunnels []Tunnel) map[string]string {
	prints := make(map[string]string, len(tunnels))
	for _, tunnel := range tunnels {
		prints[tunnel.Name] = fmt.Sprintf("%s|%s|%s|%s|%s|%s",
			tunnel.GatewayHost, tunnel.GatewayAddr, tunnel.PSK, tunnel.Username, tunnel.Password,
			strings.Join(tunnel.RemoteSubnets, ","))
	}
	return prints
}

func changedTunnels(rendered, wanted map[string]string, tunnels []Tunnel) []Tunnel {
	var changed []Tunnel
	for _, tunnel := range tunnels {
		if rendered[tunnel.Name] != wanted[tunnel.Name] {
			changed = append(changed, tunnel)
		}
	}
	return changed
}

func resolveHost(ctx context.Context, host string) (string, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("%s: no IPv4 address", host)
	}
	return addrs[0].String(), nil
}
