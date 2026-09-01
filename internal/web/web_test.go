package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	tsvvpn "tsv-vpn"
	"tsv-vpn/internal/crypto"
	"tsv-vpn/internal/db"
	"tsv-vpn/internal/discover"
	"tsv-vpn/internal/logbuf"
	"tsv-vpn/internal/tailnet"
)

const testPassword = "correct horse"

type fakeTunnels struct {
	nudges int
	state  db.State
	iface  string
}

func (t *fakeTunnels) Status(name string) (db.State, string) {
	if t.state == "" {
		return db.StateDisconnected, ""
	}
	return t.state, t.iface
}
func (t *fakeTunnels) Nudge() { t.nudges++ }

type fakeChecks struct {
	checked []string
}

func (c *fakeChecks) Check(ctx context.Context, conn db.Connection) {
	c.checked = append(c.checked, conn.Name)
}
func (c *fakeChecks) CheckSubnet(ctx context.Context, subnet db.LocalSubnet) {
	c.checked = append(c.checked, subnet.CIDR)
}

type fakeGateway struct {
	result discover.PreflightResult
	err    error
}

func (g fakeGateway) Test(ctx context.Context, host string) (discover.PreflightResult, error) {
	return g.result, g.err
}

func testServer(t *testing.T) *Server {
	t.Helper()
	key, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := crypto.New(key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(filepath.Join(t.TempDir(), "web.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{
		Store:    store,
		Tunnels:  &fakeTunnels{},
		Sessions: NewSessions(&Credentials{Store: store, EnvHash: hash}),
	}
}

func login(t *testing.T, server *Server) *http.Cookie {
	return loginWith(t, server, testPassword)
}

func loginWith(t *testing.T, server *Server, password string) *http.Cookie {
	t.Helper()
	form := url.Values{"password": {password}}
	request := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("login returned %d", response.Code)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookie {
			return cookie
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func TestDashboardRequiresASession(t *testing.T) {
	server := testServer(t)

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/", nil))

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Fatalf("got %d to %q", response.Code, response.Header().Get("Location"))
	}
}

func TestLoginGrantsAccessAndLogoutRevokesIt(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)

	request := httptest.NewRequest("GET", "/", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Connections") {
		t.Fatalf("got %d: %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest("POST", "/logout", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("logout returned %d", response.Code)
	}
	if server.Sessions.Valid(cookie.Value) {
		t.Fatal("session survived logout")
	}
}

func TestWrongPasswordIsRejected(t *testing.T) {
	server := testServer(t)
	form := url.Values{"password": {"wrong"}}
	request := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "Incorrect password") {
		t.Fatalf("got %d: %s", response.Code, response.Body.String())
	}
	if len(response.Result().Cookies()) != 0 {
		t.Fatal("issued a cookie for a wrong password")
	}
}

func TestHTMXRequestsGetARedirectHeader(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || response.Header().Get("HX-Redirect") != "/login" {
		t.Fatalf("got %d with %q", response.Code, response.Header().Get("HX-Redirect"))
	}
}

func TestStaticAssetsAreServed(t *testing.T) {
	server := testServer(t)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/static/app.css", nil))

	if response.Code != http.StatusOK || response.Body.Len() == 0 {
		t.Fatalf("got %d, %d bytes", response.Code, response.Body.Len())
	}
}

func addConnection(t *testing.T, server *Server, name string) db.Connection {
	t.Helper()
	id, err := server.Store.CreateConnection(db.Connection{
		Name:          name,
		GatewayHost:   name + ".example.com",
		PPPUsername:   "user",
		RemoteSubnets: []string{"198.51.100.0/24"},
		HealthCheckIP: "198.51.100.10",
		Enabled:       true,
	}, db.Secrets{PSK: "psk", PPPPassword: "password"})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := server.Store.Connection(id)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func do(t *testing.T, server *Server, method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func TestDashboardShowsConnectionCards(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	addConnection(t, server, "office")

	body := do(t, server, "GET", "/", cookie).Body.String()

	for _, want := range []string{"office", "office.example.com", "198.51.100.0/24", "Test now"} {
		if !strings.Contains(body, want) {
			t.Fatalf("card is missing %q", want)
		}
	}
}

func TestDisableWritesTheDatabaseAndNudgesTheReconciler(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	conn := addConnection(t, server, "office")

	response := do(t, server, "POST", fmt.Sprintf("/connections/%d/disable", conn.ID), cookie)

	if response.Code != http.StatusOK {
		t.Fatalf("got %d", response.Code)
	}
	updated, err := server.Store.Connection(conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Enabled {
		t.Fatal("connection is still enabled")
	}
	if server.Tunnels.(*fakeTunnels).nudges != 1 {
		t.Fatal("reconciler was not nudged")
	}
	if !strings.Contains(response.Body.String(), "Connect") {
		t.Fatalf("card still offers disconnect: %s", response.Body.String())
	}
}

func TestCheckNowRunsAHealthCheck(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	conn := addConnection(t, server, "office")
	checks := &fakeChecks{}
	server.Checks = checks

	do(t, server, "POST", fmt.Sprintf("/connections/%d/check", conn.ID), cookie)

	if len(checks.checked) != 1 || checks.checked[0] != "office" {
		t.Fatalf("checked %v", checks.checked)
	}
}

func TestDeleteRemovesTheConnection(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	conn := addConnection(t, server, "office")

	response := do(t, server, "DELETE", fmt.Sprintf("/connections/%d", conn.ID), cookie)

	if response.Code != http.StatusOK {
		t.Fatalf("got %d", response.Code)
	}
	if _, err := server.Store.Connection(conn.ID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("connection survived delete: %v", err)
	}
}

func TestLogsFragmentShowsRingLines(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	conn := addConnection(t, server, "office")
	server.Logs = logbuf.New(10, func() []string { return []string{"office"} })
	server.Logs.Add("charon", "office: IKE_SA established")

	body := do(t, server, "GET", fmt.Sprintf("/connections/%d/logs", conn.ID), cookie).Body.String()

	if !strings.Contains(body, "IKE_SA established") {
		t.Fatalf("got %s", body)
	}
}

func post(t *testing.T, server *Server, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func connectionForm() url.Values {
	return url.Values{
		"name":            {"office"},
		"gateway_host":    {"vpn.example.com"},
		"psk":             {"psk-value"},
		"ppp_username":    {"user"},
		"ppp_password":    {"ppp-value"},
		"remote_subnets":  {"198.51.100.0/24\n203.0.113.0/24"},
		"health_check_ip": {"198.51.100.10"},
		"enabled":         {"1"},
	}
}

func TestCreateConnectionStoresEncryptedSecrets(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)

	response := post(t, server, "/connections", connectionForm(), cookie)

	if response.Code != http.StatusNoContent || response.Header().Get("HX-Redirect") != "/" {
		t.Fatalf("got %d with %q", response.Code, response.Header().Get("HX-Redirect"))
	}
	conns, err := server.Store.ListConnections()
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 1 || len(conns[0].RemoteSubnets) != 2 {
		t.Fatalf("stored %+v", conns)
	}
	secrets, err := server.Store.ConnectionSecrets(conns[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if secrets.PSK != "psk-value" || secrets.PPPPassword != "ppp-value" {
		t.Fatalf("secrets round-tripped as %+v", secrets)
	}
}

func TestInvalidFormComesBackWithTheError(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	form := connectionForm()
	form.Set("remote_subnets", "198.51.100.5/24")

	response := post(t, server, "/connections", form, cookie)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("got %d", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, "host bits set") || !strings.Contains(body, `value="office"`) {
		t.Fatalf("got %s", body)
	}
}

func TestEditKeepsSecretsWhenFieldsAreBlank(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	conn := addConnection(t, server, "office")

	form := connectionForm()
	form.Set("psk", "")
	form.Set("ppp_password", "")
	form.Set("gateway_host", "vpn2.example.com")
	response := post(t, server, fmt.Sprintf("/connections/%d", conn.ID), form, cookie)

	if response.Code != http.StatusNoContent {
		t.Fatalf("got %d: %s", response.Code, response.Body.String())
	}
	updated, err := server.Store.Connection(conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.GatewayHost != "vpn2.example.com" {
		t.Fatalf("gateway is %q", updated.GatewayHost)
	}
	secrets, err := server.Store.ConnectionSecrets(conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if secrets.PSK != "psk" || secrets.PPPPassword != "password" {
		t.Fatalf("secrets changed: %+v", secrets)
	}
}

func TestEditFormNeverShowsASecret(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	conn := addConnection(t, server, "office")

	body := do(t, server, "GET", fmt.Sprintf("/connections/%d/edit", conn.ID), cookie).Body.String()

	if strings.Contains(body, "psk") && strings.Contains(body, "value=\"psk\"") {
		t.Fatal("form rendered the stored psk")
	}
	if !strings.Contains(body, "leave blank to keep") {
		t.Fatalf("got %s", body)
	}
}

func TestPreflightReportsResolvedAddress(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	server.Gateway = fakeGateway{result: discover.PreflightResult{
		Addr: netip.MustParseAddr("203.0.113.9"),
		RTT:  3 * time.Millisecond,
	}}

	body := post(t, server, "/connections/preflight", url.Values{"gateway_host": {"vpn.example.com"}}, cookie).Body.String()

	if !strings.Contains(body, "203.0.113.9") || !strings.Contains(body, "3.0 ms") {
		t.Fatalf("got %s", body)
	}
}

func TestPreflightReportsResolutionFailure(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	server.Gateway = fakeGateway{err: errors.New("vpn.invalid does not resolve to an IPv4 address")}

	body := post(t, server, "/connections/preflight", url.Values{"gateway_host": {"vpn.invalid"}}, cookie).Body.String()

	if !strings.Contains(body, "does not resolve") {
		t.Fatalf("got %s", body)
	}
}

type fakeTailnet struct {
	status    tailnet.Status
	err       error
	logins    []string
	exitNodes []bool
}

func (t *fakeTailnet) Status(ctx context.Context) (tailnet.Status, error) {
	return t.status, t.err
}

func (t *fakeTailnet) Up(ctx context.Context, hostname, authKey string, routes []string, exitNode bool) error {
	t.logins = append(t.logins, authKey)
	if t.err != nil {
		return t.err
	}
	t.status.BackendState = tailnet.StateRunning
	return nil
}

func (t *fakeTailnet) SetExitNode(ctx context.Context, enabled bool) error {
	t.exitNodes = append(t.exitNodes, enabled)
	return t.err
}

func approvedTailnet(routes ...string) *fakeTailnet {
	tn := &fakeTailnet{}
	tn.status.BackendState = tailnet.StateRunning
	tn.status.Self.PrimaryRoutes = routes
	return tn
}

func TestSubnetsPageListsLocalAndTunnelRoutes(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	addConnection(t, server, "office")
	if _, err := server.Store.CreateLocalSubnet(db.LocalSubnet{CIDR: "192.0.2.0/24", Description: "home LAN", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	server.Tailnet = approvedTailnet("192.0.2.0/24")

	body := do(t, server, "GET", "/subnets", cookie).Body.String()

	if !strings.Contains(body, "192.0.2.0/24") || !strings.Contains(body, "home LAN") {
		t.Fatalf("local subnet missing: %s", body)
	}
	if !strings.Contains(body, "198.51.100.0/24") || !strings.Contains(body, "office") {
		t.Fatal("tunnel subnet missing")
	}
	if strings.Count(body, "approval pending") != 1 {
		t.Fatal("want the unapproved tunnel subnet flagged and the approved local one not")
	}
}

func TestAddingAnOverlappingSubnetIsRejected(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	addConnection(t, server, "office")

	response := post(t, server, "/subnets", url.Values{"cidr": {"198.51.100.0/25"}}, cookie)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("got %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "overlaps") {
		t.Fatalf("got %s", response.Body.String())
	}
}

func TestSubnetToggleAndRemoval(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	id, err := server.Store.CreateLocalSubnet(db.LocalSubnet{CIDR: "192.0.2.0/24", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	post(t, server, fmt.Sprintf("/subnets/%d/disable", id), nil, cookie)
	subnets, err := server.Store.ListLocalSubnets()
	if err != nil {
		t.Fatal(err)
	}
	if subnets[0].Enabled {
		t.Fatal("subnet is still enabled")
	}

	do(t, server, "DELETE", fmt.Sprintf("/subnets/%d", id), cookie)
	subnets, err = server.Store.ListLocalSubnets()
	if err != nil {
		t.Fatal(err)
	}
	if len(subnets) != 0 {
		t.Fatalf("subnet survived removal: %+v", subnets)
	}
	if server.Tunnels.(*fakeTunnels).nudges != 2 {
		t.Fatalf("reconciler nudged %d times", server.Tunnels.(*fakeTunnels).nudges)
	}
}

type fakeScanner struct {
	hosts   []discover.Result
	release chan struct{}

	mu         sync.Mutex
	sweptIface string
}

func (s *fakeScanner) Sweep(ctx context.Context, prefix netip.Prefix, iface string, results chan<- discover.Result) error {
	s.mu.Lock()
	s.sweptIface = iface
	s.mu.Unlock()
	for _, host := range s.hosts {
		results <- host
	}
	if s.release != nil {
		<-s.release
	}
	return nil
}

func (s *fakeScanner) iface() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweptIface
}

func TestScanReportsHostsAndStopsPolling(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	release := make(chan struct{})
	server.Scanner = &fakeScanner{
		hosts:   []discover.Result{{Addr: netip.MustParseAddr("192.0.2.10"), RTT: 2 * time.Millisecond, Name: "printer.lan"}},
		release: release,
	}

	body := post(t, server, "/scans", url.Values{"cidr": {"192.0.2.0/24"}}, cookie).Body.String()
	if !strings.Contains(body, "hx-get=\"/scans/") || !strings.Contains(body, "scanning") {
		t.Fatalf("first fragment does not poll: %s", body)
	}
	id := strings.Split(strings.Split(body, "hx-get=\"/scans/")[1], "\"")[0]

	close(release)
	var final string
	for range 50 {
		final = do(t, server, "GET", "/scans/"+id, cookie).Body.String()
		if strings.Contains(final, "done") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(final, "192.0.2.10") || !strings.Contains(final, "printer.lan") {
		t.Fatalf("results missing: %s", final)
	}
	if strings.Contains(final, "hx-get=\"/scans/") {
		t.Fatal("finished scan still polls")
	}
}

func TestScanningATunnelSubnetUsesItsInterface(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	conn := addConnection(t, server, "office")
	server.Tunnels = &fakeTunnels{state: db.StateUp, iface: "ppp0"}
	scanner := &fakeScanner{}
	server.Scanner = scanner

	post(t, server, "/scans", url.Values{
		"cidr":          {"198.51.100.0/24"},
		"connection_id": {fmt.Sprint(conn.ID)},
	}, cookie)

	for range 50 {
		if scanner.iface() != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if scanner.iface() != "ppp0" {
		t.Fatalf("swept from %q", scanner.iface())
	}
}

func TestScanningADownTunnelIsRefused(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	conn := addConnection(t, server, "office")
	server.Scanner = &fakeScanner{}

	body := post(t, server, "/scans", url.Values{
		"cidr":          {"198.51.100.0/24"},
		"connection_id": {fmt.Sprint(conn.ID)},
	}, cookie).Body.String()

	if !strings.Contains(body, "is not up") {
		t.Fatalf("got %s", body)
	}
}

func TestScanRefusesSubnetsLargerThanA22(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	server.Scanner = &fakeScanner{}

	body := post(t, server, "/scans", url.Values{"cidr": {"10.0.0.0/8"}}, cookie).Body.String()

	if !strings.Contains(body, "larger than /22") {
		t.Fatalf("got %s", body)
	}
}

func TestScanResultBecomesTheHealthCheck(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	conn := addConnection(t, server, "office")

	post(t, server, fmt.Sprintf("/connections/%d/health-check", conn.ID), url.Values{"ip": {"198.51.100.42"}}, cookie)

	updated, err := server.Store.Connection(conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.HealthCheckIP != "198.51.100.42" {
		t.Fatalf("health check is %q", updated.HealthCheckIP)
	}
}

func TestTailnetPageOffersBothWaysIn(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	server.Tailnet = &fakeTailnet{status: tailnet.Status{
		BackendState: "NeedsLogin",
		AuthURL:      "https://login.tailscale.com/a/abc123",
	}}

	body := do(t, server, "GET", "/tailnet", cookie).Body.String()

	if !strings.Contains(body, "https://login.tailscale.com/a/abc123") {
		t.Fatal("no login link")
	}
	if !strings.Contains(body, `name="authkey"`) {
		t.Fatal("no auth key field")
	}
	if !strings.Contains(body, `hx-get="/tailnet/status"`) {
		t.Fatal("page does not poll while waiting")
	}
}

func TestTailnetLoginUsesTheKey(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	tn := &fakeTailnet{status: tailnet.Status{BackendState: "NeedsLogin"}}
	server.Tailnet = tn
	server.Hostname = "tsv-vpn"

	body := post(t, server, "/tailnet/login", url.Values{"authkey": {"tskey-auth-abc"}}, cookie).Body.String()

	if len(tn.logins) != 1 || tn.logins[0] != "tskey-auth-abc" {
		t.Fatalf("logins: %v", tn.logins)
	}
	if !strings.Contains(body, "Running") || strings.Contains(body, `name="authkey"`) {
		t.Fatalf("still offering login: %s", body)
	}
}

func TestExitNodeToggleStoresAndApplies(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	tn := approvedTailnet()
	server.Tailnet = tn
	server.Hostname = "tsv-vpn"

	body := post(t, server, "/tailnet/exit-node", url.Values{"enabled": {"1"}}, cookie).Body.String()

	if enabled, err := server.Store.ExitNode(); err != nil || !enabled {
		t.Fatalf("setting not stored (enabled=%v, err=%v)", enabled, err)
	}
	if len(tn.exitNodes) != 1 || !tn.exitNodes[0] {
		t.Fatalf("tailscale calls: %v", tn.exitNodes)
	}
	if !strings.Contains(body, "Disable exit node") || !strings.Contains(body, "approval pending") {
		t.Fatalf("got %s", body)
	}

	body = post(t, server, "/tailnet/exit-node", url.Values{"enabled": {"0"}}, cookie).Body.String()

	if enabled, _ := server.Store.ExitNode(); enabled {
		t.Fatal("setting not cleared")
	}
	if !strings.Contains(body, "Enable exit node") {
		t.Fatalf("got %s", body)
	}
}

func TestExitNodeShowsApprovedOnceTheTailnetAgrees(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	tn := approvedTailnet()
	tn.status.Self.ExitNodeOption = true
	server.Tailnet = tn
	if err := server.Store.SetExitNode(true); err != nil {
		t.Fatal(err)
	}

	body := do(t, server, "GET", "/tailnet", cookie).Body.String()

	if !strings.Contains(body, "Disable exit node") || strings.Contains(body, "approval pending") {
		t.Fatalf("got %s", body)
	}
}

func TestTailnetPageRendersTheEffectiveCommand(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	server.Tailnet = approvedTailnet()
	server.Hostname = "tsv-vpn"
	if _, err := server.Store.CreateLocalSubnet(db.LocalSubnet{CIDR: "192.0.2.0/24", Description: "lan", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := server.Store.SetExitNode(true); err != nil {
		t.Fatal(err)
	}

	body := do(t, server, "GET", "/tailnet", cookie).Body.String()

	want := "tailscale up --hostname=tsv-vpn --accept-dns=false --advertise-routes=192.0.2.0/24 --advertise-exit-node=true"
	if !strings.Contains(body, want) {
		t.Fatalf("command not rendered: %s", body)
	}
	if strings.Contains(body, "--authkey=") {
		t.Fatal("command mentions the auth key")
	}
}

func TestTailnetPageShowsRouteApprovalAndACL(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	addConnection(t, server, "office")
	if _, err := server.Store.CreateLocalSubnet(db.LocalSubnet{CIDR: "192.168.50.0/24", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	server.Tailnet = approvedTailnet("192.168.50.0/24")

	body := do(t, server, "GET", "/tailnet", cookie).Body.String()

	if strings.Count(body, "approval pending") != 1 || strings.Count(body, ">approved") != 1 {
		t.Fatalf("route approval not reported per route: %s", body)
	}
	if !strings.Contains(body, "192.168.0.0/16") || !strings.Contains(body, "tag:subnet-router") {
		t.Fatal("acl snippet is missing from the page")
	}
}

func TestAutoApproverACLCoversEveryAdvertisedRoute(t *testing.T) {
	acl := autoApproverACL([]string{"192.168.50.0/24", "10.20.0.0/16", "198.51.100.0/24"})

	for _, want := range []string{
		`"10.0.0.0/8": ["tag:subnet-router"]`,
		`"192.168.0.0/16": ["tag:subnet-router"]`,
		`"198.51.100.0/24": ["tag:subnet-router"]`,
	} {
		if !strings.Contains(acl, want) {
			t.Fatalf("missing %s in:\n%s", want, acl)
		}
	}
	if strings.Contains(acl, `"172.16.0.0/12"`) {
		t.Fatalf("added a range nothing advertises:\n%s", acl)
	}
}

func TestDashboardWarnsWhenTheNodeHasNotJoined(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	server.Tailnet = &fakeTailnet{status: tailnet.Status{BackendState: "NeedsLogin"}}

	body := do(t, server, "GET", "/", cookie).Body.String()
	if !strings.Contains(body, "has not joined a tailnet") {
		t.Fatal("no warning on the dashboard")
	}

	server.Tailnet = approvedTailnet()
	body = do(t, server, "GET", "/", cookie).Body.String()
	if strings.Contains(body, "has not joined a tailnet") {
		t.Fatal("warning shown while joined")
	}
}

func setupServer(t *testing.T) *Server {
	t.Helper()
	server := testServer(t)
	server.Sessions = NewSessions(&Credentials{Store: server.Store})
	return server
}

func TestABlankSlateSendsEveryPageToSetup(t *testing.T) {
	server := setupServer(t)

	for _, path := range []string{"/", "/subnets", "/tailnet", "/login"} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, httptest.NewRequest("GET", path, nil))
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/setup" {
			t.Fatalf("%s returned %d to %q", path, response.Code, response.Header().Get("Location"))
		}
	}

	body := do(t, server, "GET", "/setup", &http.Cookie{Name: sessionCookie}).Body.String()
	if !strings.Contains(body, "Choose an admin password") {
		t.Fatalf("got %s", body)
	}
}

func TestSetupStoresThePasswordAndSignsIn(t *testing.T) {
	server := setupServer(t)

	response := post(t, server, "/setup", url.Values{
		"password": {"a-long-enough-one"},
		"confirm":  {"a-long-enough-one"},
	}, &http.Cookie{Name: sessionCookie})

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/" {
		t.Fatalf("got %d to %q", response.Code, response.Header().Get("Location"))
	}
	var cookie *http.Cookie
	for _, candidate := range response.Result().Cookies() {
		if candidate.Name == sessionCookie {
			cookie = candidate
		}
	}
	if cookie == nil {
		t.Fatal("setup did not sign the operator in")
	}
	if do(t, server, "GET", "/", cookie).Code != http.StatusOK {
		t.Fatal("session from setup does not work")
	}

	if server.Sessions.Credentials.NeedsSetup() {
		t.Fatal("still in setup after choosing a password")
	}
	if !server.Sessions.Credentials.Matches("a-long-enough-one") {
		t.Fatal("stored password does not verify")
	}
	stored, err := server.Store.Setting(passwordSetting)
	if err != nil || strings.Contains(stored, "a-long-enough-one") {
		t.Fatalf("password stored in the clear: %q %v", stored, err)
	}
}

func TestSetupClosesAfterTheFirstPassword(t *testing.T) {
	server := setupServer(t)
	post(t, server, "/setup", url.Values{
		"password": {"a-long-enough-one"},
		"confirm":  {"a-long-enough-one"},
	}, &http.Cookie{Name: sessionCookie})

	response := post(t, server, "/setup", url.Values{
		"password": {"someone-elses-password"},
		"confirm":  {"someone-elses-password"},
	}, &http.Cookie{Name: sessionCookie})
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Fatalf("setup still open: %d to %q", response.Code, response.Header().Get("Location"))
	}
	if !server.Sessions.Credentials.Matches("a-long-enough-one") {
		t.Fatal("a second setup overwrote the password")
	}
}

func TestSetupRejectsShortAndMismatchedPasswords(t *testing.T) {
	server := setupServer(t)

	for _, form := range []url.Values{
		{"password": {"short"}, "confirm": {"short"}},
		{"password": {"a-long-enough-one"}, "confirm": {"a-different-one"}},
	} {
		response := post(t, server, "/setup", form, &http.Cookie{Name: sessionCookie})
		if response.Code != http.StatusUnprocessableEntity {
			t.Fatalf("accepted %v with %d", form, response.Code)
		}
	}
	if !server.Sessions.Credentials.NeedsSetup() {
		t.Fatal("a rejected password was stored anyway")
	}
}

func TestAnEnvironmentHashSkipsSetupEntirely(t *testing.T) {
	server := testServer(t)

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/", nil))
	if response.Header().Get("Location") != "/login" {
		t.Fatalf("sent to %q", response.Header().Get("Location"))
	}

	if err := server.Sessions.Credentials.Set("a-long-enough-one"); err == nil {
		t.Fatal("the ui overrode ADMIN_PASSWORD_HASH")
	}
}

func TestChangingThePasswordRetiresTheOldOne(t *testing.T) {
	server := setupServer(t)
	post(t, server, "/setup", url.Values{
		"password": {"the-first-password"},
		"confirm":  {"the-first-password"},
	}, &http.Cookie{Name: sessionCookie})

	form := url.Values{"password": {"the-second-password"}}
	request := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	before := httptest.NewRecorder()
	server.Handler().ServeHTTP(before, request)
	if before.Code != http.StatusUnauthorized {
		t.Fatal("the new password already works")
	}

	cookie := loginWith(t, server, "the-first-password")
	response := post(t, server, "/password", url.Values{
		"current":  {"the-first-password"},
		"password": {"the-second-password"},
		"confirm":  {"the-second-password"},
	}, cookie)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Password changed") {
		t.Fatalf("got %d: %s", response.Code, response.Body.String())
	}

	if server.Sessions.Credentials.Matches("the-first-password") {
		t.Fatal("the old password still works")
	}
	if !server.Sessions.Credentials.Matches("the-second-password") {
		t.Fatal("the new password does not work")
	}
}

func TestChangingThePasswordSignsOutOtherBrowsers(t *testing.T) {
	server := setupServer(t)
	post(t, server, "/setup", url.Values{
		"password": {"the-first-password"},
		"confirm":  {"the-first-password"},
	}, &http.Cookie{Name: sessionCookie})

	elsewhere := loginWith(t, server, "the-first-password")
	here := loginWith(t, server, "the-first-password")

	response := post(t, server, "/password", url.Values{
		"current":  {"the-first-password"},
		"password": {"the-second-password"},
		"confirm":  {"the-second-password"},
	}, here)

	var reissued *http.Cookie
	for _, candidate := range response.Result().Cookies() {
		if candidate.Name == sessionCookie {
			reissued = candidate
		}
	}
	if reissued == nil {
		t.Fatal("the browser that changed it was not reissued a session")
	}
	if server.Sessions.Valid(elsewhere.Value) {
		t.Fatal("another session survived the change")
	}
	if do(t, server, "GET", "/", reissued).Code != http.StatusOK {
		t.Fatal("the reissued session does not work")
	}
}

func TestChangingThePasswordNeedsTheCurrentOne(t *testing.T) {
	server := setupServer(t)
	post(t, server, "/setup", url.Values{
		"password": {"the-first-password"},
		"confirm":  {"the-first-password"},
	}, &http.Cookie{Name: sessionCookie})
	cookie := loginWith(t, server, "the-first-password")

	response := post(t, server, "/password", url.Values{
		"current":  {"not-the-password"},
		"password": {"the-second-password"},
		"confirm":  {"the-second-password"},
	}, cookie)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("got %d", response.Code)
	}
	if !server.Sessions.Credentials.Matches("the-first-password") {
		t.Fatal("the password changed anyway")
	}
}

func TestAnEnvironmentHashCannotBeChangedInTheUI(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)

	body := do(t, server, "GET", "/password", cookie).Body.String()
	if !strings.Contains(body, "ADMIN_PASSWORD_HASH") || strings.Contains(body, `name="current"`) {
		t.Fatalf("got %s", body)
	}

	response := post(t, server, "/password", url.Values{
		"current":  {testPassword},
		"password": {"a-long-enough-one"},
		"confirm":  {"a-long-enough-one"},
	}, cookie)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("got %d", response.Code)
	}
	if !server.Sessions.Credentials.Matches(testPassword) {
		t.Fatal("the environment password was replaced")
	}
}

type fakeProber struct {
	calls int
	hops  []netip.Addr
}

func (p *fakeProber) Hops(ctx context.Context) ([]netip.Addr, error) {
	p.calls++
	return p.hops, nil
}

func TestSubnetsPageOffersTheProbedLAN(t *testing.T) {
	server := testServer(t)
	prober := &fakeProber{hops: []netip.Addr{netip.MustParseAddr("10.222.222.1")}}
	server.Prober = prober
	cookie := login(t, server)

	body := do(t, server, "GET", "/subnets", cookie).Body.String()
	if !strings.Contains(body, "10.222.222.0/24") {
		t.Fatalf("probed LAN not offered: %s", body)
	}
	if !strings.Contains(body, "found on the path to the internet") {
		t.Fatal("probe candidate carries no description")
	}

	do(t, server, "GET", "/subnets", cookie)
	if prober.calls != 1 {
		t.Fatalf("probe ran %d times, want it cached after the first", prober.calls)
	}
}

func TestReleasesPageRendersTheChangelog(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)

	body := do(t, server, "GET", "/releases", cookie).Body.String()
	if !strings.Contains(body, tsvvpn.Version) {
		t.Fatalf("release notes missing version %s", tsvvpn.Version)
	}
	if !strings.Contains(body, "The first versioned release.") {
		t.Fatal("release notes missing the changelog body")
	}
}

func TestEveryPageLinksTheRunningVersion(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)

	body := do(t, server, "GET", "/", cookie).Body.String()
	if !strings.Contains(body, "tsv-vpn "+tsvvpn.Version) || !strings.Contains(body, `href="/releases"`) {
		t.Fatal("footer does not link the running version to the release notes")
	}
}

func TestVersionIsHiddenUntilLoggedIn(t *testing.T) {
	server := testServer(t)

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/login", nil))
	if strings.Contains(response.Body.String(), tsvvpn.Version) {
		t.Fatal("login page leaks the version")
	}

	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/setup", nil))
	if strings.Contains(response.Body.String(), tsvvpn.Version) {
		t.Fatal("setup page leaks the version")
	}
}

func TestConnectionCardShowsAssignedAddresses(t *testing.T) {
	server := testServer(t)
	cookie := login(t, server)
	conn := addConnection(t, server, "office")
	server.Tunnels = &fakeTunnels{state: db.StateUp, iface: "ppp0"}
	if err := server.Store.SetStatus(db.Status{
		ConnectionID: conn.ID, State: db.StateUp, Iface: "ppp0",
		LocalIP: "10.0.9.2", PeerIP: "10.0.9.1", ConnectedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	body := do(t, server, "GET", "/", cookie).Body.String()
	if !strings.Contains(body, "10.0.9.2") || !strings.Contains(body, "10.0.9.1") {
		t.Fatalf("card misses the assigned addresses: %s", body)
	}
}
func TestLocalSubnetHealthChecks(t *testing.T) {
	server := testServer(t)
	checks := &fakeChecks{}
	server.Checks = checks
	cookie := login(t, server)
	id, err := server.Store.CreateLocalSubnet(db.LocalSubnet{CIDR: "192.0.2.0/24", Description: "office", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	post(t, server, fmt.Sprintf("/subnets/%d/health-check", id), url.Values{"ip": {"192.0.2.10"}}, cookie)
	subnet, err := server.Store.LocalSubnet(id)
	if err != nil {
		t.Fatal(err)
	}
	if subnet.HealthCheckIP != "192.0.2.10" {
		t.Fatalf("health check ip not stored: %+v", subnet)
	}

	// The subnets page form targets the panel and gets it back re-rendered.
	request := httptest.NewRequest("POST", fmt.Sprintf("/subnets/%d/health-check", id), strings.NewReader(url.Values{"ip": {"192.0.2.20"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Target", "subnet-panel")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if !strings.Contains(response.Body.String(), `id="subnet-panel"`) || !strings.Contains(response.Body.String(), "192.0.2.20") {
		t.Fatalf("expected re-rendered subnet panel: %s", response.Body.String())
	}

	post(t, server, fmt.Sprintf("/subnets/%d/check", id), nil, cookie)
	if len(checks.checked) != 1 || checks.checked[0] != "192.0.2.0/24" {
		t.Fatalf("check not triggered: %v", checks.checked)
	}

	body := do(t, server, "GET", "/", cookie).Body.String()
	if !strings.Contains(body, "Local networks") || !strings.Contains(body, "192.0.2.0/24") {
		t.Fatal("dashboard does not show the local network")
	}
	if err := server.Store.RecordSubnetCheck(id, time.Now(), 3200*time.Microsecond, ""); err != nil {
		t.Fatal(err)
	}
	body = do(t, server, "GET", "/subnets/health", cookie).Body.String()
	if !strings.Contains(body, "3.2 ms") {
		t.Fatalf("health fragment misses the rtt: %s", body)
	}
}
