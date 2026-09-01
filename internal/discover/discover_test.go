package discover

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func prefix(t *testing.T, cidr string) netip.Prefix {
	t.Helper()
	parsed, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestCandidates(t *testing.T) {
	ifaces := []Iface{
		{Name: "lo", Addrs: []netip.Prefix{prefix(t, "127.0.0.1/8")}},
		{Name: "eth0", Addrs: []netip.Prefix{prefix(t, "172.20.0.5/16"), prefix(t, "169.254.1.1/16")}},
		{Name: "ppp0", Addrs: []netip.Prefix{prefix(t, "10.99.0.2/32")}},
		{Name: "tailscale0", Addrs: []netip.Prefix{prefix(t, "100.64.0.1/32")}},
	}
	routes := []Route{
		{Iface: "eth0", Dest: prefix(t, "0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.7.1")},
		{Iface: "eth0", Dest: prefix(t, "172.20.0.0/16"), Gateway: netip.MustParseAddr("0.0.0.0")},
	}

	got := Candidates(ifaces, routes)
	want := []Candidate{
		{Iface: "eth0", CIDR: "172.20.0.0/16", Source: SourceInterface},
		{Iface: "eth0", CIDR: "192.168.7.0/24", Source: SourceGateway},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestCandidatesSkipsDuplicateGatewayGuess(t *testing.T) {
	ifaces := []Iface{{Name: "eth0", Addrs: []netip.Prefix{prefix(t, "192.168.7.10/24")}}}
	routes := []Route{{Iface: "eth0", Dest: prefix(t, "0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.7.1")}}

	got := Candidates(ifaces, routes)
	if len(got) != 1 || got[0].Source != SourceInterface {
		t.Fatalf("got %+v", got)
	}
}

func TestParseRoutes(t *testing.T) {
	const table = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	010014AC	0003	0	0	0	00000000	0	0	0
eth0	000014AC	00000000	0001	0	0	0	0000FFFF	0	0	0
`
	routes, err := ParseRoutes(strings.NewReader(table))
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("got %d routes", len(routes))
	}
	if routes[0].Dest.String() != "0.0.0.0/0" || routes[0].Gateway.String() != "172.20.0.1" {
		t.Fatalf("default route: got %+v", routes[0])
	}
	if routes[1].Dest.String() != "172.20.0.0/16" || !routes[1].Gateway.IsUnspecified() {
		t.Fatalf("link route: got %+v", routes[1])
	}
}

func TestHosts(t *testing.T) {
	hosts, err := Hosts(prefix(t, "192.0.2.0/29"))
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 6 || hosts[0].String() != "192.0.2.1" || hosts[5].String() != "192.0.2.6" {
		t.Fatalf("got %v", hosts)
	}

	single, err := Hosts(prefix(t, "192.0.2.7/32"))
	if err != nil {
		t.Fatal(err)
	}
	if len(single) != 1 || single[0].String() != "192.0.2.7" {
		t.Fatalf("got %v", single)
	}

	if _, err := Hosts(prefix(t, "10.0.0.0/8")); err == nil {
		t.Fatal("want error for a subnet larger than /22")
	}
	if _, err := Hosts(prefix(t, "2001:db8::/64")); err == nil {
		t.Fatal("want error for IPv6")
	}
}

type fakePinger struct {
	alive map[string]time.Duration
}

func (f fakePinger) Ping(ctx context.Context, addr netip.Addr) (time.Duration, error) {
	if rtt, ok := f.alive[addr.String()]; ok {
		return rtt, nil
	}
	return 0, errors.New("timeout")
}

func TestSweepReportsOnlyResponders(t *testing.T) {
	sweeper := Sweeper{
		Pinger:  fakePinger{alive: map[string]time.Duration{"192.0.2.3": 2 * time.Millisecond}},
		Workers: 4,
		Lookup:  func(context.Context, netip.Addr) string { return "host.example.com" },
	}

	results := make(chan Result, 8)
	if err := sweeper.Sweep(t.Context(), prefix(t, "192.0.2.0/29"), results); err != nil {
		t.Fatal(err)
	}
	close(results)

	var got []Result
	for result := range results {
		got = append(got, result)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Addr.String() != "192.0.2.3" || got[0].RTT != 2*time.Millisecond || got[0].Name != "host.example.com" {
		t.Fatalf("got %+v", got[0])
	}
}

func TestSweepRefusesOversizedSubnet(t *testing.T) {
	sweeper := Sweeper{Pinger: fakePinger{}}
	if err := sweeper.Sweep(t.Context(), prefix(t, "10.0.0.0/16"), make(chan Result, 1)); err == nil {
		t.Fatal("want error")
	}
}

func TestSweepStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	sweeper := Sweeper{Pinger: fakePinger{}, Workers: 2}
	err := sweeper.Sweep(ctx, prefix(t, "192.0.2.0/24"), make(chan Result))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestHopCandidates(t *testing.T) {
	ifaces := []Iface{
		{Name: "eth0", Addrs: []netip.Prefix{prefix(t, "172.18.0.5/16")}},
	}
	hops := []netip.Addr{
		netip.MustParseAddr("172.18.0.1"),  // docker bridge, on an interface
		netip.MustParseAddr("192.168.1.1"), // the LAN router behind the host
		netip.MustParseAddr("192.168.1.1"), // answered twice, kept once
		netip.MustParseAddr("100.64.17.1"), // carrier NAT, not a LAN
		netip.MustParseAddr("203.0.113.9"), // public router, not a LAN
	}

	got := HopCandidates(hops, ifaces)
	want := []Candidate{{CIDR: "192.168.1.0/24", Source: SourceProbe}}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestCandidatesSkipsGatewayOnInterfaceSubnet(t *testing.T) {
	// The default gateway is the docker bridge; a /24 guessed from it would
	// duplicate the bridge network.
	ifaces := []Iface{{Name: "eth0", Addrs: []netip.Prefix{prefix(t, "172.18.0.5/16")}}}
	routes := []Route{{Iface: "eth0", Dest: prefix(t, "0.0.0.0/0"), Gateway: netip.MustParseAddr("172.18.0.1")}}

	got := Candidates(ifaces, routes)
	want := []Candidate{{Iface: "eth0", CIDR: "172.18.0.0/16", Source: SourceInterface}}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestQuotesEchoID(t *testing.T) {
	quoted := make([]byte, 28)
	quoted[0] = 0x45 // IPv4, 20-byte header
	quoted[20] = 8   // echo request
	quoted[24], quoted[25] = 0xab, 0xcd

	if !quotesEchoID(quoted, 0xabcd) {
		t.Fatal("matching id not recognised")
	}
	if quotesEchoID(quoted, 0x1234) {
		t.Fatal("wrong id accepted")
	}
	if quotesEchoID(quoted[:10], 0xabcd) {
		t.Fatal("truncated quote accepted")
	}
}
