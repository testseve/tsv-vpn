package discover

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Probe finds the LAN a bridged container can't see on its interfaces: walk
// toward the internet with rising TTLs and collect the routers that answer
// Time Exceeded past the first hop.
type Probe struct {
	Target  netip.Addr    // defaults to 1.1.1.1
	MaxHops int           // defaults to 4
	Timeout time.Duration // per hop, defaults to 500ms
}

func (p Probe) Hops(ctx context.Context) ([]netip.Addr, error) {
	target := p.Target
	if !target.IsValid() {
		target = netip.AddrFrom4([4]byte{1, 1, 1, 1})
	}
	maxHops := p.MaxHops
	if maxHops <= 0 {
		maxHops = 4
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	packet := conn.IPv4PacketConn()

	var hops []netip.Addr
	for ttl := 1; ttl <= maxHops; ttl++ {
		if err := ctx.Err(); err != nil {
			return hops, err
		}
		hop, done, err := p.probeHop(ctx, conn, packet, target, ttl, timeout)
		if err != nil {
			return hops, err
		}
		if hop.IsValid() {
			hops = append(hops, hop)
		}
		if done {
			break
		}
	}
	return hops, nil
}

func (p Probe) probeHop(ctx context.Context, conn *icmp.PacketConn, packet *ipv4.PacketConn, target netip.Addr, ttl int, timeout time.Duration) (netip.Addr, bool, error) {
	if err := packet.SetTTL(ttl); err != nil {
		return netip.Addr{}, false, err
	}

	id := int(binary.BigEndian.Uint16(randomBytes(2)))
	request, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: id, Seq: ttl, Data: []byte("tsv-vpn probe")},
	}).Marshal(nil)
	if err != nil {
		return netip.Addr{}, false, err
	}

	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return netip.Addr{}, false, err
	}
	if _, err := conn.WriteTo(request, &net.IPAddr{IP: target.AsSlice()}); err != nil {
		return netip.Addr{}, false, err
	}

	// The raw socket sees every ICMP packet on the host; skip replies that
	// don't quote this probe's id. A timeout is a silent hop, not a failure.
	reply := make([]byte, 1500)
	for {
		read, peer, err := conn.ReadFrom(reply)
		if err != nil {
			if os.IsTimeout(err) {
				return netip.Addr{}, false, nil
			}
			return netip.Addr{}, false, err
		}
		message, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply[:read])
		if err != nil {
			continue
		}
		switch body := message.Body.(type) {
		case *icmp.TimeExceeded:
			if !quotesEchoID(body.Data, id) {
				continue
			}
			addr, ok := netip.AddrFromSlice(net.ParseIP(peer.String()).To4())
			if !ok {
				continue
			}
			return addr, false, nil
		case *icmp.Echo:
			if message.Type == ipv4.ICMPTypeEchoReply && body.ID == id {
				return netip.Addr{}, true, nil
			}
		}
	}
}

// A Time Exceeded reply quotes the offending datagram: IPv4 header plus at
// least 8 payload bytes, with the echo id at offset 4.
func quotesEchoID(data []byte, id int) bool {
	if len(data) < 20 {
		return false
	}
	headerLen := int(data[0]&0x0f) * 4
	if len(data) < headerLen+8 || data[headerLen] != byte(ipv4.ICMPTypeEcho) {
		return false
	}
	return int(binary.BigEndian.Uint16(data[headerLen+4:headerLen+6])) == id
}

const SourceProbe Source = "probe"

// HopCandidates guesses a /24 for each private router past the first hop; the
// first-hop gateway is on a subnet an interface already covers.
func HopCandidates(hops []netip.Addr, ifaces []Iface) []Candidate {
	var candidates []Candidate
	seen := map[string]bool{}
	for _, hop := range hops {
		if !routable(hop) || !hop.IsPrivate() || onInterface(hop, ifaces) {
			continue
		}
		guess := netip.PrefixFrom(hop, 24).Masked().String()
		if seen[guess] {
			continue
		}
		seen[guess] = true
		candidates = append(candidates, Candidate{CIDR: guess, Source: SourceProbe})
	}
	return candidates
}

func onInterface(addr netip.Addr, ifaces []Iface) bool {
	for _, iface := range ifaces {
		for _, prefix := range iface.Addrs {
			if prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
}
