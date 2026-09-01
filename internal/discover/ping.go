package discover

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const defaultPingTimeout = time.Second

type ICMPPinger struct {
	Source  netip.Addr
	Timeout time.Duration
}

func (p ICMPPinger) Ping(ctx context.Context, addr netip.Addr) (time.Duration, error) {
	source := "0.0.0.0"
	if p.Source.IsValid() {
		source = p.Source.String()
	}
	conn, err := icmp.ListenPacket("ip4:icmp", source)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	timeout := p.Timeout
	if timeout <= 0 {
		timeout = defaultPingTimeout
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, err
	}

	id := int(binary.BigEndian.Uint16(randomBytes(2)))
	request, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("tsv-vpn")},
	}).Marshal(nil)
	if err != nil {
		return 0, err
	}

	sentAt := time.Now()
	if _, err := conn.WriteTo(request, &net.IPAddr{IP: addr.AsSlice()}); err != nil {
		return 0, err
	}

	// The raw socket sees every echo reply on the host; skip ones with
	// another ping's id.
	reply := make([]byte, 1500)
	for {
		read, peer, err := conn.ReadFrom(reply)
		if err != nil {
			return 0, err
		}
		if peer.String() != addr.String() {
			continue
		}
		message, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply[:read])
		if err != nil {
			continue
		}
		echo, ok := message.Body.(*icmp.Echo)
		if !ok || message.Type != ipv4.ICMPTypeEchoReply || echo.ID != id {
			continue
		}
		return time.Since(sentAt), nil
	}
}

func randomBytes(n int) []byte {
	buffer := make([]byte, n)
	if _, err := rand.Read(buffer); err != nil {
		panic(fmt.Sprintf("read random bytes: %v", err))
	}
	return buffer
}

func ReverseName(ctx context.Context, addr netip.Addr) string {
	names, err := net.DefaultResolver.LookupAddr(ctx, addr.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}
