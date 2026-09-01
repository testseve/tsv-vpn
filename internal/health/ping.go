package health

import (
	"context"
	"net/netip"
	"time"

	"tsv-vpn/internal/discover"
)

// A ping sourced from the container address returns through the masquerade
// with the wrong identity, so the socket binds to the interface's own address.
// No interface means a local check, unbound out the default route.
type InterfacePinger struct {
	Timeout time.Duration
}

func (p InterfacePinger) Ping(ctx context.Context, addr netip.Addr, iface string) (time.Duration, error) {
	var source netip.Addr
	if iface != "" {
		bound, err := discover.InterfaceAddr(iface)
		if err != nil {
			return 0, err
		}
		source = bound
	}
	return discover.ICMPPinger{Source: source, Timeout: p.Timeout}.Ping(ctx, addr)
}
