package discover

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Cheap form-side check; the reconciler's IKE attempt is the real test, and a
// gateway that drops ICMP still works.
type Preflight struct {
	Pinger  Pinger
	Timeout time.Duration
}

type PreflightResult struct {
	Addr netip.Addr
	RTT  time.Duration
	Ping error
}

func (p Preflight) Test(ctx context.Context, host string) (PreflightResult, error) {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(addrs) == 0 {
		return PreflightResult{}, fmt.Errorf("%s does not resolve to an IPv4 address", host)
	}

	result := PreflightResult{Addr: addrs[0].Unmap()}
	if p.Pinger == nil {
		return result, nil
	}
	result.RTT, result.Ping = p.Pinger.Ping(ctx, result.Addr)
	return result, nil
}
