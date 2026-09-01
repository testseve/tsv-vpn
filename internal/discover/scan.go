package discover

import (
	"context"
	"net/netip"
	"time"
)

// Tunnel sweeps are sourced from the tunnel's own interface, so a scan doubles
// as a path check.
type Scan struct {
	Workers int
	Timeout time.Duration
}

func (s Scan) Sweep(ctx context.Context, prefix netip.Prefix, iface string, results chan<- Result) error {
	var source netip.Addr
	if iface != "" {
		addr, err := InterfaceAddr(iface)
		if err != nil {
			return err
		}
		source = addr
	}
	sweeper := Sweeper{
		Pinger:  ICMPPinger{Source: source, Timeout: s.Timeout},
		Workers: s.Workers,
		Lookup:  ReverseName,
	}
	return sweeper.Sweep(ctx, prefix, results)
}
