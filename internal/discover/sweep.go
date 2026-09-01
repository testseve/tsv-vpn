package discover

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

const MaxSweepBits = 22

type Result struct {
	Addr netip.Addr
	RTT  time.Duration
	Name string
}

type Pinger interface {
	Ping(ctx context.Context, addr netip.Addr) (time.Duration, error)
}

type Sweeper struct {
	Pinger  Pinger
	Workers int
	Lookup  func(ctx context.Context, addr netip.Addr) string
}

func Hosts(prefix netip.Prefix) ([]netip.Addr, error) {
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("subnet %s is not IPv4", prefix)
	}
	if prefix.Bits() < MaxSweepBits {
		return nil, fmt.Errorf("subnet %s is larger than /%d", prefix, MaxSweepBits)
	}

	var hosts []netip.Addr
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		hosts = append(hosts, addr)
	}
	if prefix.Bits() <= 30 {
		hosts = hosts[1 : len(hosts)-1]
	}
	return hosts, nil
}

func (s Sweeper) Sweep(ctx context.Context, prefix netip.Prefix, results chan<- Result) error {
	hosts, err := Hosts(prefix)
	if err != nil {
		return err
	}

	workers := s.Workers
	if workers <= 0 {
		workers = 64
	}
	workers = min(workers, len(hosts))

	queue := make(chan netip.Addr)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for addr := range queue {
				rtt, err := s.Pinger.Ping(ctx, addr)
				if err != nil {
					continue
				}
				result := Result{Addr: addr, RTT: rtt}
				if s.Lookup != nil {
					result.Name = s.Lookup(ctx, addr)
				}
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	for _, host := range hosts {
		select {
		case queue <- host:
		case <-ctx.Done():
			close(queue)
			group.Wait()
			return ctx.Err()
		}
	}
	close(queue)
	group.Wait()
	return nil
}
