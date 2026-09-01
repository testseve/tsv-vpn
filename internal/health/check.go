package health

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"tsv-vpn/internal/db"
	"tsv-vpn/internal/logbuf"
)

const (
	defaultInterval = 30 * time.Second
	defaultTimeout  = 2 * time.Second
	failureLimit    = 3
)

type Pinger interface {
	Ping(ctx context.Context, addr netip.Addr, iface string) (time.Duration, error)
}

type Tunnels interface {
	Status(name string) (db.State, string)
	Unhealthy(ctx context.Context, name, reason string)
}

type Checker struct {
	Store    *db.Store
	Tunnels  Tunnels
	Pinger   Pinger
	Logs     *logbuf.Ring
	Interval time.Duration
	Timeout  time.Duration
	Now      func() time.Time

	mu       sync.Mutex
	failures map[string]int
}

func (c *Checker) Run(ctx context.Context) {
	ticker := time.NewTicker(c.interval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		c.CheckAll(ctx)
	}
}

func (c *Checker) CheckAll(ctx context.Context) {
	conns, err := c.Store.ListConnections()
	if err != nil {
		c.logf("list connections: %v", err)
		return
	}
	c.prune(conns)
	for _, conn := range conns {
		if !conn.Enabled || conn.HealthCheckIP == "" {
			continue
		}
		c.Check(ctx, conn)
	}

	subnets, err := c.Store.ListLocalSubnets()
	if err != nil {
		c.logf("list local subnets: %v", err)
		return
	}
	for _, subnet := range subnets {
		if !subnet.Enabled || subnet.HealthCheckIP == "" {
			continue
		}
		c.CheckSubnet(ctx, subnet)
	}
}

// A local subnet has no tunnel to restart; a failed ping is recorded and
// nothing escalates.
func (c *Checker) CheckSubnet(ctx context.Context, subnet db.LocalSubnet) {
	addr, err := netip.ParseAddr(subnet.HealthCheckIP)
	if err != nil {
		c.logf("%s: health check ip %q: %v", subnet.CIDR, subnet.HealthCheckIP, err)
		return
	}

	attempt, cancel := context.WithTimeout(ctx, c.timeout())
	rtt, err := c.Pinger.Ping(attempt, addr, "")
	cancel()

	failure := ""
	if err != nil {
		rtt = 0
		failure = fmt.Sprintf("health check %s: %v", addr, err)
	}
	if err := c.Store.RecordSubnetCheck(subnet.ID, c.now(), rtt, failure); err != nil {
		c.logf("%s: record check: %v", subnet.CIDR, err)
	}
}

// Only up tunnels are checked; the reconciler is already on the rest.
func (c *Checker) Check(ctx context.Context, conn db.Connection) {
	state, iface := c.Tunnels.Status(conn.Name)
	if state != db.StateUp || iface == "" {
		c.reset(conn.Name)
		return
	}
	addr, err := netip.ParseAddr(conn.HealthCheckIP)
	if err != nil {
		c.logf("%s: health check ip %q: %v", conn.Name, conn.HealthCheckIP, err)
		return
	}

	attempt, cancel := context.WithTimeout(ctx, c.timeout())
	rtt, err := c.Pinger.Ping(attempt, addr, iface)
	cancel()

	if err != nil {
		c.record(conn, 0, fmt.Sprintf("health check %s: %v", addr, err))
		if c.count(conn.Name) >= failureLimit {
			c.reset(conn.Name)
			c.Tunnels.Unhealthy(ctx, conn.Name, fmt.Sprintf("%s unreachable after %d checks", addr, failureLimit))
		}
		return
	}
	c.reset(conn.Name)
	c.record(conn, rtt, "")
}

func (c *Checker) record(conn db.Connection, rtt time.Duration, failure string) {
	if err := c.Store.RecordCheck(conn.ID, c.now(), rtt, failure); err != nil {
		c.logf("%s: record check: %v", conn.Name, err)
	}
}

func (c *Checker) count(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failures == nil {
		c.failures = map[string]int{}
	}
	c.failures[name]++
	return c.failures[name]
}

func (c *Checker) reset(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.failures, name)
}

// Clear failure counts on delete so a reused name does not inherit them.
func (c *Checker) prune(conns []db.Connection) {
	names := make(map[string]bool, len(conns))
	for _, conn := range conns {
		names[conn.Name] = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for name := range c.failures {
		if !names[name] {
			delete(c.failures, name)
		}
	}
}

func (c *Checker) logf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if c.Logs != nil {
		c.Logs.Add("health", message)
	}
	slog.Info("health", "msg", message)
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Checker) interval() time.Duration {
	if c.Interval > 0 {
		return c.Interval
	}
	return defaultInterval
}

func (c *Checker) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return defaultTimeout
}
