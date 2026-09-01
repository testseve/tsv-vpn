package tunnel

import (
	"context"
	"strings"

	"tsv-vpn/internal/run"
)

type network struct {
	runner run.Runner
}

func (n network) addRoutes(ctx context.Context, iface string, subnets []string) error {
	for _, subnet := range subnets {
		if _, err := n.ip(ctx, "route", "replace", subnet, "dev", iface); err != nil {
			return err
		}
	}
	return nil
}

func (n network) removeRoutes(ctx context.Context, iface string, subnets []string) error {
	for _, subnet := range subnets {
		if _, err := n.ip(ctx, "route", "del", subnet, "dev", iface); err != nil && !alreadyGone(err) {
			return err
		}
	}
	return nil
}

// Tunnel traffic is masqueraded behind the ppp address (remote hosts have no
// route back); the clamp keeps TCP inside the tunnel MTU where path discovery
// is usually blocked.
func (n network) enableNAT(ctx context.Context, iface string) error {
	for _, rule := range natRules(iface) {
		if err := n.ensureRule(ctx, rule); err != nil {
			return err
		}
	}
	return nil
}

func (n network) disableNAT(ctx context.Context, iface string) error {
	for _, rule := range natRules(iface) {
		if _, err := n.iptables(ctx, append([]string{"-t", rule.table, "-D", rule.chain}, rule.spec...)...); err != nil && !alreadyGone(err) {
			return err
		}
	}
	return nil
}

type rule struct {
	table string
	chain string
	spec  []string
}

func natRules(iface string) []rule {
	return []rule{
		{table: "nat", chain: "POSTROUTING", spec: []string{"-o", iface, "-j", "MASQUERADE"}},
		{table: "mangle", chain: "FORWARD", spec: []string{
			"-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu"}},
	}
}

func (n network) ensureRule(ctx context.Context, r rule) error {
	if _, err := n.iptables(ctx, append([]string{"-t", r.table, "-C", r.chain}, r.spec...)...); err == nil {
		return nil
	}
	_, err := n.iptables(ctx, append([]string{"-t", r.table, "-A", r.chain}, r.spec...)...)
	return err
}

func (n network) ip(ctx context.Context, args ...string) (string, error) {
	return n.runner.Run(ctx, run.Command{Path: "ip", Args: args})
}

func (n network) iptables(ctx context.Context, args ...string) (string, error) {
	return n.runner.Run(ctx, run.Command{Path: "iptables", Args: args})
}

// A vanished interface already took its routes and rules with it; both tools
// report that as an error.
func alreadyGone(err error) bool {
	text := strings.ToLower(err.Error())
	for _, phrase := range []string{"no such process", "cannot find device", "does not exist",
		"no chain/target/match", "bad rule"} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}
