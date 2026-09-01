package db

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
)

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$`)

func ValidateName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("name %q must be 2-32 characters of a-z, 0-9 and dashes, starting and ending alphanumeric", name)
	}
	return nil
}

// Connection fields are rendered verbatim into the strongSwan, xl2tpd and
// pppd configs, which do not escape input, and pppd options can run commands
// as root. Newlines and double quotes would break out of their line and
// inject directives, so both are refused up front.
func validateConfigField(field, value string) error {
	for _, r := range value {
		if r == '"' || unicode.IsControl(r) {
			return fmt.Errorf("%s must not contain quotes or control characters", field)
		}
	}
	return nil
}

// Hosts also sit in whitespace-separated positions (swanctl remote_addrs,
// the xl2tpd lns line, chap-secrets), where a space would add tokens.
func validateHostField(field, value string) error {
	if err := validateConfigField(field, value); err != nil {
		return err
	}
	if strings.ContainsFunc(value, unicode.IsSpace) {
		return fmt.Errorf("%s must not contain spaces", field)
	}
	return nil
}

// ValidateSecrets rejects the same injection vectors in the PSK and PPP
// password; empty means keep the stored value.
func ValidateSecrets(secrets Secrets) error {
	if secrets.PSK != "" {
		if err := validateConfigField("psk", secrets.PSK); err != nil {
			return err
		}
	}
	if secrets.PPPPassword != "" {
		if err := validateConfigField("ppp password", secrets.PPPPassword); err != nil {
			return err
		}
	}
	return nil
}

func ParseSubnets(subnets []string) ([]netip.Prefix, error) {
	if len(subnets) == 0 {
		return nil, fmt.Errorf("at least one subnet is required")
	}
	prefixes := make([]netip.Prefix, 0, len(subnets))
	for _, subnet := range subnets {
		prefix, err := ParseSubnet(subnet)
		if err != nil {
			return nil, err
		}
		for _, seen := range prefixes {
			if seen.Overlaps(prefix) {
				return nil, fmt.Errorf("subnet %s overlaps %s in the same list", prefix, seen)
			}
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func ParseSubnet(subnet string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(subnet))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("subnet %q is not a CIDR: %w", subnet, err)
	}
	if prefix.Addr() != prefix.Masked().Addr() {
		return netip.Prefix{}, fmt.Errorf("subnet %s has host bits set, use %s", subnet, prefix.Masked())
	}
	return prefix, nil
}

type Claim struct {
	Owner  string
	Prefix netip.Prefix
}

// Overlapping routes would make the advertised set ambiguous; rejected at
// write time.
func CheckOverlap(candidates []netip.Prefix, claimed []Claim) error {
	for _, candidate := range candidates {
		for _, claim := range claimed {
			if claim.Prefix.Overlaps(candidate) {
				return fmt.Errorf("subnet %s overlaps %s, already routed by %s", candidate, claim.Prefix, claim.Owner)
			}
		}
	}
	return nil
}

func ParseIP(ip string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%q is not an IP address", ip)
	}
	return addr, nil
}

func validateConnection(conn Connection) error {
	if err := ValidateName(conn.Name); err != nil {
		return err
	}
	if strings.TrimSpace(conn.GatewayHost) == "" {
		return fmt.Errorf("gateway host is required")
	}
	if err := validateHostField("gateway host", conn.GatewayHost); err != nil {
		return err
	}
	if strings.TrimSpace(conn.PPPUsername) == "" {
		return fmt.Errorf("ppp username is required")
	}
	if err := validateHostField("ppp username", conn.PPPUsername); err != nil {
		return err
	}
	if _, err := ParseSubnets(conn.RemoteSubnets); err != nil {
		return err
	}
	if conn.HealthCheckIP != "" {
		if _, err := ParseIP(conn.HealthCheckIP); err != nil {
			return fmt.Errorf("health check ip: %w", err)
		}
	}
	return nil
}
