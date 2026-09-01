package discover

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
)

const procRoute = "/proc/net/route"

type Iface struct {
	Name  string
	Addrs []netip.Prefix
}

type Route struct {
	Iface   string
	Dest    netip.Prefix
	Gateway netip.Addr
}

type Source string

const (
	SourceInterface Source = "interface"
	SourceGateway   Source = "gateway"
)

type Candidate struct {
	Iface  string
	CIDR   string
	Source Source
}

func (c Candidate) Description() string {
	switch c.Source {
	case SourceGateway:
		return "guessed from the default gateway"
	case SourceProbe:
		return "found on the path to the internet"
	default:
		return "detected on " + c.Iface
	}
}

// Managed and virtual interfaces are never offered as local subnets.
var skippedPrefixes = []string{"lo", "ppp", "tailscale", "docker", "veth"}

func Candidates(ifaces []Iface, routes []Route) []Candidate {
	var candidates []Candidate
	seen := map[string]bool{}

	for _, iface := range ifaces {
		if skipped(iface.Name) {
			continue
		}
		for _, addr := range iface.Addrs {
			if !routable(addr.Addr()) || addr.Bits() >= 31 {
				continue
			}
			cidr := addr.Masked().String()
			if seen[cidr] {
				continue
			}
			seen[cidr] = true
			candidates = append(candidates, Candidate{Iface: iface.Name, CIDR: cidr, Source: SourceInterface})
		}
	}

	// A bridged container sees the host's LAN on no interface; guess a /24
	// behind the default gateway. Gateways on an interface subnet (the docker
	// bridge) add nothing.
	for _, route := range routes {
		if route.Dest.Bits() != 0 || !route.Gateway.IsValid() || !routable(route.Gateway) {
			continue
		}
		if onInterface(route.Gateway, ifaces) {
			continue
		}
		guess := netip.PrefixFrom(route.Gateway, 24).Masked()
		if seen[guess.String()] {
			continue
		}
		seen[guess.String()] = true
		candidates = append(candidates, Candidate{Iface: route.Iface, CIDR: guess.String(), Source: SourceGateway})
	}
	return candidates
}

func skipped(name string) bool {
	for _, prefix := range skippedPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func routable(addr netip.Addr) bool {
	return addr.Is4() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsUnspecified()
}

func Interfaces() ([]Iface, error) {
	systemIfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ifaces []Iface
	for _, systemIface := range systemIfaces {
		if systemIface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := systemIface.Addrs()
		if err != nil {
			return nil, err
		}
		iface := Iface{Name: systemIface.Name}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			prefix, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			ones, _ := ipNet.Mask.Size()
			iface.Addrs = append(iface.Addrs, netip.PrefixFrom(prefix.Unmap(), ones))
		}
		ifaces = append(ifaces, iface)
	}
	return ifaces, nil
}

func Routes() ([]Route, error) {
	file, err := os.Open(procRoute)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ParseRoutes(file)
}

// /proc/net/route: little-endian hex words, one route per line after a header.
func ParseRoutes(source io.Reader) ([]Route, error) {
	scanner := bufio.NewScanner(source)
	if !scanner.Scan() {
		return nil, scanner.Err()
	}

	var routes []Route
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		dest, err := parseHexAddr(fields[1])
		if err != nil {
			return nil, err
		}
		gateway, err := parseHexAddr(fields[2])
		if err != nil {
			return nil, err
		}
		mask, err := parseHexAddr(fields[7])
		if err != nil {
			return nil, err
		}
		bits, _ := net.IPMask(mask.AsSlice()).Size()
		routes = append(routes, Route{
			Iface:   fields[0],
			Dest:    netip.PrefixFrom(dest, bits),
			Gateway: gateway,
		})
	}
	return routes, scanner.Err()
}

func parseHexAddr(field string) (netip.Addr, error) {
	raw, err := hex.DecodeString(field)
	if err != nil || len(raw) != 4 {
		return netip.Addr{}, fmt.Errorf("route field %q is not a hex address", field)
	}
	return netip.AddrFrom4([4]byte(binary.BigEndian.AppendUint32(nil, binary.LittleEndian.Uint32(raw)))), nil
}

func InterfaceAddr(name string) (netip.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		parsed, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		if parsed := parsed.Unmap(); parsed.Is4() {
			return parsed, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s has no IPv4 address", name)
}
