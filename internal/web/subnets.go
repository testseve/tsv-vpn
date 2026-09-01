package web

import (
	"context"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"tsv-vpn/internal/db"
	"tsv-vpn/internal/discover"
)

type subnetsData struct {
	Local      []localRow
	Candidates []discover.Candidate
	VPN        []vpnRoute
	Error      string
}

type localRow struct {
	Subnet  db.LocalSubnet
	Pending bool
}

type vpnRoute struct {
	CIDR         string
	Connection   string
	ConnectionID int64
	Enabled      bool
	Pending      bool
}

func (s *Server) subnets(w http.ResponseWriter, r *http.Request) {
	data, err := s.subnetsData(r.Context(), "")
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "subnets", "Subnets", data)
}

func (s *Server) addSubnet(w http.ResponseWriter, r *http.Request) {
	_, err := s.Store.CreateLocalSubnet(db.LocalSubnet{
		CIDR:        r.FormValue("cidr"),
		Description: r.FormValue("description"),
		Enabled:     true,
	})
	if err == nil {
		s.Tunnels.Nudge()
	}
	s.renderSubnets(w, r, err)
}

func (s *Server) setSubnetEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, "bad subnet id", http.StatusBadRequest)
			return
		}
		if err := s.Store.SetLocalSubnetEnabled(id, enabled); err != nil {
			s.fail(w, err)
			return
		}
		s.Tunnels.Nudge()
		s.renderSubnets(w, r, nil)
	}
}

func (s *Server) deleteSubnet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad subnet id", http.StatusBadRequest)
		return
	}
	if err := s.Store.DeleteLocalSubnet(id); err != nil {
		s.fail(w, err)
		return
	}
	s.Tunnels.Nudge()
	s.renderSubnets(w, r, nil)
}

func (s *Server) renderSubnets(w http.ResponseWriter, r *http.Request, failure error) {
	message := ""
	if failure != nil {
		message = failure.Error()
	}
	data, err := s.subnetsData(r.Context(), message)
	if err != nil {
		s.fail(w, err)
		return
	}
	if failure != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}
	s.fragment(w, "subnet-panel", data)
}

func (s *Server) subnetsData(ctx context.Context, message string) (subnetsData, error) {
	data := subnetsData{Error: message}

	locals, err := s.Store.ListLocalSubnets()
	if err != nil {
		return data, err
	}
	conns, err := s.Store.ListConnections()
	if err != nil {
		return data, err
	}
	approved := s.approvedRoutes(ctx)

	for _, local := range locals {
		data.Local = append(data.Local, localRow{
			Subnet:  local,
			Pending: local.Enabled && !approved[local.CIDR],
		})
	}
	for _, conn := range conns {
		for _, subnet := range conn.RemoteSubnets {
			data.VPN = append(data.VPN, vpnRoute{
				CIDR:         subnet,
				Connection:   conn.Name,
				ConnectionID: conn.ID,
				Enabled:      conn.Enabled,
				Pending:      conn.Enabled && !approved[subnet],
			})
		}
	}
	data.Candidates = s.candidates(ctx, locals)
	return data, nil
}

// Advisory only: an unreachable tailscaled means no hint, not a broken page.
func (s *Server) approvedRoutes(ctx context.Context) map[string]bool {
	approved := map[string]bool{}
	if s.Tailnet == nil {
		return approved
	}
	status, err := s.Tailnet.Status(ctx)
	if err != nil {
		return approved
	}
	return routeSet(status.Self.PrimaryRoutes)
}

func routeSet(routes []string) map[string]bool {
	set := make(map[string]bool, len(routes))
	for _, route := range routes {
		set[route] = true
	}
	return set
}

type Prober interface {
	Hops(ctx context.Context) ([]netip.Addr, error)
}

func (s *Server) candidates(ctx context.Context, locals []db.LocalSubnet) []discover.Candidate {
	ifaces, err := discover.Interfaces()
	if err != nil {
		return nil
	}
	routes, err := discover.Routes()
	if err != nil {
		routes = nil
	}

	added := map[string]bool{}
	for _, local := range locals {
		added[local.CIDR] = true
	}
	var candidates []discover.Candidate
	for _, candidate := range append(discover.Candidates(ifaces, routes), discover.HopCandidates(s.probedHops(ctx), ifaces)...) {
		if !added[candidate.CIDR] {
			added[candidate.CIDR] = true
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

// The probe can wait a couple of seconds on silent hops; too slow per page
// load.
const probeCacheFor = 10 * time.Minute

func (s *Server) probedHops(ctx context.Context) []netip.Addr {
	if s.Prober == nil {
		return nil
	}
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	if !s.probedAt.IsZero() && time.Since(s.probedAt) < probeCacheFor {
		return s.probeHops
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	hops, _ := s.Prober.Hops(ctx)
	s.probeHops = hops
	s.probedAt = time.Now()
	return hops
}
