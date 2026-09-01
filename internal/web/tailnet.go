package web

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"tsv-vpn/internal/db"
	"tsv-vpn/internal/tailnet"
)

type Tailnet interface {
	Status(ctx context.Context) (tailnet.Status, error)
	Up(ctx context.Context, hostname, authKey string, routes []string, exitNode bool) error
	SetExitNode(ctx context.Context, enabled bool) error
}

type tailnetView struct {
	State            string
	Running          bool
	AuthURL          string
	Hostname         string
	DNSName          string
	Addrs            []string
	Routes           []routeView
	ExitNode         bool
	ExitNodeApproved bool
	Command          string
	ACL              string
	Error            string
	Unreachable      bool
}

type routeView struct {
	CIDR     string
	Approved bool
}

func (s *Server) tailnetPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "tailnet", "Tailnet", s.tailnetView(r.Context(), ""))
}

func (s *Server) tailnetStatus(w http.ResponseWriter, r *http.Request) {
	s.fragment(w, "tailnet-status", s.tailnetView(r.Context(), ""))
}

func (s *Server) tailnetLogin(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSpace(r.FormValue("authkey"))
	if key == "" {
		s.fragment(w, "tailnet-status", s.tailnetView(r.Context(), "Paste an auth key first."))
		return
	}

	routes, err := s.Store.AdvertisedRoutes()
	if err != nil {
		s.fail(w, err)
		return
	}
	exitNode, err := s.Store.ExitNode()
	if err != nil {
		s.fail(w, err)
		return
	}
	message := ""
	if err := s.Tailnet.Up(r.Context(), s.Hostname, key, routes, exitNode); err != nil {
		message = err.Error()
	}
	s.fragment(w, "tailnet-status", s.tailnetView(r.Context(), message))
}

// Stored before tailscale is told: if tailscaled isn't answering, the next
// login replays it.
func (s *Server) tailnetExitNode(w http.ResponseWriter, r *http.Request) {
	enabled := r.FormValue("enabled") == "1"
	if err := s.Store.SetExitNode(enabled); err != nil {
		s.fail(w, err)
		return
	}
	message := ""
	if err := s.Tailnet.SetExitNode(r.Context(), enabled); err != nil {
		message = err.Error()
	}
	s.fragment(w, "tailnet-status", s.tailnetView(r.Context(), message))
}

func (s *Server) tailnetView(ctx context.Context, message string) tailnetView {
	view := tailnetView{State: "unreachable", Unreachable: true, Error: message}
	if s.Tailnet == nil {
		return view
	}

	status, err := s.Tailnet.Status(ctx)
	if err != nil {
		if view.Error == "" {
			view.Error = err.Error()
		}
		return view
	}

	view.Unreachable = false
	view.State = status.BackendState
	view.Running = status.Running()
	view.AuthURL = status.AuthURL
	view.Hostname = status.Self.HostName
	view.DNSName = strings.TrimSuffix(status.Self.DNSName, ".")
	view.Addrs = status.TailscaleIPs

	approved := routeSet(status.Self.PrimaryRoutes)
	view.ExitNodeApproved = status.Self.ExitNodeOption
	if exitNode, err := s.Store.ExitNode(); err == nil {
		view.ExitNode = exitNode
	}
	routes, err := s.Store.AdvertisedRoutes()
	if err == nil {
		for _, route := range routes {
			view.Routes = append(view.Routes, routeView{CIDR: route, Approved: approved[route]})
		}
		view.ACL = autoApproverACL(routes)
		view.Command = tailnet.UpCommand(s.Hostname, routes, view.ExitNode)
	}
	return view
}

func autoApproverACL(routes []string) string {
	prefixes := coveringPrefixes(routes)
	var lines []string
	for _, prefix := range prefixes {
		lines = append(lines, `        "`+prefix+`": ["tag:subnet-router"]`)
	}
	return `{
  "tagOwners": {
    "tag:subnet-router": ["autogroup:admin"]
  },
  "autoApprovers": {
    "routes": {
` + strings.Join(lines, ",\n") + `
    }
  }
}`
}

var privateRanges = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

func coveringPrefixes(routes []string) []string {
	covered := map[string]bool{}
	var extra []string
	for _, route := range routes {
		prefix, err := db.ParseSubnet(route)
		if err != nil {
			continue
		}
		matched := false
		for _, private := range privateRanges {
			block, err := db.ParseSubnet(private)
			if err == nil && block.Overlaps(prefix) {
				covered[private] = true
				matched = true
				break
			}
		}
		if !matched && !contains(extra, prefix.String()) {
			extra = append(extra, prefix.String())
		}
	}

	var prefixes []string
	for _, private := range privateRanges {
		if covered[private] {
			prefixes = append(prefixes, private)
		}
	}
	sort.Strings(extra)
	prefixes = append(prefixes, extra...)
	if len(prefixes) == 0 {
		return privateRanges
	}
	return prefixes
}

func contains(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}
