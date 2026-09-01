package web

import (
	"fmt"
	"net/http"
	"strings"

	"tsv-vpn/internal/db"
)

type formData struct {
	Conn    db.Connection
	Subnets string
	Action  string
	IsNew   bool
	Error   string
}

type preflightData struct {
	Addr  string
	RTT   string
	Error string
}

func (s *Server) newConnection(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "connection", "Add connection", formData{
		Conn:   db.Connection{Enabled: true},
		Action: "/connections",
		IsNew:  true,
	})
}

func (s *Server) editConnection(w http.ResponseWriter, r *http.Request) {
	conn, ok := s.connection(w, r)
	if !ok {
		return
	}
	s.render(w, r, "connection", "Edit "+conn.Name, formData{
		Conn:    conn,
		Subnets: strings.Join(conn.RemoteSubnets, "\n"),
		Action:  fmt.Sprintf("/connections/%d", conn.ID),
	})
}

func (s *Server) createConnection(w http.ResponseWriter, r *http.Request) {
	form := parseConnectionForm(r)
	form.Action = "/connections"
	form.IsNew = true

	secrets := db.Secrets{PSK: r.FormValue("psk"), PPPPassword: r.FormValue("ppp_password")}
	if _, err := s.Store.CreateConnection(form.Conn, secrets); err != nil {
		s.formError(w, form, err)
		return
	}
	s.Tunnels.Nudge()
	s.redirect(w, "/")
}

func (s *Server) updateConnection(w http.ResponseWriter, r *http.Request) {
	conn, ok := s.connection(w, r)
	if !ok {
		return
	}
	form := parseConnectionForm(r)
	form.Conn.ID = conn.ID
	form.Action = fmt.Sprintf("/connections/%d", conn.ID)

	secrets := db.Secrets{PSK: r.FormValue("psk"), PPPPassword: r.FormValue("ppp_password")}
	if err := s.Store.UpdateConnection(form.Conn, secrets); err != nil {
		s.formError(w, form, err)
		return
	}
	s.Tunnels.Nudge()
	s.redirect(w, "/")
}

func (s *Server) preflight(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.FormValue("gateway_host"))
	if host == "" || s.Gateway == nil {
		s.fragment(w, "preflight", preflightData{Error: "Enter a gateway host first."})
		return
	}
	result, err := s.Gateway.Test(r.Context(), host)
	if err != nil {
		s.fragment(w, "preflight", preflightData{Error: err.Error()})
		return
	}
	data := preflightData{Addr: result.Addr.String()}
	// Zero RTT means no pinger ran, not a 0.0 ms reply.
	if result.Ping == nil && result.RTT > 0 {
		data.RTT = fmt.Sprintf("%.1f ms", float64(result.RTT.Microseconds())/1000)
	}
	s.fragment(w, "preflight", data)
}

// Rejected forms come back as the form so htmx swaps it in with the typed
// values intact.
func (s *Server) formError(w http.ResponseWriter, form formData, err error) {
	form.Error = err.Error()
	w.WriteHeader(http.StatusUnprocessableEntity)
	s.fragment(w, "connection-form", form)
}

func (s *Server) redirect(w http.ResponseWriter, to string) {
	w.Header().Set("HX-Redirect", to)
	w.WriteHeader(http.StatusNoContent)
}

func parseConnectionForm(r *http.Request) formData {
	subnets := r.FormValue("remote_subnets")
	return formData{
		Conn: db.Connection{
			Name:          strings.TrimSpace(r.FormValue("name")),
			GatewayHost:   strings.TrimSpace(r.FormValue("gateway_host")),
			PPPUsername:   strings.TrimSpace(r.FormValue("ppp_username")),
			RemoteSubnets: splitFields(subnets),
			HealthCheckIP: strings.TrimSpace(r.FormValue("health_check_ip")),
			Enabled:       r.FormValue("enabled") != "",
		},
		Subnets: subnets,
	}
}

func splitFields(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
}
