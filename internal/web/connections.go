package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"tsv-vpn/internal/db"
	"tsv-vpn/internal/logbuf"
)

// Display-only state for connections the reconciler is deliberately not
// dialing.
const stateDisabled db.State = "disabled"

type card struct {
	Conn      db.Connection
	State     db.State
	Iface     string
	LocalIP   string
	PeerIP    string
	Since     string
	RTT       string
	LastCheck string
	LastError string
	Uptime    string
}

type logView struct {
	ID    int64
	Lines []logLine
}

type logLine struct {
	At     string
	Source string
	Text   string
}

type dashboardData struct {
	Cards        []card
	Subnets      []subnetHealth
	NeedsTailnet bool
}

type subnetHealth struct {
	Subnet    db.LocalSubnet
	State     string
	RTT       string
	LastCheck string
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	cards, err := s.cards()
	if err != nil {
		s.fail(w, err)
		return
	}
	subnets, err := s.subnetHealth()
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "dashboard", "Connections", dashboardData{
		Cards:        cards,
		Subnets:      subnets,
		NeedsTailnet: !s.tailnetReady(r.Context()),
	})
}

func (s *Server) tailnetReady(ctx context.Context) bool {
	if s.Tailnet == nil {
		return true
	}
	status, err := s.Tailnet.Status(ctx)
	return err == nil && status.Running()
}

func (s *Server) connectionStatus(w http.ResponseWriter, r *http.Request) {
	conn, ok := s.connection(w, r)
	if !ok {
		return
	}
	s.fragment(w, "connection-status", s.card(conn))
}

func (s *Server) setEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, ok := s.connection(w, r)
		if !ok {
			return
		}
		if err := s.Store.SetConnectionEnabled(conn.ID, enabled); err != nil {
			s.fail(w, err)
			return
		}
		s.Tunnels.Nudge()

		conn.Enabled = enabled
		s.fragment(w, "connection-status", s.card(conn))
	}
}

func (s *Server) checkConnection(w http.ResponseWriter, r *http.Request) {
	conn, ok := s.connection(w, r)
	if !ok {
		return
	}
	if s.Checks != nil && conn.HealthCheckIP != "" {
		s.Checks.Check(r.Context(), conn)
	}
	s.fragment(w, "connection-status", s.card(conn))
}

func (s *Server) deleteConnection(w http.ResponseWriter, r *http.Request) {
	conn, ok := s.connection(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteConnection(conn.ID); err != nil {
		s.fail(w, err)
		return
	}
	s.Tunnels.Nudge()
	w.WriteHeader(http.StatusOK)
}

func (s *Server) connectionLogs(w http.ResponseWriter, r *http.Request) {
	conn, ok := s.connection(w, r)
	if !ok {
		return
	}
	view := logView{ID: conn.ID}
	if s.Logs != nil {
		view.Lines = formatLines(s.Logs.Lines(conn.Name))
	}
	s.fragment(w, "connection-logs", view)
}

func (s *Server) closeConnectionLogs(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (s *Server) cards() ([]card, error) {
	conns, err := s.Store.ListConnections()
	if err != nil {
		return nil, err
	}
	cards := make([]card, 0, len(conns))
	for _, conn := range conns {
		cards = append(cards, s.card(conn))
	}
	return cards, nil
}

// Live state comes from the reconciler, the rest from the status row.
func (s *Server) card(conn db.Connection) card {
	state, iface := s.Tunnels.Status(conn.Name)
	if !conn.Enabled {
		state, iface = stateDisabled, ""
	}
	view := card{Conn: conn, State: state, Iface: iface}

	status, err := s.Store.Status(conn.ID)
	if err != nil {
		slog.Error("web", "err", fmt.Errorf("connection %d status: %w", conn.ID, err))
		return view
	}
	view.LastError = status.LastError
	if state == db.StateUp {
		view.LocalIP = status.LocalIP
		view.PeerIP = status.PeerIP
		if !status.ConnectedAt.IsZero() {
			view.Since = status.ConnectedAt.Local().Format("Jan 2 15:04")
		}
	}
	if status.LastRTTMS > 0 {
		view.RTT = fmt.Sprintf("%.1f ms", status.LastRTTMS)
	}
	if !status.LastCheckAt.IsZero() {
		view.LastCheck = since(status.LastCheckAt) + " ago"
	}
	if state == db.StateUp && !status.ConnectedAt.IsZero() {
		view.Uptime = since(status.ConnectedAt)
	}
	return view
}

func (s *Server) subnetHealth() ([]subnetHealth, error) {
	subnets, err := s.Store.ListLocalSubnets()
	if err != nil {
		return nil, err
	}
	views := make([]subnetHealth, 0, len(subnets))
	for _, subnet := range subnets {
		view := subnetHealth{Subnet: subnet, State: "up"}
		switch {
		case !subnet.Enabled:
			view.State = "disabled"
		case subnet.HealthCheckIP == "":
			view.State = "unchecked"
		case subnet.LastError != "":
			view.State = "failed"
		case subnet.LastCheckAt.IsZero():
			view.State = "connecting"
		}
		if subnet.LastRTTMS > 0 && subnet.LastError == "" {
			view.RTT = fmt.Sprintf("%.1f ms", subnet.LastRTTMS)
		}
		if !subnet.LastCheckAt.IsZero() {
			view.LastCheck = since(subnet.LastCheckAt) + " ago"
		}
		views = append(views, view)
	}
	return views, nil
}

func (s *Server) localHealth(w http.ResponseWriter, r *http.Request) {
	subnets, err := s.subnetHealth()
	if err != nil {
		s.fail(w, err)
		return
	}
	s.fragment(w, "local-health", subnets)
}

func (s *Server) checkSubnet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad subnet id", http.StatusBadRequest)
		return
	}
	subnet, err := s.Store.LocalSubnet(id)
	if err != nil {
		s.notFound(w, err)
		return
	}
	if s.Checks != nil && subnet.HealthCheckIP != "" {
		s.Checks.CheckSubnet(r.Context(), subnet)
	}
	s.localHealth(w, r)
}

func (s *Server) connection(w http.ResponseWriter, r *http.Request) (db.Connection, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad connection id", http.StatusBadRequest)
		return db.Connection{}, false
	}
	conn, err := s.Store.Connection(id)
	if err != nil {
		s.notFound(w, err)
		return db.Connection{}, false
	}
	return conn, true
}

func (s *Server) notFound(w http.ResponseWriter, err error) {
	if errors.Is(err, db.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.fail(w, err)
}

func formatLines(lines []logbuf.Line) []logLine {
	formatted := make([]logLine, 0, len(lines))
	for _, line := range lines {
		formatted = append(formatted, logLine{
			At:     line.At.Local().Format("15:04:05"),
			Source: line.Source,
			Text:   line.Text,
		})
	}
	return formatted
}

func since(at time.Time) string {
	elapsed := time.Since(at)
	switch {
	case elapsed < time.Minute:
		return fmt.Sprintf("%ds", int(elapsed.Seconds()))
	case elapsed < time.Hour:
		return fmt.Sprintf("%dm", int(elapsed.Minutes()))
	case elapsed < 24*time.Hour:
		return fmt.Sprintf("%dh %dm", int(elapsed.Hours()), int(elapsed.Minutes())%60)
	default:
		return fmt.Sprintf("%dd %dh", int(elapsed.Hours())/24, int(elapsed.Hours())%24)
	}
}
