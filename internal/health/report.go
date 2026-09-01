package health

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"tsv-vpn/internal/db"
	"tsv-vpn/internal/tailnet"
)

type TunnelStatus interface {
	Status(name string) (db.State, string)
}

type Reporter struct {
	Store   *db.Store
	Tunnels TunnelStatus
	Backend func(ctx context.Context) (string, error)
}

type Report struct {
	Status      string       `json:"status"`
	Tailnet     string       `json:"tailnet"`
	Connections []Connection `json:"connections"`
}

type Connection struct {
	Name        string    `json:"name"`
	State       db.State  `json:"state"`
	Iface       string    `json:"iface,omitempty"`
	LastCheckAt time.Time `json:"last_check_at,omitempty"`
	LastRTTMS   float64   `json:"last_rtt_ms,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
}

func (r Reporter) Report(ctx context.Context) Report {
	report := Report{Status: "ok"}
	if r.Backend != nil {
		state, err := r.Backend(ctx)
		if err != nil {
			state = "unreachable"
		}
		report.Tailnet = state
	}
	if report.Tailnet != tailnet.StateRunning {
		report.Status = "down"
	}

	conns, err := r.Store.ListConnections()
	if err != nil {
		// A transient store error does not justify a container restart;
		// "down" is the tailnet check's verdict alone.
		if report.Status == "ok" {
			report.Status = "degraded"
		}
		return report
	}
	for _, conn := range conns {
		if !conn.Enabled {
			continue
		}
		state, iface := r.Tunnels.Status(conn.Name)
		entry := Connection{Name: conn.Name, State: state, Iface: iface}
		if status, err := r.Store.Status(conn.ID); err == nil {
			entry.LastCheckAt = status.LastCheckAt
			entry.LastRTTMS = status.LastRTTMS
			entry.LastError = status.LastError
		}
		report.Connections = append(report.Connections, entry)
		if state != db.StateUp && report.Status == "ok" {
			report.Status = "degraded"
		}
	}
	return report
}

// A tunnel mid-redial is not a broken container; only a stopped tailnet
// fails the check Docker restarts on.
func (r Reporter) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		report := r.Report(req.Context())
		w.Header().Set("Content-Type", "application/json")
		if report.Status == "down" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(report)
	})
}
