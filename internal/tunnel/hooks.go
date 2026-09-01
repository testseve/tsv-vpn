package tunnel

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

const DefaultPPPDir = "/etc/ppp"

func (m *Manager) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/ppp/up", func(w http.ResponseWriter, r *http.Request) {
		m.handleHook(w, r, m.PPPUp)
	})
	mux.HandleFunc("POST /internal/ppp/down", func(w http.ResponseWriter, r *http.Request) {
		m.handleHook(w, r, func(ctx context.Context, name, iface, _, _ string) error {
			return m.PPPDown(ctx, name, iface)
		})
	})
	return mux
}

func (m *Manager) handleHook(w http.ResponseWriter, r *http.Request, apply func(ctx context.Context, name, iface, localIP, peerIP string) error) {
	name := r.URL.Query().Get("peer")
	iface := r.URL.Query().Get("iface")
	if name == "" {
		http.Error(w, "peer is required", http.StatusBadRequest)
		return
	}
	if err := apply(r.Context(), name, iface, r.URL.Query().Get("local"), r.URL.Query().Get("peerip")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pppd reports which interface a connection landed on only through its ip-up
// and ip-down scripts, which hand the mapping back over localhost.
func InstallHooks(pppDir, addr string) error {
	for event, dir := range map[string]string{"up": "ip-up.d", "down": "ip-down.d"} {
		path := filepath.Join(pppDir, dir)
		if err := os.MkdirAll(path, 0o755); err != nil {
			return err
		}
		// pppd invokes these as: script iface tty speed local-ip remote-ip ipparam
		script := fmt.Sprintf(`#!/bin/sh
curl -fsS -m 5 -o /dev/null -X POST "http://%s/internal/ppp/%s?peer=$6&iface=$1&local=$4&peerip=$5" || true
`, addr, event)
		if err := os.WriteFile(filepath.Join(path, "tsv-vpn"), []byte(script), 0o755); err != nil {
			return err
		}
	}
	return nil
}

// pppd's CHAP secrets path is fixed and the rendered copy holds live
// passwords, so the path points at tmpfs.
func LinkCHAPSecrets(pppDir, dir string) error {
	link := filepath.Join(pppDir, "chap-secrets")
	target := filepath.Join(dir, "chap-secrets")
	if current, err := os.Readlink(link); err == nil && current == target {
		return nil
	}
	if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Symlink(target, link)
}
