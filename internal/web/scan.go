package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"tsv-vpn/internal/db"
	"tsv-vpn/internal/discover"
)

const scanRetention = 15 * time.Minute

type Scanner interface {
	Sweep(ctx context.Context, prefix netip.Prefix, iface string, results chan<- discover.Result) error
}

type scan struct {
	ID           string
	Prefix       netip.Prefix
	Iface        string
	ConnectionID int64
	SubnetID     int64
	StartedAt    time.Time

	mu      sync.Mutex
	results []discover.Result
	done    bool
	err     error
}

type scans struct {
	mu   sync.Mutex
	jobs map[string]*scan
}

type scanView struct {
	ID           string
	Prefix       string
	Iface        string
	ConnectionID int64
	SubnetID     int64
	Running      bool
	Error        string
	Hosts        []scanHost
}

type scanHost struct {
	Addr string
	RTT  string
	Name string
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	prefix, err := db.ParseSubnet(r.FormValue("cidr"))
	if err != nil {
		s.fragment(w, "scan", scanView{Error: err.Error()})
		return
	}
	if _, err := discover.Hosts(prefix); err != nil {
		s.fragment(w, "scan", scanView{Error: err.Error()})
		return
	}
	if s.Scanner == nil {
		s.fragment(w, "scan", scanView{Error: "scanning is not available"})
		return
	}

	job := &scan{ID: randomID(), Prefix: prefix, StartedAt: time.Now()}
	if id, err := strconv.ParseInt(r.FormValue("subnet_id"), 10, 64); err == nil {
		job.SubnetID = id
	}
	if id, err := strconv.ParseInt(r.FormValue("connection_id"), 10, 64); err == nil {
		conn, err := s.Store.Connection(id)
		if err != nil {
			s.fragment(w, "scan", scanView{Error: err.Error()})
			return
		}
		state, iface := s.Tunnels.Status(conn.Name)
		if state != db.StateUp || iface == "" {
			s.fragment(w, "scan", scanView{Error: conn.Name + " is not up, so its subnet cannot be scanned"})
			return
		}
		job.ConnectionID = conn.ID
		job.Iface = iface
	}

	s.scans().add(job)
	go s.runScan(job)
	s.fragment(w, "scan", job.view())
}

func (s *Server) scanStatus(w http.ResponseWriter, r *http.Request) {
	job := s.scans().get(r.PathValue("id"))
	if job == nil {
		s.fragment(w, "scan", scanView{Error: "this scan has expired"})
		return
	}
	s.fragment(w, "scan", job.view())
}

func (s *Server) useAsHealthCheck(w http.ResponseWriter, r *http.Request) {
	conn, ok := s.connection(w, r)
	if !ok {
		return
	}
	if err := s.Store.SetHealthCheckIP(conn.ID, r.FormValue("ip")); err != nil {
		s.fail(w, err)
		return
	}
	s.fragment(w, "health-check-set", r.FormValue("ip"))
}

func (s *Server) useAsSubnetHealthCheck(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad subnet id", http.StatusBadRequest)
		return
	}
	// Scan results swap in a confirmation span; the subnets page re-renders
	// the whole panel.
	fromPanel := r.Header.Get("HX-Target") == "subnet-panel"
	if err := s.Store.SetLocalSubnetHealthCheckIP(id, r.FormValue("ip")); err != nil {
		if fromPanel && !errors.Is(err, db.ErrNotFound) {
			s.renderSubnets(w, r, err)
			return
		}
		s.notFound(w, err)
		return
	}
	if fromPanel {
		s.renderSubnets(w, r, nil)
		return
	}
	s.fragment(w, "health-check-set", r.FormValue("ip"))
}

// A sweep outlives its request, so it reports into a job the polling fragment
// reads.
func (s *Server) runScan(job *scan) {
	ctx, cancel := context.WithTimeout(context.Background(), scanRetention)
	defer cancel()

	results := make(chan discover.Result)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for result := range results {
			job.mu.Lock()
			job.results = append(job.results, result)
			job.mu.Unlock()
		}
	}()

	err := s.Scanner.Sweep(ctx, job.Prefix, job.Iface, results)
	close(results)
	// Every result must land before done is set; the final poll stops on it.
	<-drained

	job.mu.Lock()
	job.err = err
	job.done = true
	job.mu.Unlock()
}

func (j *scan) view() scanView {
	j.mu.Lock()
	defer j.mu.Unlock()

	view := scanView{
		ID:           j.ID,
		Prefix:       j.Prefix.String(),
		Iface:        j.Iface,
		ConnectionID: j.ConnectionID,
		SubnetID:     j.SubnetID,
		Running:      !j.done,
	}
	if j.err != nil {
		view.Error = j.err.Error()
	}
	results := append([]discover.Result(nil), j.results...)
	sort.Slice(results, func(a, b int) bool { return results[a].Addr.Less(results[b].Addr) })
	for _, result := range results {
		view.Hosts = append(view.Hosts, scanHost{
			Addr: result.Addr.String(),
			RTT:  fmt.Sprintf("%.1f ms", float64(result.RTT.Microseconds())/1000),
			Name: result.Name,
		})
	}
	return view
}

func (s *Server) scans() *scans {
	s.scansOnce.Do(func() { s.running = &scans{jobs: map[string]*scan{}} })
	return s.running
}

func (s *scans) add(job *scan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, existing := range s.jobs {
		if time.Since(existing.StartedAt) > scanRetention {
			delete(s.jobs, id)
		}
	}
	s.jobs[job.ID] = job
}

func (s *scans) get(id string) *scan {
	s.mu.Lock()
	defer s.mu.Unlock()
	job := s.jobs[id]
	if job != nil && time.Since(job.StartedAt) > scanRetention {
		delete(s.jobs, id)
		return nil
	}
	return job
}

func randomID() string {
	raw := make([]byte, 8)
	rand.Read(raw)
	return hex.EncodeToString(raw)
}
