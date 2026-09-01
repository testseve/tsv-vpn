package supervise

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) add(source, line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, source+": "+line)
}

func (r *recorder) count(substring string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	found := 0
	for _, line := range r.lines {
		if strings.Contains(line, substring) {
			found++
		}
	}
	return found
}

func (r *recorder) waitFor(t *testing.T, substring string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r.count(substring) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	t.Fatalf("waiting for %d of %q, saw %v", want, substring, r.lines)
}

func TestRestartsAndCapturesOutput(t *testing.T) {
	lines := &recorder{}
	supervisor := &Supervisor{
		OnLine:     lines.add,
		MinBackoff: time.Millisecond,
		MaxBackoff: 2 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		supervisor.Run(ctx, Process{Name: "flaky", Path: "/bin/sh", Args: []string{"-c", "echo working; exit 3"}})
	}()

	lines.waitFor(t, "flaky: working", 3)
	lines.waitFor(t, "flaky: exited", 3)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not stop")
	}
}
