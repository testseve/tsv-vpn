package tailnet

import (
	"context"
	"errors"
	"testing"
	"time"

	"tsv-vpn/internal/run"
)

type fakeRunner struct {
	calls    []string
	failures int
	output   string
}

func (f *fakeRunner) Run(ctx context.Context, command run.Command) (string, error) {
	f.calls = append(f.calls, command.String())
	if f.failures > 0 {
		f.failures--
		return "", errors.New("failed to connect to local tailscaled")
	}
	return f.output, nil
}

func TestUpAndSetRoutes(t *testing.T) {
	runner := &fakeRunner{}
	client := Client{Runner: runner, Socket: "/tmp/ts.sock"}

	if err := client.Up(t.Context(), "tsv-vpn", "tskey-abc", []string{"192.0.2.0/24"}, false); err != nil {
		t.Fatal(err)
	}
	// The rendered command lands in errors and logs; no auth key allowed.
	want := "tailscale --socket=/tmp/ts.sock up --hostname=tsv-vpn --accept-dns=false --advertise-routes=192.0.2.0/24 --advertise-exit-node=false --authkey=[redacted]"
	if runner.calls[0] != want {
		t.Fatalf("got %q", runner.calls[0])
	}

	if err := client.SetRoutes(t.Context(), []string{"192.0.2.0/24", "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	want = "tailscale --socket=/tmp/ts.sock set --advertise-routes=192.0.2.0/24,198.51.100.0/24"
	if runner.calls[1] != want {
		t.Fatalf("got %q", runner.calls[1])
	}
}

func TestUpWithoutAuthKey(t *testing.T) {
	runner := &fakeRunner{}
	client := Client{Runner: runner}
	if err := client.Up(t.Context(), "tsv-vpn", "", nil, true); err != nil {
		t.Fatal(err)
	}
	if got := runner.calls[0]; got != "tailscale --socket="+DefaultSocket+" up --hostname=tsv-vpn --accept-dns=false --advertise-routes= --advertise-exit-node=true" {
		t.Fatalf("got %q", got)
	}
}

func TestSetExitNode(t *testing.T) {
	runner := &fakeRunner{}
	client := Client{Runner: runner, Socket: "/tmp/ts.sock"}
	if err := client.SetExitNode(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if got := runner.calls[0]; got != "tailscale --socket=/tmp/ts.sock set --advertise-exit-node=true" {
		t.Fatalf("got %q", got)
	}
}

func TestUpCommandOmitsTheAuthKey(t *testing.T) {
	got := UpCommand("tsv-vpn", []string{"192.0.2.0/24"}, true)
	want := "tailscale up --hostname=tsv-vpn --accept-dns=false --advertise-routes=192.0.2.0/24 --advertise-exit-node=true"
	if got != want {
		t.Fatalf("got %q", got)
	}
}

func TestWaitForSocketRetries(t *testing.T) {
	runner := &fakeRunner{failures: 1}
	client := Client{Runner: runner}
	if err := client.WaitForSocket(t.Context(), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("got %d calls", len(runner.calls))
	}
}

func TestWaitForSocketGivesUp(t *testing.T) {
	runner := &fakeRunner{failures: 100}
	client := Client{Runner: runner}
	if err := client.WaitForSocket(t.Context(), 0); err == nil {
		t.Fatal("want an error once the timeout passes")
	}
}

func TestStatusReportsBackendState(t *testing.T) {
	runner := &fakeRunner{output: `{"BackendState":"Running","Self":{"Online":true}}`}
	client := Client{Runner: runner}

	status, err := client.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.BackendState != "Running" || !status.Self.Online {
		t.Fatalf("got %+v", status)
	}
}
