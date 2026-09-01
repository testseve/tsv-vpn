package tailnet

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"tsv-vpn/internal/run"
)

const DefaultSocket = "/var/run/tailscale/tailscaled.sock"

type Client struct {
	Runner run.Runner
	Binary string
	Socket string
}

// The exit-node flag is always passed: "tailscale up" refuses to run when an
// unmentioned pref differs from the default.
func (c Client) Up(ctx context.Context, hostname, authKey string, routes []string, exitNode bool) error {
	args := upArgs(hostname, routes, exitNode)
	// Without a key "tailscale up" blocks on the interactive login, so it
	// must outlive the runner's default timeout.
	timeout := -1 * time.Second
	if authKey != "" {
		args = append(args, "--authkey="+authKey)
		timeout = 2 * time.Minute
	}
	_, err := c.run(ctx, timeout, args...)
	return err
}

func upArgs(hostname string, routes []string, exitNode bool) []string {
	return []string{
		"up", "--hostname=" + hostname, "--accept-dns=false",
		"--advertise-routes=" + strings.Join(routes, ","),
		"--advertise-exit-node=" + strconv.FormatBool(exitNode),
	}
}

// UpCommand renders the "tailscale up" the stored settings amount to, for
// display. Never includes the auth key.
func UpCommand(hostname string, routes []string, exitNode bool) string {
	return "tailscale " + strings.Join(upArgs(hostname, routes, exitNode), " ")
}

func (c Client) SetRoutes(ctx context.Context, routes []string) error {
	_, err := c.command(ctx, "set", "--advertise-routes="+strings.Join(routes, ","))
	return err
}

func (c Client) SetExitNode(ctx context.Context, enabled bool) error {
	_, err := c.command(ctx, "set", "--advertise-exit-node="+strconv.FormatBool(enabled))
	return err
}

type Status struct {
	BackendState string
	// Set while the node waits to be authorised; opening it in a browser
	// completes login.
	AuthURL      string
	TailscaleIPs []string
	Self         struct {
		Online   bool
		HostName string
		DNSName  string
		// True only once the exit node is both advertised and approved.
		ExitNodeOption bool
		PrimaryRoutes  []string
	}
}

const StateRunning = "Running"

func (s Status) Running() bool { return s.BackendState == StateRunning }

// Routes appear in PrimaryRoutes only after admin approval.
func (c Client) ApprovedRoutes(ctx context.Context) ([]string, error) {
	status, err := c.Status(ctx)
	if err != nil {
		return nil, err
	}
	return status.Self.PrimaryRoutes, nil
}

func (c Client) Status(ctx context.Context) (Status, error) {
	output, err := c.command(ctx, "status", "--json")
	if err != nil {
		return Status{}, err
	}
	var status Status
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		return Status{}, err
	}
	return status, nil
}

// tailscaled creates its socket a moment after exec; commands fail until it
// exists.
func (c Client) WaitForSocket(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		_, err := c.command(ctx, "status", "--json")
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (c Client) command(ctx context.Context, args ...string) (string, error) {
	return c.run(ctx, 0, args...)
}

func (c Client) run(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	binary := c.Binary
	if binary == "" {
		binary = "tailscale"
	}
	socket := c.Socket
	if socket == "" {
		socket = DefaultSocket
	}
	return c.Runner.Run(ctx, run.Command{
		Path:    binary,
		Args:    append([]string{"--socket=" + socket}, args...),
		Timeout: timeout,
	})
}
