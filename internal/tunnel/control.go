package tunnel

import (
	"context"
	"path/filepath"

	"tsv-vpn/internal/run"
)

type Control interface {
	Add(ctx context.Context, tunnel Tunnel, peersDir string) error
	Connect(ctx context.Context, name string) error
	Disconnect(ctx context.Context, name string) error
	Remove(ctx context.Context, name string) error
}

// xl2tpd reads its config only at startup; live changes go in over the
// control socket. The rendered file is what it comes back with after a
// restart.
type XL2TPDControl struct {
	Runner run.Runner
	Path   string
}

func (c XL2TPDControl) Add(ctx context.Context, tunnel Tunnel, peersDir string) error {
	return c.control(ctx, "add-lac", tunnel.Name,
		"lns="+tunnel.GatewayHost,
		"require chap=yes",
		"refuse pap=yes",
		"require authentication=no",
		"name="+tunnel.Username,
		"pppoptfile="+filepath.Join(peersDir, tunnel.Name),
		"length bit=yes",
		"redial=yes",
		"redial timeout=10",
		"max redials=5",
	)
}

func (c XL2TPDControl) Connect(ctx context.Context, name string) error {
	return c.control(ctx, "connect-lac", name)
}

func (c XL2TPDControl) Disconnect(ctx context.Context, name string) error {
	return c.control(ctx, "disconnect-lac", name)
}

func (c XL2TPDControl) Remove(ctx context.Context, name string) error {
	return c.control(ctx, "remove-lac", name)
}

func (c XL2TPDControl) control(ctx context.Context, args ...string) error {
	_, err := c.Runner.Run(ctx, run.Command{
		Path: "xl2tpd-control",
		Args: append([]string{"-c", c.Path}, args...),
	})
	return err
}
