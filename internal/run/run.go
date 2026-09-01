package run

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DefaultTimeout bounds every external command so a wedged tool
// (xl2tpd-control on a dead FIFO) cannot stall the caller.
const DefaultTimeout = 30 * time.Second

type Command struct {
	Path string
	Args []string
	Env  []string
	// Negative means no timeout, for commands that legitimately wait
	// (an interactive tailscale login).
	Timeout time.Duration
}

// String renders the command for errors and logs, masking secret flag values.
func (c Command) String() string {
	parts := []string{c.Path}
	for _, arg := range c.Args {
		if name, _, ok := strings.Cut(arg, "="); ok && isSecretFlag(name) {
			arg = name + "=[redacted]"
		}
		parts = append(parts, arg)
	}
	return strings.Join(parts, " ")
}

func isSecretFlag(name string) bool {
	name = strings.ToLower(name)
	return strings.Contains(name, "authkey") || strings.Contains(name, "password") || strings.Contains(name, "secret")
}

type Runner interface {
	Run(ctx context.Context, command Command) (string, error)
}

type Exec struct{}

func (Exec) Run(ctx context.Context, command Command) (string, error) {
	if command.Timeout >= 0 {
		timeout := command.Timeout
		if timeout == 0 {
			timeout = DefaultTimeout
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	process := exec.CommandContext(ctx, command.Path, command.Args...)
	if len(command.Env) > 0 {
		process.Env = append(process.Environ(), command.Env...)
	}
	var output bytes.Buffer
	process.Stdout = &output
	process.Stderr = &output
	if err := process.Run(); err != nil {
		return output.String(), fmt.Errorf("%s: %w: %s", command, err, strings.TrimSpace(output.String()))
	}
	return output.String(), nil
}
