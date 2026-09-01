package supervise

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

type Process struct {
	Name string
	Path string
	Args []string
	Env  []string
}

type Supervisor struct {
	OnLine     func(source, line string)
	MinBackoff time.Duration
	MaxBackoff time.Duration
	// After this uptime the process counts as healthy and backoff resets.
	StableAfter time.Duration
}

func (s *Supervisor) Run(ctx context.Context, processes ...Process) {
	var group sync.WaitGroup
	for _, process := range processes {
		group.Add(1)
		go func() {
			defer group.Done()
			s.supervise(ctx, process)
		}()
	}
	group.Wait()
}

func (s *Supervisor) supervise(ctx context.Context, process Process) {
	backoff := s.min()
	for ctx.Err() == nil {
		startedAt := time.Now()
		err := s.start(ctx, process)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			s.line(process.Name, "exited: "+err.Error())
		} else {
			s.line(process.Name, "exited")
		}

		if time.Since(startedAt) >= s.stableAfter() {
			backoff = s.min()
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		backoff = min(backoff*2, s.max())
	}
}

func (s *Supervisor) start(ctx context.Context, process Process) error {
	command := exec.CommandContext(ctx, process.Path, process.Args...)
	if len(process.Env) > 0 {
		command.Env = append(command.Environ(), process.Env...)
	}
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 10 * time.Second

	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	s.line(process.Name, "started")

	var streams sync.WaitGroup
	streams.Add(2)
	for _, stream := range []io.Reader{stdout, stderr} {
		go func() {
			defer streams.Done()
			s.scan(process.Name, stream)
		}()
	}
	streams.Wait()

	err = command.Wait()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (s *Supervisor) scan(name string, stream io.Reader) {
	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 0, 4096), 64*1024)
	for scanner.Scan() {
		s.line(name, scanner.Text())
	}
	// Keep draining after a scan error: a full pipe blocks the daemon's next
	// write and Wait never returns.
	if err := scanner.Err(); err != nil {
		s.line(name, "log stream unreadable: "+err.Error())
		io.Copy(io.Discard, stream)
	}
}

func (s *Supervisor) line(source, text string) {
	if s.OnLine != nil {
		s.OnLine(source, text)
	}
}

func (s *Supervisor) min() time.Duration {
	if s.MinBackoff <= 0 {
		return time.Second
	}
	return s.MinBackoff
}

func (s *Supervisor) max() time.Duration {
	if s.MaxBackoff <= 0 {
		return 30 * time.Second
	}
	return s.MaxBackoff
}

func (s *Supervisor) stableAfter() time.Duration {
	if s.StableAfter <= 0 {
		return time.Minute
	}
	return s.StableAfter
}
