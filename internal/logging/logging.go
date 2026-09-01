// Package logging writes structured logs to stderr and a pruned daily file.
package logging

import (
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	DefaultRetention = 30 * 24 * time.Hour
	filePrefix       = "tsv-vpn"
	fileSuffix       = ".log"
	dayLayout        = "2006-01-02"
)

// Setup wires slog and the standard log package to stderr and to a daily file
// under dir. An empty dir logs to stderr only, for the password subcommands
// that run before the data volume exists. Zero retention keeps the default.
func Setup(dir string, retention time.Duration) (io.Closer, error) {
	if retention <= 0 {
		retention = DefaultRetention
	}

	var sink io.Writer = os.Stderr
	var closer io.Closer = io.NopCloser(nil)
	if dir != "" {
		writer, err := newDailyWriter(dir, retention)
		if err != nil {
			return nil, err
		}
		sink = io.MultiWriter(os.Stderr, writer)
		closer = writer
	}

	handler := slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(handler))

	// slog stamps its own time; drop the standard logger's.
	log.SetFlags(0)
	log.SetOutput(sink)

	return closer, nil
}

// dailyWriter appends to one file per day, pruning old files as it rolls.
type dailyWriter struct {
	dir       string
	retention time.Duration
	now       func() time.Time

	mu   sync.Mutex
	day  string
	file *os.File
}

func newDailyWriter(dir string, retention time.Duration) (*dailyWriter, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	w := &dailyWriter{dir: dir, retention: retention, now: time.Now}
	if err := w.roll(w.now()); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *dailyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if today := w.now().Format(dayLayout); today != w.day {
		if err := w.roll(w.now()); err != nil {
			return 0, err
		}
	}
	return w.file.Write(p)
}

func (w *dailyWriter) roll(at time.Time) error {
	if w.file != nil {
		w.file.Close()
	}
	day := at.Format(dayLayout)
	path := filepath.Join(w.dir, filePrefix+"-"+day+fileSuffix)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w.file = file
	w.day = day
	w.prune(at)
	return nil
}

// Best effort: a file that won't delete is retried on the next roll.
func (w *dailyWriter) prune(at time.Time) {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}
	cutoff := at.Add(-w.retention)
	for _, entry := range entries {
		name := entry.Name()
		if len(name) < len(filePrefix)+len(fileSuffix) ||
			name[:len(filePrefix)] != filePrefix ||
			name[len(name)-len(fileSuffix):] != fileSuffix {
			continue
		}
		stamp := name[len(filePrefix)+1 : len(name)-len(fileSuffix)]
		day, err := time.Parse(dayLayout, stamp)
		if err != nil {
			continue
		}
		if day.Before(cutoff.Truncate(24 * time.Hour)) {
			os.Remove(filepath.Join(w.dir, name))
		}
	}
}

func (w *dailyWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	return w.file.Close()
}
