package logging

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDailyWriterRollsOverPerDay(t *testing.T) {
	dir := t.TempDir()
	day1 := time.Date(2026, 1, 10, 8, 0, 0, 0, time.UTC)
	clock := day1
	w, err := newDailyWriter(dir, DefaultRetention)
	if err != nil {
		t.Fatal(err)
	}
	w.now = func() time.Time { return clock }
	defer w.Close()

	if _, err := w.Write([]byte("day one\n")); err != nil {
		t.Fatal(err)
	}
	clock = day1.Add(24 * time.Hour)
	if _, err := w.Write([]byte("day two\n")); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"tsv-vpn-2026-01-10.log", "tsv-vpn-2026-01-11.log"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s: %v", name, err)
		}
	}
}

func TestPruneDeletesFilesPastRetention(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	old := filepath.Join(dir, "tsv-vpn-2026-01-01.log") // ~60 days old
	fresh := filepath.Join(dir, "tsv-vpn-2026-02-28.log")
	other := filepath.Join(dir, "keep-me.txt")
	for _, p := range []string{old, fresh, other} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	w := &dailyWriter{dir: dir, retention: DefaultRetention, now: func() time.Time { return now }}
	w.prune(now)

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("old file should be pruned, got %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh file should survive: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("non-log file should be untouched: %v", err)
	}
}

func TestSetupWithoutDirLogsToStderrOnly(t *testing.T) {
	closer, err := Setup("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
