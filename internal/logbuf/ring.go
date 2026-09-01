package logbuf

import (
	"strings"
	"sync"
	"time"
)

type Line struct {
	At     time.Time
	Source string
	Text   string
}

// Ring buckets daemon output per connection by matching connection names in
// the lines, so the UI can show why a tunnel won't come up.
type Ring struct {
	mu    sync.Mutex
	size  int
	lines map[string][]Line
	keys  func() []string

	// keys may hit the database; too slow per log line, so cached briefly.
	keyMu         sync.Mutex
	cachedKeys    []string
	keysFetchedAt time.Time
}

const (
	General = ""
	keyTTL  = 3 * time.Second
)

func New(size int, keys func() []string) *Ring {
	return &Ring{size: size, lines: map[string][]Line{}, keys: keys}
}

func (r *Ring) Add(source, text string) {
	text = strings.TrimRight(text, "\r\n")
	if strings.TrimSpace(text) == "" {
		return
	}
	line := Line{At: time.Now().UTC(), Source: source, Text: text}
	keys := r.currentKeys()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.append(General, line)
	for _, key := range keys {
		if key != General && strings.Contains(text, key) {
			r.append(key, line)
		}
	}
}

func (r *Ring) currentKeys() []string {
	if r.keys == nil {
		return nil
	}
	r.keyMu.Lock()
	defer r.keyMu.Unlock()
	if time.Since(r.keysFetchedAt) < keyTTL {
		return r.cachedKeys
	}
	r.cachedKeys = r.keys()
	r.keysFetchedAt = time.Now()
	return r.cachedKeys
}

func (r *Ring) append(key string, line Line) {
	lines := append(r.lines[key], line)
	if len(lines) > r.size {
		lines = lines[len(lines)-r.size:]
	}
	r.lines[key] = lines
}

func (r *Ring) Lines(key string) []Line {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Line(nil), r.lines[key]...)
}
