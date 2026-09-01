package run

import (
	"strings"
	"testing"
	"time"
)

func TestStringRedactsSecrets(t *testing.T) {
	command := Command{Path: "tailscale", Args: []string{"up", "--authkey=tskey-abc", "--hostname=box"}}
	got := command.String()
	if strings.Contains(got, "tskey-abc") {
		t.Fatalf("secret leaked: %q", got)
	}
	if want := "tailscale up --authkey=[redacted] --hostname=box"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRunTimesOut(t *testing.T) {
	_, err := Exec{}.Run(t.Context(), Command{Path: "sleep", Args: []string{"10"}, Timeout: 50 * time.Millisecond})
	if err == nil {
		t.Fatal("want timeout error")
	}
}
