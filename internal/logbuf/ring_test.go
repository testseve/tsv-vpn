package logbuf

import "testing"

func TestLinesAreKeyedByConnectionName(t *testing.T) {
	ring := New(10, func() []string { return []string{"alpha", "beta"} })
	ring.Add("charon", "establishing IKE_SA alpha[1]")
	ring.Add("xl2tpd", "Connecting to host beta.example.com")
	ring.Add("charon", "unrelated chatter")

	if got := ring.Lines("alpha"); len(got) != 1 || got[0].Source != "charon" {
		t.Fatalf("alpha: %+v", got)
	}
	if got := ring.Lines("beta"); len(got) != 1 {
		t.Fatalf("beta: %+v", got)
	}
	if got := ring.Lines(General); len(got) != 3 {
		t.Fatalf("general: %+v", got)
	}
	if got := ring.Lines("gamma"); len(got) != 0 {
		t.Fatalf("gamma: %+v", got)
	}
}

func TestRingDropsOldestLines(t *testing.T) {
	ring := New(2, nil)
	ring.Add("charon", "first")
	ring.Add("charon", "second")
	ring.Add("charon", "third")

	lines := ring.Lines(General)
	if len(lines) != 2 || lines[0].Text != "second" || lines[1].Text != "third" {
		t.Fatalf("got %+v", lines)
	}
}

func TestBlankLinesAreIgnored(t *testing.T) {
	ring := New(4, nil)
	ring.Add("charon", "   \n")
	if got := ring.Lines(General); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}
