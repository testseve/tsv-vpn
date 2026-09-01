package tunnel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The renderer is measured against the hand-written configs in examples/.
func exampleTunnel() Tunnel {
	return Tunnel{
		Name:        "example",
		GatewayHost: "vpn.example.com",
		PSK:         "replace-with-preshared-key",
		Username:    "replace-with-ppp-username",
		Password:    "replace-with-ppp-password",
	}
}

func readExample(t *testing.T, name string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", "examples", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func TestRenderMatchesManualConfigs(t *testing.T) {
	tunnels := []Tunnel{exampleTunnel()}

	swanctl, err := RenderSwanctl(tunnels)
	if err != nil {
		t.Fatal(err)
	}
	if want := readExample(t, "swanctl.conf"); swanctl != want {
		t.Errorf("swanctl.conf mismatch:\n%s", diff(swanctl, want))
	}

	xl2tpd, err := RenderXL2TPD(tunnels, "/etc/ppp/peers")
	if err != nil {
		t.Fatal(err)
	}
	if want := readExample(t, "xl2tpd.conf"); xl2tpd != want {
		t.Errorf("xl2tpd.conf mismatch:\n%s", diff(xl2tpd, want))
	}

	peer, err := RenderPPPPeer(tunnels[0])
	if err != nil {
		t.Fatal(err)
	}
	if want := readExample(t, "ppp-peer"); peer != want {
		t.Errorf("ppp peer mismatch:\n%s", diff(peer, want))
	}

	if got, want := RenderCHAPSecrets(tunnels), readExample(t, "chap-secrets"); got != want {
		t.Errorf("chap-secrets mismatch:\n%s", diff(got, want))
	}
}

func TestRenderTwoTunnels(t *testing.T) {
	tunnels := []Tunnel{
		{Name: "alpha", GatewayHost: "alpha.example.com", GatewayAddr: "198.51.100.1", PSK: "one", Username: "a", Password: "pa"},
		{Name: "beta", GatewayHost: "beta.example.com", GatewayAddr: "203.0.113.1", PSK: "two", Username: "b", Password: "pb"},
	}

	swanctl, err := RenderSwanctl(tunnels)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"    alpha {", "    beta {", "ike-alpha {", "ike-beta {",
		"id = 198.51.100.1", "id = 203.0.113.1", `secret = "one"`, `secret = "two"`} {
		if !strings.Contains(swanctl, want) {
			t.Errorf("swanctl.conf missing %q:\n%s", want, swanctl)
		}
	}
	if strings.Contains(swanctl, "%any\n        secret") {
		t.Error("two tunnels share a wildcard psk identity")
	}

	xl2tpd, err := RenderXL2TPD(tunnels, "/run/tsv-vpn/peers")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[lac alpha]", "[lac beta]",
		"pppoptfile = /run/tsv-vpn/peers/alpha", "pppoptfile = /run/tsv-vpn/peers/beta"} {
		if !strings.Contains(xl2tpd, want) {
			t.Errorf("xl2tpd.conf missing %q:\n%s", want, xl2tpd)
		}
	}
	if strings.Count(xl2tpd, "[global]") != 1 {
		t.Errorf("want exactly one global section:\n%s", xl2tpd)
	}

	chap := RenderCHAPSecrets(tunnels)
	if !strings.Contains(chap, "a\t*\t\"pa\"\t*") || !strings.Contains(chap, "b\t*\t\"pb\"\t*") {
		t.Errorf("chap-secrets missing an entry:\n%s", chap)
	}
}

func TestWriteFilePermissions(t *testing.T) {
	dir := t.TempDir()
	tunnels := []Tunnel{exampleTunnel()}
	if err := Write(dir, tunnels); err != nil {
		t.Fatal(err)
	}

	paths := []string{
		filepath.Join(dir, "swanctl.conf"),
		filepath.Join(dir, "xl2tpd.conf"),
		filepath.Join(dir, "chap-secrets"),
		filepath.Join(dir, "peers", "example"),
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v, want 0600", path, info.Mode().Perm())
		}
	}

	xl2tpd, err := os.ReadFile(filepath.Join(dir, "xl2tpd.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(xl2tpd), "pppoptfile = "+filepath.Join(dir, "peers", "example")) {
		t.Errorf("xl2tpd.conf points somewhere else:\n%s", xl2tpd)
	}
}

func TestWriteRemovesStalePeerFiles(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, []Tunnel{exampleTunnel(), {Name: "gone", GatewayHost: "gone.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, []Tunnel{exampleTunnel()}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "peers", "gone")); !os.IsNotExist(err) {
		t.Fatalf("stale peer file survived: %v", err)
	}
}

func diff(got, want string) string {
	gotLines, wantLines := strings.Split(got, "\n"), strings.Split(want, "\n")
	var out strings.Builder
	for i := 0; i < len(gotLines) || i < len(wantLines); i++ {
		var gotLine, wantLine string
		if i < len(gotLines) {
			gotLine = gotLines[i]
		}
		if i < len(wantLines) {
			wantLine = wantLines[i]
		}
		if gotLine != wantLine {
			out.WriteString("-got:  " + gotLine + "\n+want: " + wantLine + "\n")
		}
	}
	return out.String()
}
