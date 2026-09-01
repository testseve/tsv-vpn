package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"tsv-vpn/internal/db"
)

type Tunnel struct {
	Name        string
	GatewayHost string
	// Resolved gateway address. IKEv1 selects the PSK by peer address before
	// identities are exchanged, so each secret is keyed by one; unresolved
	// falls back to %any, correct for a single tunnel.
	GatewayAddr string
	PSK         string
	Username    string
	Password    string
	// Not rendered into any file but part of the fingerprint: subnet edits
	// reach the running tunnel's routes by redial.
	RemoteSubnets []string
}

func FromConnection(conn db.Connection, secrets db.Secrets, gatewayAddr string) Tunnel {
	return Tunnel{
		Name:          conn.Name,
		GatewayHost:   conn.GatewayHost,
		GatewayAddr:   gatewayAddr,
		PSK:           secrets.PSK,
		Username:      conn.PPPUsername,
		Password:      secrets.PPPPassword,
		RemoteSubnets: conn.RemoteSubnets,
	}
}

func (t Tunnel) pskIdentity() string {
	if t.GatewayAddr == "" {
		return "%any"
	}
	return t.GatewayAddr
}

var swanctlTemplate = template.Must(template.New("swanctl").Parse(
	`connections {
{{- range . }}
    {{ .Name }} {
        version = 1
        local_addrs = %any
        remote_addrs = {{ .GatewayHost }}
        encap = yes
        keyingtries = 0
        rekey_time = 0
        proposals = aes256-sha256-modp2048,aes128-sha1-modp1024,default

        local {
            auth = psk
        }
        remote {
            auth = psk
        }

        children {
            {{ .Name }} {
                mode = transport
                local_ts = dynamic[udp/l2tp]
                remote_ts = dynamic[udp/l2tp]
                esp_proposals = aes256-sha256,aes128-sha1,default
                start_action = none
                dpd_action = clear
            }
        }
    }
{{- end }}
}

secrets {
{{- range . }}
    ike-{{ .Name }} {
        id = {{ .Identity }}
        secret = "{{ .PSK }}"
    }
{{- end }}
}
`))

var xl2tpdTemplate = template.Must(template.New("xl2tpd").Parse(
	`[global]
access control = no
port = 1701
{{ range . }}
[lac {{ .Name }}]
lns = {{ .GatewayHost }}
require chap = yes
refuse pap = yes
require authentication = no
name = {{ .Username }}
pppoptfile = {{ .PeerFile }}
length bit = yes
redial = yes
redial timeout = 10
max redials = 5
{{ end -}}
`))

var pppPeerTemplate = template.Must(template.New("peer").Parse(
	`remotename {{ .Name }}
ipparam {{ .Name }}
user "{{ .Username }}"
noauth
refuse-eap
refuse-pap
hide-password
nodefaultroute
noipdefault
usepeerdns
noccp
mtu 1400
mru 1400
lcp-echo-interval 10
lcp-echo-failure 5
connect-delay 5000
`))

type swanctlTunnel struct {
	Tunnel
	Identity string
}

type xl2tpdTunnel struct {
	Tunnel
	PeerFile string
}

func RenderSwanctl(tunnels []Tunnel) (string, error) {
	view := make([]swanctlTunnel, 0, len(tunnels))
	for _, tunnel := range tunnels {
		view = append(view, swanctlTunnel{Tunnel: tunnel, Identity: tunnel.pskIdentity()})
	}
	return render(swanctlTemplate, view)
}

func RenderXL2TPD(tunnels []Tunnel, peersDir string) (string, error) {
	view := make([]xl2tpdTunnel, 0, len(tunnels))
	for _, tunnel := range tunnels {
		view = append(view, xl2tpdTunnel{Tunnel: tunnel, PeerFile: filepath.Join(peersDir, tunnel.Name)})
	}
	return render(xl2tpdTemplate, view)
}

func RenderPPPPeer(tunnel Tunnel) (string, error) {
	return render(pppPeerTemplate, tunnel)
}

func RenderCHAPSecrets(tunnels []Tunnel) string {
	var out strings.Builder
	out.WriteString("# client\tserver\tsecret\tIP addresses\n")
	for _, tunnel := range tunnels {
		// Quoted: the file is whitespace-delimited and passwords may contain
		// spaces; '"' itself is rejected on the way in.
		fmt.Fprintf(&out, "%s\t*\t%q\t*\n", tunnel.Username, tunnel.Password)
	}
	return out.String()
}

func render(tmpl *template.Template, data any) (string, error) {
	var out strings.Builder
	if err := tmpl.Execute(&out, data); err != nil {
		return "", err
	}
	return out.String(), nil
}

// Rendered files hold secrets in the clear: tmpfs only, root-only.
func Write(dir string, tunnels []Tunnel) error {
	peersDir := filepath.Join(dir, "peers")
	if err := os.MkdirAll(peersDir, 0o700); err != nil {
		return err
	}

	swanctl, err := RenderSwanctl(tunnels)
	if err != nil {
		return err
	}
	xl2tpd, err := RenderXL2TPD(tunnels, peersDir)
	if err != nil {
		return err
	}
	files := map[string]string{
		filepath.Join(dir, "swanctl.conf"): swanctl,
		filepath.Join(dir, "xl2tpd.conf"):  xl2tpd,
		filepath.Join(dir, "chap-secrets"): RenderCHAPSecrets(tunnels),
	}
	for _, tunnel := range tunnels {
		peer, err := RenderPPPPeer(tunnel)
		if err != nil {
			return err
		}
		files[filepath.Join(peersDir, tunnel.Name)] = peer
	}

	if err := pruneStalePeers(peersDir, tunnels); err != nil {
		return err
	}
	for path, contents := range files {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func pruneStalePeers(peersDir string, tunnels []Tunnel) error {
	entries, err := os.ReadDir(peersDir)
	if err != nil {
		return err
	}
	wanted := make(map[string]bool, len(tunnels))
	for _, tunnel := range tunnels {
		wanted[tunnel.Name] = true
	}
	for _, entry := range entries {
		if wanted[entry.Name()] {
			continue
		}
		if err := os.Remove(filepath.Join(peersDir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}
