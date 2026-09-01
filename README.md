# tsv-vpn

Tailscale subnet router with L2TP/IPsec client tunnels, in one container.
Tailnet devices reach the remote networks behind the tunnels and the LAN the
container runs on. Configuration happens in a web UI; credentials are encrypted
in SQLite.

```
tailnet peer -> tailscaled -> kernel routes -> ppp0..pppN -> remote subnet
                                            -> eth0       -> local LAN
```

The container runs tailscaled, charon (strongSwan), xl2tpd and a Go binary that
supervises them. The UI writes to SQLite and nudges a reconciler, which renders
the daemon configs and dials. On restart the reconciler replays desired state
from the database.

## Requirements

- A tailnet. An auth key is optional; the UI can log the node in through a
  browser.
- `/dev/net/tun` and `/dev/ppp` on the Docker host. If `/dev/ppp` is missing:

  ```sh
  modprobe af_key xfrm_user ppp_generic l2tp_ppp pppol2tp
  ```

- A VM or bare metal. Docker Desktop works. Unprivileged LXC does not: IPsec
  and PPP need kernel access it doesn't grant.

## Quickstart

Save this as `compose.yaml` in an empty directory:

```yaml
services:
  tsv-vpn:
    image: ghcr.io/testseve/tsv-vpn:latest
    container_name: tsv-vpn
    init: true
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
      - /dev/ppp
    sysctls:
      net.ipv4.ip_forward: "1"
      net.ipv6.conf.all.forwarding: "1"
    volumes:
      - tsv-vpn-ts-state:/var/lib/tailscale
      - tsv-vpn-data:/data
    environment:
      TS_AUTHKEY: ${TS_AUTHKEY:-}
      TS_HOSTNAME: ${TS_HOSTNAME:-tsv-vpn}
      ADMIN_PASSWORD_HASH: ${ADMIN_PASSWORD_HASH:-}
    secrets:
      - tsv_vpn_master_key
    ports:
      - "8080:8080"
    restart: unless-stopped

secrets:
  tsv_vpn_master_key:
    file: ${MASTER_KEY_PATH:-./master.key}

volumes:
  tsv-vpn-ts-state:
  tsv-vpn-data:
```

Then:

```sh
openssl rand -hex 32 > master.key
chmod 600 master.key

docker compose up -d
```

The master key encrypts stored VPN credentials. Back it up; losing it means
re-entering them.

Open http://\<server\>:8080. With no admin password configured, the first visit
shows a setup page; choosing a password there signs the browser in. Until then
the setup page answers anyone who can reach port 8080, so on a network with
untrusted devices either set `ADMIN_PASSWORD_HASH` in `.env` before first start
(see `.env.example`; generate the hash with
`docker run --rm ghcr.io/testseve/tsv-vpn hash-password 'password'`), or bind
the port to loopback (`"127.0.0.1:8080:8080"`) and reach it over SSH or the
tailnet.

From there:

1. **Tailnet page** → **Authorize on Tailscale** logs the node in through the
   browser. A reusable auth key can be pasted there instead.
2. **Add connection** → gateway, PSK, PPP credentials, remote subnets.
3. **Subnets page** → add the LAN from the detected chips. In bridge mode the
   host's LAN is found by probing the path to the internet.

The Tailnet page lists advertised routes with their approval state, shows the
equivalent `tailscale up` command, and can offer the node as an exit node
(which needs the same admin-console approval as a route).

Upgrade with `docker compose pull && docker compose up -d`. State lives in the
named volumes.

## Route approval

Tailscale doesn't route a subnet until it's approved: admin console →
[Machines](https://login.tailscale.com/admin/machines) → this node → Edit route
settings. Pending routes are flagged on the Tailnet page.

To auto-approve, the Tailnet page prints a snippet for the tailnet
[access controls](https://login.tailscale.com/admin/acls) covering the subnets
in use:

```json
{
  "tagOwners": {
    "tag:subnet-router": ["autogroup:admin"]
  },
  "autoApprovers": {
    "routes": {
      "10.0.0.0/8":     ["tag:subnet-router"],
      "172.16.0.0/12":  ["tag:subnet-router"],
      "192.168.0.0/16": ["tag:subnet-router"]
    }
  }
}
```

Auto-approval only applies to nodes logged in with an auth key tagged
`tag:subnet-router`. Approved prefixes cover anything narrower.

Linux peers need `tailscale up --accept-routes`; other platforms accept routes
by default.

## Configuration

| Variable              | Default             | Notes                                  |
| --------------------- | ------------------- | -------------------------------------- |
| `TS_AUTHKEY`          | -                   | Used on first start only               |
| `TS_HOSTNAME`         | `tsv-vpn`           | Node name in the tailnet               |
| `ADMIN_PASSWORD_HASH` | -                   | bcrypt; optional, set in the UI otherwise |
| `MASTER_KEY_FILE`     | `/run/secrets/tsv_vpn_master_key` | 32 raw bytes or 64 hex chars |
| `TSV_VPN_DB`          | `/data/tsv-vpn.db`  |                                        |
| `TSV_VPN_LISTEN`      | `:8080`             |                                        |

Two volumes: `/var/lib/tailscale` for tailnet state, `/data` for the database.

## Networking

Bridge networking is the default. Traffic leaving a tunnel is masqueraded
behind the container, so hosts on the far side need no route back to the
tailnet.

Use `network_mode: host` when LAN hosts need to see real client IPs, or when
Docker's NAT in front of IKE causes trouble. Drop the `ports` key with it.

## Health

`GET /healthz` returns the tailnet state and every enabled connection as JSON,
and backs the image's `HEALTHCHECK`. A down tunnel reports `degraded` but
still returns 200, since the reconciler is already redialing and a container
restart wouldn't help. Only a stopped tailnet fails the check.

## Security

- PSKs and PPP passwords are encrypted with AES-GCM before reaching SQLite,
  using the master key from the Docker secret. The app refuses to start
  without the key.
- Rendered daemon configs contain secrets in the clear, so they live in
  `/run/tsv-vpn` (tmpfs, 0600, root), never on a volume.
- The UI never renders a stored secret; edit forms show "set, leave blank to
  keep".
- Auth is a single admin password with a session cookie. Anyone who reaches
  the UI and knows the password can read every configured network, so keep
  the port on a trusted network, bound to `127.0.0.1`, or behind the tailnet.
- Until a password is set, the UI serves only the setup form. A node going
  straight onto an untrusted network should get `ADMIN_PASSWORD_HASH` up
  front (`docker run --rm ghcr.io/testseve/tsv-vpn hash-password '...'`).
- The subnet scanner is ICMP echo, one packet per host, capped at a /22, and
  only targets subnets that are configured or explicitly scanned. Network
  detection sends up to four rising-TTL probes toward 1.1.1.1; the result is
  cached for ten minutes.
- The container runs with `NET_ADMIN` and writes routes, NAT and MSS rules for
  its own ppp interfaces only.

## Development

```sh
docker compose -f compose.dev.yaml up --build
go test ./...
```

`compose.dev.yaml` reads the same `.env`. See `docs/manual-tunnel.md` for the
by-hand version of what the reconciler does, useful for debugging an endpoint
that won't dial.

### Test rig

`compose.test.yaml` pairs the app with a real L2TP/IPsec server and a fake
remote network:

```sh
sh test/rig.sh
docker compose -f compose.test.yaml down -v
```

The script drives the UI over HTTP (create a connection, wait for the tunnel,
ping the far side, scan the subnet), then runs failure drills: charon killed,
pppd killed, health check blackholed, wrong PSK, container restart. Requires
`/dev/ppp`; joins no tailnet.

## Troubleshooting

**Tailnet page says NeedsLogin with no link.** tailscaled takes a few seconds
to fetch one; the page polls.

**Container exits on start.** The entrypoint checks `/dev/net/tun`, `/dev/ppp`
and IP forwarding, and names whichever is missing in
`docker compose logs tsv-vpn`.

**Forgotten admin password.** Clear it and the setup page comes back:

```sh
docker compose exec tsv-vpn tsv-vpn reset-password
```

**Stuck on connecting.** Expand the card's log. `AUTHENTICATION_FAILED` is a
wrong PSK. `CHILD_SA ... not established` means UDP 500/4500 never reached the
gateway.

**IKE fine, no `pppX`.** L2TP blocked or PPP credentials rejected.
`Couldn't open the /dev/ppp device` means the device wasn't passed into the
container.

**Tunnel up, nothing routes.** Routes need approval in the admin console; the
Tailnet and Subnets pages mark pending ones. On Linux peers check
`--accept-routes`.

**Slow transfers, TLS handshakes hanging.** MTU. The app clamps MSS per tunnel
interface; confirm with `iptables -t mangle -S FORWARD`.

## Releases

Versions are `year.major.minor.patch` (`2026.1.0.0`) and live in
`version.go`; each gets an entry in `CHANGELOG.md`, which the UI serves as
release notes. Push to `main` publishes `ghcr.io/testseve/tsv-vpn:latest` plus
a `sha-` tag; a tag like `v2026.1.0.0` publishes `2026.1.0.0` and `2026.1.0`.
CI refuses a tag that does not match `version.go`, and the tests refuse a
version with no changelog entry. Both amd64 and arm64.

## License

MIT
