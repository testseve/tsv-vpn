# Changelog

## 2026.1.0.0 - 2026-08-19

The first versioned release.

### Added

- L2TP/IPsec tunnels configured from the web UI, dialled by a reconciler and
  replayed from SQLite after a restart.
- Tailnet subnet routing: local and tunnel subnets advertised to the tailnet,
  with route approval hints from tailscaled.
- Network discovery: interface subnets, a default-gateway guess and a path
  probe that finds the LAN behind the docker bridge.
- Subnet scanning: an ICMP sweep of any subnet up to a /22, with reverse DNS
  and one-click health-check targets.
- Health checks that ping through each tunnel's own interface and report on
  `/healthz`.
- Health checks on local subnets: pick a host from a scan and the dashboard
  reports whether the LAN answers.
- Connection cards show the addresses pppd assigned: the tunnel IP, the peer IP
  and when the tunnel came up.
- A logo, shown in the header and the sign-in page and served as the favicon.
- Release notes in the UI, backed by this changelog.
- Encrypted credentials at rest, a password-protected UI and daily log files
  under `/data/logs`.

### Changed

- Buttons and panels animate: presses give feedback, in-flight requests show a
  spinner and scans display a progress bar.
- Detected networks no longer offer a second copy of the docker bridge subnet.
