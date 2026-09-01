# Dialing one tunnel by hand

The app renders these configs from the database into `/run/tsv-vpn` and drives
charon and xl2tpd itself. The manual path below proves a new endpoint works at
all, and isolates one that does not.

Substitute real values for `GATEWAY`, `PSK`, `PPP_USER`, `PPP_PASS` and
`REMOTE_SUBNET` (for example `198.51.100.0/24`).

## Host

The container uses the host kernel for IPsec and PPP. If `/dev/ppp` is missing:

```sh
modprobe af_key xfrm_user ppp_generic l2tp_ppp pppol2tp
ls -l /dev/ppp
```

Docker Desktop's VM has all of these modules already.

```sh
docker run -d --name tsv-vpn \
  --cap-add NET_ADMIN \
  --device /dev/net/tun --device /dev/ppp \
  --sysctl net.ipv4.ip_forward=1 \
  -e TS_AUTHKEY=... \
  tsv-vpn:dev
```

## Configs

Copy `examples/` somewhere outside the repo and fill in the real values there.
Those copies hold a PSK and a password; keep them untracked.

```sh
docker cp swanctl.conf tsv-vpn:/etc/swanctl/swanctl.conf
docker cp xl2tpd.conf  tsv-vpn:/etc/xl2tpd/xl2tpd.conf
docker cp ppp-peer     tsv-vpn:/etc/ppp/peers/example
docker cp chap-secrets tsv-vpn:/etc/ppp/chap-secrets
docker exec tsv-vpn chmod 600 /etc/swanctl/swanctl.conf /etc/ppp/chap-secrets
```

`example` is the connection name. It must match in four places: the swanctl
connection, the xl2tpd LAC, the peer filename, and `remotename` inside the peer
file.

## Dial

Everything below runs inside the container (`docker exec -it tsv-vpn bash`).

```sh
/usr/lib/ipsec/charon &
swanctl --load-all
swanctl --initiate --ike example --child example
```

Order matters. A gateway that requires IPsec drops bare L2TP, so the SA has to
exist before the L2TP session starts.

```sh
mkdir -p /var/run/xl2tpd
xl2tpd -D -C /var/run/xl2tpd/l2tp-control &
xl2tpd-control -c /var/run/xl2tpd/l2tp-control connect-lac example
```

xl2tpd reads its config file only at startup. LACs added or edited later go in
over the control socket, which is what the app does:

```sh
xl2tpd-control -c /var/run/xl2tpd/l2tp-control add-lac example \
  lns=GATEWAY name=PPP_USER pppoptfile=/etc/ppp/peers/example
```

Wait for the interface:

```sh
ip -brief link show type ppp
```

## Routes and NAT

```sh
ip route add REMOTE_SUBNET dev ppp0
iptables -t nat -A POSTROUTING -o ppp0 -j MASQUERADE
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu
```

MASQUERADE removes the need for a return route on the far side. The MSS clamp
covers the case where a tunnel pings fine and stalls on larger packets.

Advertise the subnet, then approve it in the admin console:

```sh
tailscale set --advertise-routes=REMOTE_SUBNET
```

## Verify

```sh
ping -I ppp0 HOST_IN_REMOTE_SUBNET
```

Then ping the same host from another tailnet device.

## Teardown

```sh
xl2tpd-control -c /var/run/xl2tpd/l2tp-control disconnect-lac example
swanctl --terminate --ike example
ip route del REMOTE_SUBNET
```

## Troubleshooting

**IKE never completes.** Watch charon's stderr. `AUTHENTICATION_FAILED` on the
first exchange is a wrong PSK. Silence means UDP 500/4500 is not reaching the
gateway.

**IKE completes, L2TP goes nowhere.** Usually NAT-T. Bridge networking puts the
container behind NAT, which is why `encap = yes` is forced in the example
config. Confirm the SA landed in UDP encapsulation:

```sh
swanctl --list-sas
```

**No `pppX`.** Check pppd actually started:

```sh
ps aux | grep pppd
```

`Couldn't open the /dev/ppp device` means the device was not passed into the
container, or the host has no `ppp_generic`.

**Tunnel up, nothing routes.** Check `net.ipv4.ip_forward`, then the MASQUERADE
rule:

```sh
iptables -t nat -L POSTROUTING -n -v
```
