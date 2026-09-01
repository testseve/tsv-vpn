#!/bin/sh
# Dials a real tunnel against the bundled L2TP server, breaks it, waits for
# recovery. See compose.test.yaml.
set -eu

compose="${COMPOSE:-docker compose -f compose.test.yaml}"
base="http://127.0.0.1:8099"
jar="$(mktemp)"

# On failure dump the container logs before teardown (CI has no other window
# into them). KEEP=1 leaves the rig up.
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        printf '\n== rig failed (exit %s); container state and logs follow\n' "$status" >&2
        $compose ps >&2 2>&1 || true
        $compose logs --no-color --tail 300 >&2 2>&1 || true
    fi
    rm -f "$jar"
    if [ "${KEEP:-0}" = "1" ]; then
        printf 'KEEP=1: leaving the rig up; "%s down -v" to clean it up\n' "$compose" >&2
    else
        $compose down -v --remove-orphans >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

log() { printf '\n== %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

api() { curl -sS -b "$jar" -c "$jar" "$@"; }

state() {
    connection_state "${1:-lab}"
}

connection_state() {
    api "$base/healthz" | jq -r --arg name "$1" '.connections[] | select(.name == $name) | .state' | head -1
}

last_error() {
    api "$base/healthz" | jq -r '.connections[0].last_error // ""'
}

wait_not() {
    avoid="$1"; timeout="${2:-60}"; elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        got="$(state)"
        [ "$got" != "$avoid" ] && { printf 'state %s after %ss\n' "$got" "$elapsed"; return 0; }
        sleep 2
        elapsed=$((elapsed + 2))
    done
    fail "connection never left $avoid"
}

ping_remote() {
    $compose exec -T tsv-vpn ping -c 2 -W 3 198.51.100.10 >/dev/null 2>&1
}

wait_ping() {
    timeout="${1:-120}"; elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        ping_remote && { printf 'traffic flows again after %ss\n' "$elapsed"; return 0; }
        sleep 5
        elapsed=$((elapsed + 5))
    done
    printf 'last state %s, last error: %s\n' "$(state)" "$(last_error)" >&2
    fail "traffic never came back"
}

wait_for() {
    want="$1"; timeout="${2:-90}"; elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        got="$(state)"
        [ "$got" = "$want" ] && { printf 'state %s after %ss\n' "$got" "$elapsed"; return 0; }
        sleep 3
        elapsed=$((elapsed + 3))
    done
    printf 'last state %s, last error: %s\n' "$(state)" "$(last_error)" >&2
    fail "connection never reached $want"
}

[ -f test/master.key ] || openssl rand -hex 32 > test/master.key

log "starting the rig"
$compose down -v --remove-orphans >/dev/null 2>&1 || true
$compose up -d --build --force-recreate

printf 'waiting for the ui'
until curl -sSf -o /dev/null "$base/healthz" 2>/dev/null || [ "$(curl -s -o /dev/null -w '%{http_code}' "$base/healthz")" = "503" ]; do
    printf '.'; sleep 2
done
printf '\n'

log "signing in"
api -o /dev/null -X POST -d 'password=test-admin' "$base/login"
api "$base/" | grep -q 'Add connection' || fail "dashboard did not render"

log "creating the connection through the ui"
code="$(api -o /dev/null -w '%{http_code}' -X POST \
    --data-urlencode 'name=lab' \
    --data-urlencode 'gateway_host=vpn-server' \
    --data-urlencode 'psk=test-preshared-key' \
    --data-urlencode 'ppp_username=testuser' \
    --data-urlencode 'ppp_password=test-ppp-password' \
    --data-urlencode 'remote_subnets=198.51.100.0/24' \
    --data-urlencode 'health_check_ip=198.51.100.10' \
    --data-urlencode 'enabled=1' \
    "$base/connections")"
[ "$code" = "204" ] || fail "creating the connection returned $code"
wait_for up 120

log "the database holds no plaintext secret"
if $compose exec -T tsv-vpn grep -a -q 'test-preshared-key' /data/tsv-vpn.db; then
    fail "the psk is readable in the database"
fi
if $compose exec -T tsv-vpn grep -a -q 'test-ppp-password' /data/tsv-vpn.db; then
    fail "the ppp password is readable in the database"
fi

log "traffic reaches the remote subnet"
ping_remote || fail "no reply through the tunnel"

log "scanning the tunnel subnet"
id="$(api -X POST -d 'cidr=198.51.100.0/24' -d 'connection_id=1' "$base/scans" \
    | sed -n 's/.*hx-get="\/scans\/\([a-f0-9]*\)".*/\1/p' | head -1)"
[ -n "$id" ] || fail "scan did not start"
found=""
for _ in $(seq 1 40); do
    body="$(api "$base/scans/$id")"
    printf '%s' "$body" | grep -q '198.51.100.10' && found=yes
    printf '%s' "$body" | grep -q 'hx-get="/scans/' || break
    sleep 3
done
[ -n "$found" ] || fail "scan did not find 198.51.100.10"

log "a second tunnel comes up beside the first"
code="$(api -o /dev/null -w '%{http_code}' -X POST \
    --data-urlencode 'name=lab2' \
    --data-urlencode 'gateway_host=vpn-server' \
    --data-urlencode 'psk=test-preshared-key' \
    --data-urlencode 'ppp_username=testuser' \
    --data-urlencode 'ppp_password=test-ppp-password' \
    --data-urlencode 'remote_subnets=203.0.113.0/24' \
    --data-urlencode 'health_check_ip=203.0.113.10' \
    --data-urlencode 'enabled=1' \
    "$base/connections")"
[ "$code" = "204" ] || fail "creating the second connection returned $code"

elapsed=0
until [ "$(connection_state lab2)" = "up" ]; do
    [ "$elapsed" -ge 120 ] && fail "the second tunnel never came up"
    sleep 3
    elapsed=$((elapsed + 3))
done
printf 'second tunnel up after %ss\n' "$elapsed"
[ "$(state lab)" = "up" ] || fail "the first tunnel dropped when the second dialled"
$compose exec -T tsv-vpn ping -c 2 -W 3 203.0.113.10 >/dev/null || fail "no reply on the second tunnel"
ping_remote || fail "the first tunnel stopped passing traffic"

log "deleting the second tunnel takes its routes with it"
api -o /dev/null -X DELETE "$base/connections/2"
sleep 5
$compose exec -T tsv-vpn ip route | grep -q '203.0.113.0/24' && fail "the deleted tunnel left its route behind"
[ "$(state lab)" = "up" ] || fail "deleting the second tunnel disturbed the first"

log "drill: charon is killed"
$compose exec -T tsv-vpn pkill -f /usr/lib/ipsec/charon
wait_ping 180
wait_for up 60

log "drill: pppd is killed"
$compose exec -T tsv-vpn pkill pppd
wait_not up 60
wait_for up 180
wait_ping 60

log "drill: the health check ip stops answering"
$compose exec -T vpn-server iptables -A INPUT -p icmp -d 198.51.100.10 -j DROP
wait_for failed 120
$compose exec -T vpn-server iptables -D INPUT -p icmp -d 198.51.100.10 -j DROP
wait_for up 150
wait_ping 60

log "drill: the psk is wrong"
api -o /dev/null -X POST \
    --data-urlencode 'name=lab' \
    --data-urlencode 'gateway_host=vpn-server' \
    --data-urlencode 'psk=not-the-preshared-key' \
    --data-urlencode 'ppp_username=testuser' \
    --data-urlencode 'ppp_password=test-ppp-password' \
    --data-urlencode 'remote_subnets=198.51.100.0/24' \
    --data-urlencode 'health_check_ip=198.51.100.10' \
    --data-urlencode 'enabled=1' \
    "$base/connections/1"
wait_for failed 180
api "$base/connections/1/logs" | grep -qi 'auth' || printf 'note: no authentication line in the ring buffer yet\n'

log "drill: the psk is corrected"
api -o /dev/null -X POST \
    --data-urlencode 'name=lab' \
    --data-urlencode 'gateway_host=vpn-server' \
    --data-urlencode 'psk=test-preshared-key' \
    --data-urlencode 'ppp_username=testuser' \
    --data-urlencode 'ppp_password=test-ppp-password' \
    --data-urlencode 'remote_subnets=198.51.100.0/24' \
    --data-urlencode 'health_check_ip=198.51.100.10' \
    --data-urlencode 'enabled=1' \
    "$base/connections/1"
wait_for up 180

log "drill: the container restarts"
$compose restart tsv-vpn
sleep 5
until curl -s -o /dev/null "$base/healthz"; do sleep 2; done
api -o /dev/null -X POST -d 'password=test-admin' "$base/login"
wait_for up 180
wait_ping 60

log "all drills passed"
