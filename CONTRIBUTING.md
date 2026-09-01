# Contributing

This project is maintained on a best-effort basis. It does what I built it to
do and I'm not actively developing it further, so issues and pull requests may
sit for a while, and features I don't use myself are unlikely to be merged.
Bug fixes are welcome. Security reports get priority; see
[SECURITY.md](SECURITY.md).

If you need something it doesn't do, forking is encouraged.

## Development

```sh
make check      # gofmt, go vet, go test
make race       # go test -race
make lint       # golangci-lint
make vuln       # govulncheck
```

Changes to the reconciler, the daemons or the rendered configs also need the
end-to-end rig, which dials a real L2TP/IPsec tunnel against a bundled server
and runs the failure drills:

```sh
make e2e         # needs /dev/ppp on the host; takes a few minutes
make e2e-keep    # leave the containers up afterwards
make e2e-logs    # follow the container logs
make e2e-down    # tear the rig down
```

CI runs `make check` and the rig on every pull request.

## Local instance

```sh
make dev         # http://127.0.0.1:8080, persistent volume
make dev-down
```
