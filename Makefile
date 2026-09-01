# `make` runs the fast checks.
.DEFAULT_GOAL := check
.PHONY: check fmt vet test race cover lint vuln tidy e2e e2e-keep e2e-logs e2e-down dev dev-down

# Same set CI runs on every pull request.
check: fmt vet test

fmt:
	@test -z "$$(gofmt -l cmd internal)" || { echo "gofmt needed:"; gofmt -l cmd internal; exit 1; }

vet:
	go vet ./...

test:
	go test ./...

# Supervisor, reconciler and the session/throttle maps run concurrently.
race:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

tidy:
	go mod tidy
	git diff --exit-code go.mod go.sum

# Build the image, dial a real tunnel against the bundled L2TP server, run
# the failure drills. Needs /dev/ppp on the host; takes minutes.
e2e:
	sh test/rig.sh

# Leave the containers running afterwards.
e2e-keep:
	KEEP=1 sh test/rig.sh

e2e-logs:
	docker compose -f compose.test.yaml logs -f

e2e-down:
	docker compose -f compose.test.yaml down -v --remove-orphans

# Local instance with a persistent volume, on http://127.0.0.1:8080.
dev:
	docker compose -f compose.dev.yaml up --build

dev-down:
	docker compose -f compose.dev.yaml down
