# Cross-compile on the native architecture; emulated Go builds cost minutes.
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS build

ARG TAILWIND_VERSION=v4.3.3
ARG BUILDARCH
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY version.go CHANGELOG.md ./
COPY cmd cmd
COPY internal internal

RUN arch="$(case "$BUILDARCH" in amd64) echo x64 ;; arm64) echo arm64 ;; esac)" \
    && curl -fsSL -o /usr/local/bin/tailwindcss \
        "https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWIND_VERSION}/tailwindcss-linux-${arch}" \
    && chmod +x /usr/local/bin/tailwindcss \
    && tailwindcss -i internal/web/input.css -o internal/web/static/app.css --minify

RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -o /out/tsv-vpn ./cmd/tsv-vpn

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg \
        -o /usr/share/keyrings/tailscale-archive-keyring.gpg \
    && curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list \
        -o /etc/apt/sources.list.d/tailscale.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        tailscale \
        strongswan strongswan-swanctl libcharon-extra-plugins \
        xl2tpd ppp \
        iproute2 iptables iputils-ping procps \
    && apt-get purge -y gnupg \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY etc/strongswan.d/tsv-vpn.conf /etc/strongswan.d/tsv-vpn.conf
COPY --from=build /out/tsv-vpn /usr/local/bin/tsv-vpn
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Track TSV_VPN_LISTEN so overriding the listen address keeps the healthcheck
# working.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD p="${TSV_VPN_LISTEN:-:8080}"; curl -fsS -o /dev/null "http://127.0.0.1:${p##*:}/healthz"

VOLUME /var/lib/tailscale
VOLUME /data

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
