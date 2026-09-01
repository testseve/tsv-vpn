FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        strongswan strongswan-swanctl libcharon-extra-plugins \
        xl2tpd ppp \
        iproute2 iptables iputils-ping procps \
    && rm -rf /var/lib/apt/lists/*

COPY swanctl.conf /etc/swanctl/swanctl.conf
COPY strongswan.conf /etc/strongswan.d/test-server.conf
COPY xl2tpd.conf /etc/xl2tpd/xl2tpd.conf
COPY options.xl2tpd /etc/ppp/options.xl2tpd
COPY chap-secrets /etc/ppp/chap-secrets
COPY entrypoint.sh /entrypoint.sh
RUN chmod 600 /etc/swanctl/swanctl.conf /etc/ppp/chap-secrets && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
