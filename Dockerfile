# This Dockerfile is used to build the image available on DockerHub
FROM golang:1.21 AS build

# Add everything
ADD . /usr/src/multi-networkpolicy-iptables

RUN cd /usr/src/multi-networkpolicy-iptables && \
    CGO_ENABLED=0 go build ./cmd/multi-networkpolicy-iptables/

FROM docker.io/debian:stable-slim
LABEL org.opencontainers.image.source=https://github.com/telekom/multi-networkpolicy-iptables
RUN apt update \
    && apt install -y --no-install-recommends \
    nftables \
    && apt clean \
    && rm -Rf /usr/share/doc && rm -Rf /usr/share/man \
    && rm -rf /var/lib/apt/lists/* \
    && touch -d "2 hours ago" /var/lib/apt/lists
COPY --from=build /usr/src/multi-networkpolicy-iptables/multi-networkpolicy-iptables /usr/bin
WORKDIR /usr/bin

ENTRYPOINT ["multi-networkpolicy-iptables"]
