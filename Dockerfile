# This Dockerfile is used to build the image available on DockerHub
FROM golang:1.21 AS build

# Add everything
ADD . /usr/src/multi-networkpolicy-iptables

RUN cd /usr/src/multi-networkpolicy-iptables && \
    CGO_ENABLED=0 go build ./cmd/multi-networkpolicy-iptables/

FROM fedora:38
LABEL org.opencontainers.image.source=https://github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables
RUN dnf install -y iptables-utils iptables-legacy iptables-nft
RUN alternatives --set iptables /usr/sbin/iptables-nft
COPY --from=build /usr/src/multi-networkpolicy-iptables/multi-networkpolicy-iptables /usr/bin
WORKDIR /usr/bin

ENTRYPOINT ["multi-networkpolicy-iptables"]
