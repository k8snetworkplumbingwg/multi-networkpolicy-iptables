# This Dockerfile is used to build the image available on DockerHub
FROM golang:1.18 as build

# Add everything
ADD . /usr/src/multi-networkpolicy-iptables

RUN cd /usr/src/multi-networkpolicy-iptables && \
    go build ./cmd/multi-networkpolicy-iptables/

FROM centos:centos7
LABEL org.opencontainers.image.source https://github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables
RUN yum install -y iptables-utils
COPY --from=build /usr/src/multi-networkpolicy-iptables/multi-networkpolicy-iptables /usr/bin
WORKDIR /usr/bin

ENTRYPOINT ["multi-networkpolicy-iptables"]
