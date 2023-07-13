FROM docker.io/fedora:38

LABEL org.opencontainers.image.source https://github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables
LABEL org.opencontainers.image.base.name ghcr.io/k8snetworkplumbingwg/multi-networkpolicy-iptables:e2e-test
RUN dnf install -y nginx iptables-utils iptables-legacy iptables-nft net-tools iputils iproute tcpdump wireshark-cli nmap-ncat
RUN alternatives --set iptables /usr/sbin/iptables-nft
