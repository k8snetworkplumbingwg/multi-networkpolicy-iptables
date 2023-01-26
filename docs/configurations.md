## Multi-networkpolicy-iptables Configurations


### Command Line Options

Most command line options have description in help, so please execute with `--help` to see the option.

```
$ ./multi-networkpolicy-iptables --help
```

### Advanced Options

#### Add exceptional IPv6 prefix address to accept

Some IPv6 networks may require accepting traffic from/to specific address prefixes for the network, such as multicast address (all routers multicast address, link-local address and so on). You can configure `--allow-ipv6-src-prefix` and `--allow-ipv6-dst-prefix` to specify which prefix should be accepted (even though network policy does not have it). Both options accept comma separated IPv6 prefix list.

```
--allow-ipv6-src-prefix=fe80::/10
--allow-ipv6-dst-prefix=fe80::/10,ff00::/8
```

#### Add custom iptables/ip6tables rules

Some IPv4/v6 networks may require accepting some specific traffic (e.g. DHCP). You can add custom iptable rules in ingress/egress for IPv4/v6 network to accept such traffics, by 

- `--custom-v4-ingress-rule-file`
- `--custom-v4-egress-rule-file`
- `--custom-v6-ingress-rule-file`
- `--custom-v6-egress-rule-file`

Each option takes file path for iptable rules. This file can contain 

- iptable rules (no `-A` option)
- comment (begins with '#')

Here is the example to accept DHCPv6 packets using the options.
```
$ cat testv6IngressRules.txt
# comment: this accepts DHCPv6 packets from link-local address
-m udp -p udp --dport 546 -d fe80::/64 -j ACCEPT

$ cat testv6EgressRules.txt
# comment: this rules accepts DHCPv6 packet to dhcp relay agents/servers
-m udp -p udp --dport 547 -d ff02::1:2 -j ACCEPT

$ ./multi-networkpolicy-iptables \
    (snip, some options here) \
    --custom-v6-ingress-rule-file testv6IngressRules.txt \
    --custom-v6-egress-rule-file testv6EgressRules.txt
```
