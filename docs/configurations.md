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

