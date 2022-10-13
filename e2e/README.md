## e2e test with kind


### How to test e2e

This requires [Bats](https://github.com/bats-core/bats-core) for test runner. Please install bats (e.g. dnf, apt and so on).

```
$ git clone https://github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables
$ cd multi-networkpolicy-iptables/e2e
$ ./get_tools.sh
$ ./setup_cluster.sh
$ ./tests/simple-v4-ingress.bats
```

### How to teardown cluster

```
$ kind delete cluster
$ docker kill kind-registry
$ docker rm kind-registry
```

### How to deploy server image with new changes

After making changes to the code, it is possible to update the server Daemonset image with the script:

```
./update_image_on_cluster.sh
```
