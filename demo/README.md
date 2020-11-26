
This demo assumes both working go & kind environments. For more information on
kind check:
https://kind.sigs.k8s.io/docs/user/quick-start/

Run a kind cluster:
```
kind create cluster
```

Deploy multus:
```
git clone https://github.com/intel/multus-cni
cat multus-cni/images/multus-daemonset.yml | kubectl apply -f -
```

Deploy the MultiNetworkPolicy CRD:
```
git clone https://github.com/k8snetworkplumbingwg/multi-networkpolicy
kubectl apply -f multi-networkpolicy/scheme.yml
```

Deploy the multi-networkpolicy implementation with iptables:
```
git clone https://github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables
kubectl apply -f multi-networkpolicy-iptables/demo/deploy.yml
```

Copy macvlan cni to the control plane node:
```
git clone https://github.com/containernetworking/plugins
plugins/build_linux.sh
...
docker cp plugins/bin/macvlan kind-control-plane:/opt/cni/bin/
```

Deploy a sample [network attachment definition](demo/net.yml), its
[policy](demo/policy.yml) and [pod](demo/alpine.yml) that attaches to that
network:
```
kubectl apply -f multi-networkpolicy-iptables/demo/net.yml
kubectl apply -f multi-networkpolicy-iptables/demo/policy.yml
kubectl apply -f multi-networkpolicy-iptables/demo/alpine.yml
```

You can the log in to the alpine pod and check the
[iptables rules](demo/iptables.log) that are enforcing the policy:
(note: this rule might be different from yours because we may change iptable generation rules...)

```
kubectl exec -ti alpine -- /bin/sh
...
apk update
apk add iptables
iptables -Lv
```
