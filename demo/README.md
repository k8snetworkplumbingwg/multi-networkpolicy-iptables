
This demo assumes both working go & kind environments. For more information on
kind check:
https://kind.sigs.k8s.io/docs/user/quick-start/

Run a kind cluster:
```
kind create cluster
```

Deploy multus:
```
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset.yml
```

Deploy the MultiNetworkPolicy CRD:
```
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multi-networkpolicy/master/scheme.yml
```

Deploy the multi-networkpolicy implementation with iptables:
```
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/master/demo/deploy.yml 
```

Copy macvlan cni to the control plane node:
```
curl -sSf -L --retry 5 https://github.com/containernetworking/plugins/releases/download/v1.5.0/cni-plugins-linux-amd64-v1.5.0.tgz | tar -xz -C . ./macvlan
...
docker cp macvlan kind-control-plane:/opt/cni/bin/
```

Deploy a sample [network attachment definition](demo/net.yml), its
[policy](demo/policy.yml) and [pod](demo/alpine.yml) that attaches to that
network:
```
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/master/demo/net.yml
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/master/demo/policy.yml
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multi-networkpolicy-iptables/master/demo/alpine.yml
```

You can the log in to the alpine pod and check the
[iptables rules](demo/iptables.log) that are enforcing the policy:
(note: this rule might be different from yours because we may change iptable generation rules...)

```
kubectl exec -ti alpine -- /bin/sh
...
apk update
apk add iptables
iptables -vL
```
