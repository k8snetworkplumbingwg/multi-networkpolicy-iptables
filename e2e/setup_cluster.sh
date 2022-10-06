#!/bin/sh
set -o errexit

export PATH=./bin:${PATH}

# define the OCI binary to be used. Acceptable values are `docker`, `podman`.
# Defaults to `docker`.
OCI_BIN="${OCI_BIN:-docker}"

kind_network='kind'
reg_name='kind-registry'
reg_port='5000'
running="$($OCI_BIN inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)"
if [ "${running}" != 'true' ]; then
  $OCI_BIN run -d --restart=always -p "${reg_port}:5000" --name "${reg_name}" registry:2
fi

$OCI_BIN build -t localhost:5000/multus-networkpolicy-iptables:e2e -f ../Dockerfile ..
$OCI_BIN push localhost:5000/multus-networkpolicy-iptables:e2e

reg_host="${reg_name}"
echo "Registry Host: ${reg_host}"

# deploy cluster with kind
cat <<EOF | kind create cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${reg_port}"]
    endpoint = ["http://${reg_host}:${reg_port}"]
nodes:
  - role: control-plane
  - role: worker
networking:
  disableDefaultCNI: true
  podSubnet: 10.244.0.0/16
EOF

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${reg_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF

# reconnect container registry if it is not connected
containers=$($OCI_BIN network inspect ${kind_network} -f "{{range .Containers}}{{.Name}} {{end}}")
needs_connect="true"
for c in $containers; do
  if [ "$c" = "${reg_name}" ]; then
    needs_connect="false"
  fi
done
if [ "${needs_connect}" = "true" ]; then
  $OCI_BIN network connect "${kind_network}" "${reg_name}" || true
fi

kind export kubeconfig
sleep 1

# install calico
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/master/manifests/calico.yaml
kubectl -n kube-system set env daemonset/calico-node FELIX_IGNORELOOSERPF=true
kubectl -n kube-system set env daemonset/calico-node FELIX_XDPENABLED=false

kubectl -n kube-system wait --for=condition=available deploy/coredns --timeout=300s

#install multus
kubectl create -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset.yml
sleep 3
kubectl -n kube-system wait --for=condition=ready -l name=multus pod --timeout=660s
kubectl create -f cni-install.yml
sleep 3
kubectl -n kube-system wait --for=condition=ready -l name=cni-plugins pod --timeout=300s


# install multi-networkpolicy API
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multi-networkpolicy/master/scheme.yml

# install multi-networkpolicy-iptables
kubectl apply -f multi-network-policy-iptables-e2e.yml
sleep 3
kubectl -n kube-system wait --for=condition=ready -l name=multi-networkpolicy pod --timeout=300s
