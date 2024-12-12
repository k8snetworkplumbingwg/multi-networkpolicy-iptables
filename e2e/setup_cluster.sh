#!/bin/sh
set -o errexit

export PATH=./bin:${PATH}

# define the OCI binary to be used. Acceptable values are `docker`, `podman`.
# Defaults to `docker`.
OCI_BIN="${OCI_BIN:-docker}"

kind_network='kind'

$OCI_BIN build -t localhost:5000/multus-networkpolicy-iptables:e2e -f ../Dockerfile ..

# deploy cluster with kind
cat <<EOF | kind create cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF

# load multus image from container host to kind node
kind load docker-image localhost:5000/multus-networkpolicy-iptables:e2e

kind export kubeconfig
sleep 1

# install calico
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.1/manifests/calico.yaml
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
