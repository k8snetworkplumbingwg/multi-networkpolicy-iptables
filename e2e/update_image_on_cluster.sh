#!/bin/sh
set -o errexit

E2E="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
export PATH=${PATH}:${E2E}/bin
OCI_BIN="${OCI_BIN:-docker}"
IMAGE="localhost:5000/multus-networkpolicy-iptables:e2e"

$OCI_BIN build -t ${IMAGE} ${E2E}/..
$OCI_BIN push ${IMAGE}
new_image_with_digest=`${OCI_BIN} inspect --format='{{index .RepoDigests 0}}' ${IMAGE}`

kubectl set image -n kube-system ds/multi-networkpolicy-ds-amd64 multi-networkpolicy=${new_image_with_digest}
