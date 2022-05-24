#!/bin/sh
set -o errexit

E2E="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"


if [ ! -d "${E2E}/bin" ]; then
	mkdir -p "${E2E}/bin"
fi

curl -Lo ${E2E}/bin/kind "https://github.com/kubernetes-sigs/kind/releases/download/v0.12.0/kind-$(uname)-amd64"
chmod +x ${E2E}/bin/kind
curl -Lo ${E2E}/bin/kubectl https://storage.googleapis.com/kubernetes-release/release/`curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt`/bin/linux/amd64/kubectl
chmod +x ${E2E}/bin/kubectl
curl -Lo ${E2E}/bin/koko https://github.com/redhat-nfvpe/koko/releases/download/v0.83/koko_0.83_linux_amd64
chmod +x ${E2E}/bin/koko
curl -Lo ${E2E}/bin/jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64
chmod +x ${E2E}/bin/jq
