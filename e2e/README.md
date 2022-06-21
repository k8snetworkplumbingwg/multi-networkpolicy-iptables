# E2E test with kind

This folder contains scripts to setup a KinD cluster to run end to end (e2e) tests.
Following sections describes how to setup/teardown the environment and run tests.

## How to setup the cluster


```sh
$ cd e2e
$ ./get_tools.sh
$ ./setup_cluster.sh
```

## How to run E2E tests

```sh
./bin/kind get kubeconfig > /tmp/kubeconfig
export KUBECONFIG=/tmp/kubeconfig
go test -tags=e2e -v ./test
```

## How to teardown cluster

```sh
$ ./teardown.sh
```
