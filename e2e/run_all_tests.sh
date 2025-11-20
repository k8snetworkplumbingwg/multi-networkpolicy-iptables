#!/bin/bash

E2E="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

pushd ${E2E}

suite_failed=0

for f in ./tests/*.bats; do
    # Dump logs to a file to catch shutdown errors
    tmp_logs="$(mktemp -d)"
    ./bin/kubectl logs -n kube-system ds/multi-networkpolicy-ds-amd64 --since=30s -f --all-pods > "${tmp_logs}/daemon-set.logs" &

    bats $f
    retval=$?
    if [ $retval -ne 0 ]; then
        suite_failed=1
        ./bin/kind export logs ./artifacts/`basename $f`.test/kind-logs
        cp "${tmp_logs}/daemon-set.logs" ./artifacts/`basename $f`.test/daemon-set.logs
    fi

    rm -rf "$tmp_logs"
done

exit $suite_failed
