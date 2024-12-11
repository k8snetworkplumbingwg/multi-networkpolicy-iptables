#!/bin/bash

E2E="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

pushd ${E2E}

suite_failed=0

for f in ./tests/*.bats; do
    bats $f
    retval=$?
    if [ $retval -ne 0 ]; then
        suite_failed=1
        ./bin/kind export logs ./artifacts/`basename $f`.test/kind-logs
    fi
done

exit $suite_failed
