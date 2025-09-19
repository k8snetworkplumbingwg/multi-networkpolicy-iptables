#!/bin/bash

E2E="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

pushd ${E2E}

suite_failed=0


bats ./tests/$1.bats
retval=$?
if [ $retval -ne 0 ]; then
    suite_failed=1
    ./bin/kind export logs ./artifacts/`basename $1`.test/kind-logs
fi

exit $suite_failed
