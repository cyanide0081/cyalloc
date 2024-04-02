#!/bin/sh

FLAGS="-I. -std=c99 -pedantic -Wall -Wextra -D_DEFAULT_SOURCE"

set -xe
cc -o tests/page_test tests/page_test.c $FLAGS
cc -o tests/arena_test tests/arena_test.c $FLAGS
set +xe

if [ "$1" = "run" ]; then
    tests/page_test
    tests/arena_test
fi
