FLAGS="-std=c99 -pedantic -Wall -Wextra -D_DEFAULT_SOURCE"

cc -o tests/page_test tests/page_test.c
cc -o tests/arena_test tests/arena_test.c

if [ "$1" = "run" ]; then
    tests/page_test
    tests/arena_test
fi
