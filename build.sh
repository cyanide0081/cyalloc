FLAGS="-std=c99 -pedantic -Wall -Wextra -D_DEFAULT_SOURCE"

cc -o arena_test arena_test.c
cc -o page_test page_test.c

if [ "$1" = "run" ]; then
    ./arena_test
    ./page_test
fi
