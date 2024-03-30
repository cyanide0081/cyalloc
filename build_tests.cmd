set "FLAGS=-I. -std=c99 -pedantic -Wall -Wextra -D_CRT_SECURE_NO_WARNINGS"

clang -o tests\page_test.exe tests\page_test.c %FLAGS%
clang -o tests\arena_test.exe tests\arena_test.c %FLAGS%

if /I "%~1" == "run" (
    .\tests\page_test.exe
    .\tests\arena_test.exe
)
