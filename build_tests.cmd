@echo off
set "FLAGS=-I. -std=c99 -pedantic -Wall -Wextra -D_CRT_SECURE_NO_WARNINGS -g -gcodeview"

@echo on
clang -o tests\page_test.exe tests\page_test.c %FLAGS%
clang -o tests\arena_test.exe tests\arena_test.c %FLAGS%
clang -o tests\stack_test.exe tests\stack_test.c %FLAGS%
@echo off
echo:

if /I "%~1" == "run" (
    .\tests\page_test.exe && echo:
    .\tests\arena_test.exe && echo:
    .\tests\stack_test.exe && echo:
)
