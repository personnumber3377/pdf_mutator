#!/bin/sh

afl-clang-fast dummy.c -o dummy

afl-fuzz -i testfile -o findings -- ./dummy

