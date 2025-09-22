#!/bin/sh

afl-clang-fast dummy.c -o dummy

AFL_PYTHON_MODULE=mutator PYTHONPATH=. AFL_CUSTOM_MUTATOR_ONLY=1 afl-fuzz -i testfile -o findings -- ./dummy

