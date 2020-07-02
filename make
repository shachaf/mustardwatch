#!/bin/bash

set -euo pipefail

cc=clang
#cc=tcc

cflags=()
cflags+=(-Wall -Wextra -g)
#cflags+=(-O2 -DNDEBUG)

$cc \
  -o mustardwatch mustardwatch.c \
  "${cflags[@]}"
