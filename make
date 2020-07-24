#!/bin/bash

set -euo pipefail

cc=clang

cflags=()
cflags+=(-Wall -Wextra)
cflags+=(-g)
cflags+=(-O2)

mkdir -p build

$cc \
  -o build/mustardwatch mustardwatch.c \
  "${cflags[@]}"
