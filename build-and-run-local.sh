#!/usr/bin/env bash
set -eux
mkdir -p ./cmake-build-debug
cd ./cmake-build-debug
cmake ../CMakeLists.txt
cmake --build .
echo "Reading card..."
./src/mifareinfo