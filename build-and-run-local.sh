#!/usr/bin/env bash
set -eux
mkdir -p ./cmake-build-debug
cd ./cmake-build-debug
cmake ../CMakeLists.txt
cmake --build .
echo "Reading card..."
./src/mifareinfo
## Or:
# LIBNFC_DEFAULT_DEVICE=pn532_uart:/dev/ttyACM0 ./src/mifareinfo