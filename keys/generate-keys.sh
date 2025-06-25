#!/bin/bash
set -eux -o pipefail
test -f picc.master.key && exit 1
echo "Generating keys..."
head -c 16 /dev/random  > picc.master.key
head -c 16 /dev/random  > app1.master.key
head -c 16 /dev/random  > app1.rw1.key
for i in {2..13}; do
    head -c 16 /dev/random > app1.r${i}.key
done
cp -r ./* ../cmake-build-debug/keys/