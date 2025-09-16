#!/usr/bin/env bash
set -eux
docker compose build --progress=plain
docker compose run --rm nfc ./src/mifareinfo