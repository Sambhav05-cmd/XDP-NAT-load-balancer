#!/usr/bin/env bash
set -e
ROOT=$(dirname "$(realpath "$0")")/..
cd "$ROOT"
echo "==> running code generation"
./scripts/gen.sh
echo "==> creating bin directory"
mkdir -p bin
echo "==> building daemon"
go build -o bin/lbxdpd ./cmd/lbxdpd
echo "==> building ctl"
go build -o bin/lbctl ./cmd/lbctl
echo "==> build complete"
ls -lh bin
