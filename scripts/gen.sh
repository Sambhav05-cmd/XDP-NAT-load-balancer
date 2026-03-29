#!/usr/bin/env bash
set -e
echo "==> generating protobuf bindings"
protoc -I . \
--go_out=paths=source_relative:. \
--go-grpc_out=paths=source_relative:. \
proto/control.proto
echo "==> generating eBPF bindings"
go generate ./cmd/lbxdpd
echo "==> generation done"
