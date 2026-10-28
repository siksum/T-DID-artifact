#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE=infsec/monpoly@sha256:3d997ba9e927c8359455cea9b8df186dc5dc02b8ae3a7a7153ff60369387503d
DEST="$ROOT/experiments/eval/monitors/vendor"
mkdir -p "$DEST/musl"
docker pull --platform linux/amd64 "$IMAGE"
CID=$(docker create --platform linux/amd64 "$IMAGE")
trap 'docker rm "$CID" >/dev/null' EXIT INT TERM
docker cp -L "$CID:/usr/local/bin/monpoly" "$DEST/monpoly"
docker cp -L "$CID:/lib/ld-musl-x86_64.so.1" "$DEST/musl/ld-musl-x86_64.so.1"
docker cp -L "$CID:/usr/lib/libgmp.so.10" "$DEST/musl/libgmp.so.10"
chmod +x "$DEST/monpoly" "$DEST/musl/ld-musl-x86_64.so.1"
cd "$DEST"
printf '%s\n' \
 'c3e41482dfa170ce81ad8372b4fc6dbdbb551b9e554a52992ea275f1004e679e  monpoly' \
 'f513b5bbac4ce52d26b70d90520da47868c6244e84108ac21122bbf9b7e9d300  musl/ld-musl-x86_64.so.1' \
 'feeca03dbc3c9bde02a01b31a5f6430cd12b9acfcec4f369495b895eed21e4de  musl/libgmp.so.10' | sha256sum -c -
