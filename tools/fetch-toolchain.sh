#!/bin/sh
# Fetches the pinned Zig toolchain (bundles clang + musl) used for the
# static big-endian MIPS32r2 soft-float build. Verifies the SHA256.
set -eu

ZIG_VERSION=0.13.0
ZIG_SHA256=d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea
ZIG_TARBALL=zig-linux-x86_64-$ZIG_VERSION.tar.xz
ZIG_URL=https://ziglang.org/download/$ZIG_VERSION/$ZIG_TARBALL

dir=$(cd "$(dirname "$0")/.." && pwd)/.toolchain
mkdir -p "$dir"
cd "$dir"

if [ -x zig-linux-x86_64-$ZIG_VERSION/zig ]; then
	echo "toolchain present: $dir/zig-linux-x86_64-$ZIG_VERSION"
	exit 0
fi
[ -f "$ZIG_TARBALL" ] || curl -fsSLO "$ZIG_URL"
echo "$ZIG_SHA256  $ZIG_TARBALL" | sha256sum -c -
tar xf "$ZIG_TARBALL"
echo "toolchain ready: $dir/zig-linux-x86_64-$ZIG_VERSION"
