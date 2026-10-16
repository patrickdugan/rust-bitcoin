#!/usr/bin/env bash
# Vendor the dependencies this fork patches, at the revisions Raito pins, into
# `rust-bitcoin-zk-vendor/` next to the rust-bitcoin checkout.
#
# Why outside the repo: the vendored crates inherit fields from their own Cargo
# workspaces, and Cargo resolves that inheritance against an already-loaded workspace
# root among the crate's ancestors when it finds one. Inside this repo that is
# rust-bitcoin's root manifest, which defines none of those fields.
#
# cairo-vm (m-kus fork c9aa51b) treats every wasm32 target as `no_std`, even with the
# `std` feature on: `lib.rs` has `cfg_attr(any(target_arch = "wasm32", not(feature =
# "std")), no_std)` and two modules gate alloc imports the same way. WASI has std, so
# key all of these on the feature alone; nothing changes on native targets.
# `#![deny(warnings)]` is dropped: a path dependency is not lint-capped like a git one.
#
# stwo-cairo (e8bc957) + patches/stwo-cairo-zk.patch:
# - a preprocessed-trace variant whose Seq columns stop at 2^k rows, with twiddles sized
#   to match. Stock stwo-cairo commits Seq columns up to 2^25 rows for every proof; their
#   Merkle tree alone needs a 2 GiB allocation, which wasm32 cannot make;
# - the two witness generators that build their own rayon pool fall back to the current
#   thread where threads cannot be spawned (wasm32-wasip1).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
V=$(cd "$HERE/../../../.." && pwd)/rust-bitcoin-zk-vendor
mkdir -p "$V"

CV=$V/cairo-vm
[ -d $CV/.git ] || git clone -q https://github.com/m-kus/cairo-vm $CV
git -C $CV checkout -q --force c9aa51b9360a6c89389cf88c93ac30b5213e64a7
OLD='any(target_arch = "wasm32", not(feature = "std"))'
NEW='not(feature = "std")'
FILES=$(grep -rlF --include='*.rs' "$OLD" $CV/vm/src | grep -v '/tests/' || true)
[ "$(echo "$FILES" | grep -c .)" -eq 3 ] || { echo "vendor.sh: expected 3 files, got: $FILES" >&2; exit 1; }
for f in $FILES; do OLD="$OLD" NEW="$NEW" perl -pi -e 's/\Q$ENV{OLD}\E/$ENV{NEW}/g' "$f"; done
perl -ni -e 'print unless /^#!\[deny\(warnings\)\]$/' $CV/vm/src/lib.rs
! grep -rqF --include='*.rs' "$OLD" $CV/vm/src --exclude-dir=tests || { echo "vendor.sh: cairo-vm patch incomplete" >&2; exit 1; }
echo "vendored cairo-vm c9aa51b + WASI std patch at $CV"

SC=$V/stwo-cairo
[ -d $SC/.git ] || git clone -q https://github.com/starkware-libs/stwo-cairo $SC
git -C $SC checkout -q --force e8bc9571675bb654b6e26a7bd53838a6ae78c344
git -C $SC clean -qfd
git -C $SC apply "$HERE/../patches/stwo-cairo-zk.patch"
echo "vendored stwo-cairo e8bc957 + zk patch at $SC"
