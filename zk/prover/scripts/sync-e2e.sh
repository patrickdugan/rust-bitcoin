#!/usr/bin/env bash
# End to end: prove mainnet headers 1..TO in segments, then sync a light client from the
# proofs (verify, link from genesis, accept the tip), follow the chain natively to 2100,
# and check Satoshi's block-170 payment to Hal Finney against the proven MMR.
# Then try to get the client to accept tampered artifacts; every attempt must fail.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ZK=$(cd "$HERE/../.." && pwd)
BIN=${BIN:-/root/build/rb-zk-prover/release/zk-sync}
EXE=${EXE:-/root/build/raito-fork/release/chain_segment.executable.json}
OTHER_EXE=${OTHER_EXE:-/root/build/raito-fork/release/client.executable.json}
H=$ZK/sync/tests/data/headers_0_2100.bin
OUT=${OUT:-/root/zk-sync-e2e}
TO=${TO:-200}
SEG=${SEG:-8}
K=${K:-20}
HAL=f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
export RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-4}

verify() {  # proofs dir, extra flags...
  local dir=$1; shift
  "$BIN" verify --executable "$EXE" --proofs "$dir" --max-log-rows "$K" --min-work "${MIN:-$MIN_WORK}" "$@"
}
expect_reject() {  # label, command...
  local label=$1; shift
  if out=$("$@" 2>&1); then
    echo "{\"adversarial\": \"$label\", \"result\": \"ACCEPTED (BAD)\"}"; FAIL=1
  else
    # A Rust panic prints "thread 'main' panicked at FILE:L:C:" and the message below it.
    echo "{\"adversarial\": \"$label\", \"result\": \"rejected\", \"why\": $(echo "$out" | grep -m1 -A1 "panicked at" | tail -1 | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()[:220]))')}"
  fi
}

if [ "${SKIP_PROVE:-0}" != 1 ]; then
  rm -rf "$OUT"
  GUARD_LOG=$OUT.guard.log bash "$HERE/guard.sh" "$BIN" prove --executable "$EXE" --headers "$H" \
    --from 1 --to "$TO" --segment "$SEG" --out "$OUT" --max-log-rows "$K" 2>"$OUT.segments.log" || exit 1
fi

# Work floor: mainnet's chain work at height 200 (201 blocks of difficulty 1, each
# 0x100010001), the role Bitcoin Core's nMinimumChainWork plays.
MIN_WORK=0xC900C900C9

FAIL=0

echo "== light client"
verify "$OUT" --headers "$H" --extend-to 2100 \
  --spv-block "$ZK/args/tests/data/block_170.bin" --txid "$HAL" || exit 1

echo "== segment boundaries at heights 5 and 10 (six-timestamp chain-state digest)"
B5=$OUT.boundary5
if [ "${SKIP_PROVE:-0}" != 1 ]; then
  rm -rf "$B5"
  "$BIN" prove --executable "$EXE" --headers "$H" --from 1 --to 13 --segment 5 --out "$B5" --max-log-rows "$K" \
    2>/dev/null | cut -c1-300 || FAIL=1
fi
# Work at height 13: 14 blocks of 0x100010001.
MIN=0xE000E000E verify "$B5" | cut -c1-400
[ "${PIPESTATUS[0]}" = 0 ] || FAIL=1

echo "== adversarial"
T=$(mktemp -d)
segs=($(ls "$OUT"/*.proof.json | sort))
# 1. A segment missing from the middle.
mkdir -p "$T/gap" && cp "$OUT"/*.proof.json "$OUT/tip.json" "$T/gap/" && rm "$T/gap/$(basename "${segs[1]}")"
expect_reject "missing segment" verify "$T/gap"
# 2. Only a later part of the chain (not anchored at genesis).
mkdir -p "$T/late" && cp "$OUT/tip.json" "$T/late/" && for s in "${segs[@]:1}"; do cp "$s" "$T/late/"; done
expect_reject "not from genesis" verify "$T/late"
# 3. A tip whose total work was inflated.
mkdir -p "$T/work" && cp "$OUT"/*.proof.json "$T/work/" && \
  python3 -c "import json,sys; t=json.load(open('$OUT/tip.json')); w=int(t['total_work'],16)*2; t['total_work']=format(w,'064x'); json.dump(t,open('$T/work/tip.json','w'))"
expect_reject "inflated tip work" verify "$T/work"
# 4. A tip claiming a different best block.
mkdir -p "$T/hash" && cp "$OUT"/*.proof.json "$T/hash/" && \
  python3 -c "import json; t=json.load(open('$OUT/tip.json')); t['best_block_hash']='00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048'; json.dump(t,open('$T/hash/tip.json','w'))"
expect_reject "wrong tip hash" verify "$T/hash"
# 5. The right proofs checked against another program's bytecode (program pinning).
expect_reject "other program" "$BIN" verify --executable "$OTHER_EXE" --proofs "$OUT" --max-log-rows "$K"
# 6. A proof whose public output was edited (the STARK must fail).
mkdir -p "$T/out" && cp "$OUT"/*.proof.json "$OUT/tip.json" "$T/out/" && python3 - "$T/out/$(basename "${segs[0]}")" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
out = p["claim"]["public_data"]["public_memory"]["output"]
out[-1][1][0] ^= 1          # n_blocks low limb
json.dump(p, open(sys.argv[1], "w"))
PY
expect_reject "edited public output" verify "$T/out"
# 7. A client that expects more work than the proven chain has.
expect_reject "work floor above proven work" verify "$OUT" --min-work 0xC900C900CA
# 8-10. Proofs edited where verify_cairo would read the prover's value unchecked; the
# client's claim-shape gate must refuse them before the STARK check.
edit() {  # dir, python statement on p (the proof JSON)
  mkdir -p "$T/$1" && cp "$OUT"/*.proof.json "$OUT/tip.json" "$T/$1/"
  python3 -c "import json,sys; f=sys.argv[1]; p=json.load(open(f)); $2; json.dump(p,open(f,'w'))" "$T/$1/$(basename "${segs[0]}")"
}
edit queries "p['stark_proof']['config']['fri_config']['n_queries'] = 1"
expect_reject "fewer FRI queries" verify "$T/queries"
edit root "c = p['stark_proof']['commitments']; c[0] = c[1]"
expect_reject "other preprocessed root" verify "$T/root"
edit outptr "o = p['claim']['public_data']['public_memory']['public_segments']['output']; o['start_ptr']['value'] += 9; o['stop_ptr']['value'] += 9"
expect_reject "moved output segment" verify "$T/outptr"
rm -rf "$T"
echo "{\"e2e_failures\": $FAIL}"
exit $FAIL
