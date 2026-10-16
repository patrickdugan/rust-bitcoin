#!/usr/bin/env python3
"""Fetch mainnet block headers into a flat file of 80-byte raw headers.

usage: fetch-headers.py OUT.bin FIRST_HEIGHT LAST_HEIGHT

Uses mempool.space's `/api/blocks/<height>` (10 blocks per request, newest first),
rebuilds each 80-byte header from the JSON fields, and checks that its double SHA-256
equals the block id the API reports and that each header links to the previous one.
Nothing downstream trusts this file: the Rust side re-decodes every header with
rust-bitcoin and the proofs re-check every rule. Standard library only.
"""

import hashlib
import json
import struct
import sys
import time
import urllib.request

API = "https://mempool.space/api/blocks/{}"


def header_bytes(b: dict) -> bytes:
    return (
        struct.pack("<i", b["version"])
        + bytes.fromhex(b["previousblockhash"] if b["height"] else "00" * 32)[::-1]
        + bytes.fromhex(b["merkle_root"])[::-1]
        + struct.pack("<III", b["timestamp"], b["bits"], b["nonce"])
    )


def block_hash(h: bytes) -> str:
    return hashlib.sha256(hashlib.sha256(h).digest()).digest()[::-1].hex()


def fetch(height: int) -> list:
    for attempt in range(5):
        try:
            req = urllib.request.Request(API.format(height), headers={"User-Agent": "bitcoin-zk/0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except Exception as e:  # rate limits and transient errors: back off and retry
            time.sleep(2 * (attempt + 1))
            last = e
    raise SystemExit(f"fetch {height}: {last}")


def main() -> None:
    out, first, last = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    headers = {}
    h = last
    while h >= first:
        for b in fetch(h):
            raw = header_bytes(b)
            assert len(raw) == 80
            if block_hash(raw) != b["id"]:
                raise SystemExit(f"height {b['height']}: rebuilt header does not hash to {b['id']}")
            headers[b["height"]] = raw
        h -= 10
        time.sleep(0.25)
    chain = [headers[i] for i in range(first, last + 1)]
    for i in range(1, len(chain)):
        if chain[i][4:36][::-1].hex() != block_hash(chain[i - 1]):
            raise SystemExit(f"height {first + i}: does not link to the previous header")
    with open(out, "wb") as f:
        f.write(b"".join(chain))
    print(f"{len(chain)} headers {first}..{last}, tip {block_hash(chain[-1])}")


if __name__ == "__main__":
    main()
