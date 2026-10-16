# Test data provenance (fetched 2026-10-16)

- `block_170.bin`, `block_2016.bin`: raw mainnet blocks from
  `https://mempool.space/api/block/<hash>/raw`
  (170 = 00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee,
  2016 = 00000000a141216a896c54f211301c436e557a8d55900637bbdce14c6c7bddef).
  The tests decode and `validate()` them, so a wrong download fails loudly.
- `full_169.json`, `full_2015.json`: copied from starkware-bitcoin/raito
  `packages/client/tests/data/` at 48c237ac941d8061a857ecd111d7e81107912556.
- `raito_felts_full_*.json`: `python -I scripts/data/format_args.py --input_file <fixture>`
  from the same Raito commit.
