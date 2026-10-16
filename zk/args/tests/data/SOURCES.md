# Test data provenance (fetched 2026-10-16)

- `block_170.bin`, `block_2016.bin`: raw mainnet blocks from
  `https://mempool.space/api/block/<hash>/raw`
  (170 = 00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee,
  2016 = 00000000a141216a896c54f211301c436e557a8d55900637bbdce14c6c7bddef).
  The tests decode and `validate()` them, so a wrong download fails loudly.
- `block_116928.bin`, `block_481824.bin`, `block_709632.bin`: same source
  (116928 = 000000000000494457221111a6a99da34a993c69c2761582bec31f90ba5d560d,
  10 transactions spending 12 P2PKH outputs;
  481824 = 0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893,
  the first block with segwit enforced, 1,866 transactions, 5,192 inputs;
  709632 = 0000000000000000000687bca986194dc2c1f949318629b44bb54ec0a94d8244,
  the first block with taproot enforced, 2,043 transactions, 6,630 inputs, none of
  them spending a P2TR output). Each hash is the `best_block_hash` the matching Raito
  fixture expects, and each file's header double-SHA-256es to it. File SHA-256:
  116928 3a9af22fc609a6cc28897ae7e8a410579c124f1ff386d27c341d9a0645fa2c20,
  481824 b3438263c8e86d0c3a391447784559fbd40f0908b61c60141f49bced8f63a3f6,
  709632 367c1748797cbaaa4519eeb51519db33a90ba611ff06e0710802e02075d813da.
- Coinbase witness reserved value: blocks 481824 and 709632 both use 32 zero bytes
  (block 116928 predates segwit and its coinbase has no witness), so on these blocks
  this crate's encoding of the block's own value and Raito's generator, which always
  writes zeros, give the same felts.
- `full_169.json`, `full_2015.json`, `full_116927.json`, `full_481823.json`,
  `full_709631.json`: copied from starkware-bitcoin/raito `packages/client/tests/data/`
  at 48c237ac941d8061a857ecd111d7e81107912556.
- `raito_felts_full_*.json`: `python -I scripts/data/format_args.py --input_file <fixture>`
  from the same Raito commit.
