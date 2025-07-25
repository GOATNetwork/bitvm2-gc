# bitvm2-gc



Commit Reference

The `garbled-snark-verifier` is modified from [garbled-snark-verifier:5a2cd4](https://github.com/BitVM/garbled-snark-verifier/commit/5a2cd4dc6cb19e37adb1b3ab94414e01d1e8b338).

To switch between hash functions in the guest program, modify the default feature in `verifiable-circuit/Cargo.toml`:

Blake3
```toml
default = ["blake3"]
```

Poseidon2
```toml
default = ["poseidon2"]
```

SHA2 Precompile
```toml
default = ["sha2"]
```

Then run:
```shell
cd verifiable-circuit-host
cargo run -r
```

## Benchmarks

|Program| gates | Cycles | Peak memory |
|---|---| ---|---|
| deserialize_compressed_g2_circuit | and variants:    122185357, xor variants: 350864003, not: 550724, total:473600084 | 11619308053 * 237  | 150G | 
| deserialize_compressed_g2_circuit | same as above | 5594647134 * 79 | ?? |
| deserialize_compressed_g2_circuit | same as above | 5594647134 * 68 | ?? |

Proving efficiency:  100M/mins on 5 GPU cards.