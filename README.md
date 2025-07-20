# bitvm2-gc



Commit Reference

`garbled-snark-verifier` commit: `5a2cd4dc6cb19e37adb1b3ab94414e01d1e8b338`

**Benchmark Results**

| Hash Function   | Cycles         |
| --------------- |----------------|
| Blake3          | 4,015,285,370  |
| Poseidon2       | 10,294,024,826 |
| SHA2            | 7,887,069,170  |
| SHA2 Precompile | 3,832,397,090  |

To switch between hash functions in `verifiable-circuit/Cargo.toml`, modify the feature list for garbled-snark-verifier:

Poseidon2
```toml
garbled-snark-verifier = { workspace = true, features = ["garbled"] }
```

SHA2 Precompile
```toml
garbled-snark-verifier = { workspace = true, features = ["sha2"] }
```

Then run:
```shell
cd verifiable-circuit-host
cargo run -r
```