# bitvm2-gc



Commit Reference

The `garbled-snark-verifier` is modified from [garbled-snark-verifier:5a2cd4](https://github.com/BitVM/garbled-snark-verifier/commit/5a2cd4dc6cb19e37adb1b3ab94414e01d1e8b338).

**Benchmark Results**

| Hash Function        | Cycles        |
|----------------------|---------------|
| Blake3               | 4,015,285,370 |
| Poseidon2 Precompile | 3,314,475,262 |
| SHA2                 | 7,887,069,170 |
| SHA2 Precompile      | 3,832,397,090 |

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