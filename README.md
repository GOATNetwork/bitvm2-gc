# bitvm2-gc

This repository implements the bitvm2-gc construction, with both **Groth16 verifier** and **DV-SNARK
verifier**.

Commit Reference

The `garbled-snark-verifier` is modified
from [garbled-snark-verifier:5a2cd4](https://github.com/BitVM/garbled-snark-verifier/commit/5a2cd4dc6cb19e37adb1b3ab94414e01d1e8b338).

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

AES

```toml
default = ["aes"]
```

## Groth16 verifier

Run:

```shell
cd verifiable-circuit-host
cargo run -r
```

## DV-SNARK verifier

For the detailed bitvm2-gc with dv-snark scheme design, please refer to
the [BitVM2-GC with DV-SNARK](https://hackmd.io/@goatresearch/HkLx3FYigg).

Run:

```shell
cd verifiable-circuit-host
cargo run -r --bin dv-snark
```

## Benchmarks

Server configuration: 32 core, 480G RAM

| Program                           | Gates                                                                                 | Cycles           | Peak memory | Garbling(s) | Spliting(s)       | Single Execution(s) |
|-----------------------------------|---------------------------------------------------------------------------------------|------------------|-------------|-------------|-------------------|---------------------|
| deserialize_compressed_g2_circuit | and variants: 122185357, xor variants: 350864003, not: 550724, total:473600084        | 4268330910 * 68  | 51G         | 33s         | 480M/(IOPS) = 188 | 178                 |
| groth16_verifier_circuit          | and variants: 2718558275, xor variants: 7617087185, not: 62381441, total: 10398026901 |                  |             |             |                   |
| dv_snark                          | and variants: 11083481, xor variants: 2736913012, total: 2747996493                   | 297417996 * 2271 | 292G        | 80s         |                   |

Proving efficiency:  300k Poseidon2 hashes/s on a single RTX 4090 card.
