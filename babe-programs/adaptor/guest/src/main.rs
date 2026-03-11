#![no_std]
#![no_main]
extern crate alloc;

use alloc::vec::Vec;

zkm_zkvm::entrypoint!(main);

use ark_bn254::{Fq, G1Affine};
use ark_ff::PrimeField;
use sha2::{Digest, Sha256};
use verifiable_circuit_babe::dre::{L, N};
use verifiable_circuit_babe::gc::AdaptorTable;

fn reconstruct_fq(b: &[u8; 32]) -> Fq {
    Fq::from_le_bytes_mod_order(b)
}

fn bytes_to_g1affine(b: &[u8; 64]) -> G1Affine {
    let x = reconstruct_fq(b[..32].try_into().unwrap());
    let y = reconstruct_fq(b[32..].try_into().unwrap());
    G1Affine::new_unchecked(x, y)
}

fn main() {
    // ── 1. Read inputs from host ──────────────────────────────────────────────

    // labels: 2*L raw 16-byte S values, interleaved as [l0, l1, l0, l1, ...]
    let labels = zkm_zkvm::io::read::<Vec<[u8; 16]>>();
    assert_eq!(labels.len(), 2 * L);

    // r_bits: N bits (each byte is 0 or 1) — no Fr reconstruction needed
    let r_bits = zkm_zkvm::io::read::<Vec<u8>>();
    assert_eq!(r_bits.len(), N);

    // rhos: N G1Affine points as flat Vec<u8> of length N*64 (x ‖ y per point)
    let rhos_flat = zkm_zkvm::io::read::<Vec<u8>>();
    assert_eq!(rhos_flat.len(), N * 64);
    let rhos: Vec<G1Affine> = rhos_flat
        .chunks_exact(64)
        .map(|c| bytes_to_g1affine(c.try_into().unwrap()))
        .collect();
    
    // s_all: N × 3 × L Fq values, flat Vec<[u8; 32]> in (i, j, k) row-major order
    let s_flat = zkm_zkvm::io::read::<Vec<[u8; 32]>>();
    assert_eq!(s_flat.len(), N * 3 * L);
    let s_all: Vec<Vec<Vec<Fq>>> = (0..N)
        .map(|i| {
            (0..3)
                .map(|j| {
                    (0..L)
                        .map(|k| reconstruct_fq(&s_flat[i * 3 * L + j * L + k]))
                        .collect()
                })
                .collect()
        })
        .collect();
    
    // deltas: N Fq values, each [u8; 32]
    let deltas_raw = zkm_zkvm::io::read::<Vec<[u8; 32]>>();
    assert_eq!(deltas_raw.len(), N);
    let deltas: Vec<Fq> = deltas_raw.iter().map(reconstruct_fq).collect();
    
    // ── 2. Build and verify the adaptor table inside zkVM ────────────────────
    let table = AdaptorTable::build_in_zkvm(&labels, &r_bits, &rhos, &s_all, &deltas);
    
    // ── 3. Commit public outputs ──────────────────────────────────────────────
    //
    // Three values are committed so the verifier can bind the proof to specific
    // (r, labels, table) without seeing the private randomness (rhos, s_all, deltas).
    
    // (a) r — SHA-256 over the N-bit representation; no Fr reconstruction needed
    let r_hash: [u8; 32] = Sha256::digest(&r_bits[..]).into();
    zkm_zkvm::io::commit::<[u8; 32]>(&r_hash);
    
    // (b) labels — SHA-256 over all 2*L raw label bytes in order
    let mut labels_hasher = Sha256::new();
    for b in &labels {
        labels_hasher.update(b);
    }
    let labels_hash: [u8; 32] = labels_hasher.finalize().into();
    zkm_zkvm::io::commit::<[u8; 32]>(&labels_hash);
    
    // (c) table — SHA-256 over all ciphertexts in deterministic order (i, {x,y,z}, k)
    let mut table_hasher = Sha256::new();
    for entry in &table.entries {
        for ct_pair in &entry.x {
            table_hasher.update(ct_pair[0]);
            table_hasher.update(ct_pair[1]);
        }
        for ct_pair in &entry.y {
            table_hasher.update(ct_pair[0]);
            table_hasher.update(ct_pair[1]);
        }
        for ct_pair in &entry.z {
            table_hasher.update(ct_pair[0]);
            table_hasher.update(ct_pair[1]);
        }
    }
    let table_hash: [u8; 32] = table_hasher.finalize().into();
    zkm_zkvm::io::commit::<[u8; 32]>(&table_hash);
}
