#![no_std]
#![no_main]
extern crate alloc;

use alloc::vec::Vec;

zkm_zkvm::entrypoint!(main);

use ark_bn254::{Fq, G1Affine};
use ark_ff::PrimeField;
use sha2::{Digest, Sha256};
use verifiable_circuit_babe::dre::{L, N};
use verifiable_circuit_babe::gc::SparseAdaptorTable;

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

    let labels = zkm_zkvm::io::read::<Vec<[u8; 16]>>();
    assert_eq!(labels.len(), 2 * L);

    let r_bits = zkm_zkvm::io::read::<Vec<u8>>();
    assert_eq!(r_bits.len(), N);

    let rhos_flat = zkm_zkvm::io::read::<Vec<u8>>();
    assert_eq!(rhos_flat.len(), N * 64);
    let rhos: Vec<G1Affine> = rhos_flat
        .chunks_exact(64)
        .map(|c| bytes_to_g1affine(c.try_into().unwrap()))
        .collect();

    let deltas_raw = zkm_zkvm::io::read::<Vec<[u8; 32]>>();
    assert_eq!(deltas_raw.len(), N);
    let deltas: Vec<Fq> = deltas_raw.iter().map(reconstruct_fq).collect();

    // ── 2. Build and verify the sparse adaptor table inside zkVM ─────────────
    // s_k values are derived from PRF(label_1_k) — no s_all input needed.
    let table = SparseAdaptorTable::build_in_zkvm(&labels, &r_bits, &rhos, &deltas);

    // ── 3. Commit public outputs ──────────────────────────────────────────────

    // (a) r — SHA-256 over the N-bit representation
    let r_hash: [u8; 32] = Sha256::digest(&r_bits[..]).into();
    zkm_zkvm::io::commit::<[u8; 32]>(&r_hash);

    // (b) labels — SHA-256 over all 2*L raw label bytes
    let mut labels_hasher = Sha256::new();
    for b in &labels { labels_hasher.update(b); }
    let labels_hash: [u8; 32] = labels_hasher.finalize().into();
    zkm_zkvm::io::commit::<[u8; 32]>(&labels_hash);

    // (c) table — SHA-256 over all ciphertexts in deterministic order (i, {x,y,z}, k')
    let mut table_hasher = Sha256::new();
    for entry in &table.entries {
        for ct in &entry.x.cts { table_hasher.update(ct); }
        for ct in &entry.y.cts { table_hasher.update(ct); }
        for ct in &entry.z.cts { table_hasher.update(ct); }
    }
    let table_hash: [u8; 32] = table_hasher.finalize().into();
    zkm_zkvm::io::commit::<[u8; 32]>(&table_hash);
}