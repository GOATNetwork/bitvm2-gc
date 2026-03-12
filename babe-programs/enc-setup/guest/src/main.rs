// Guest program: proves enc_setup of the BABE verifier.
//
// Proves that ct_setup = (ct2, ct3) was correctly computed as:
//   ct2 = r · [delta]_2
//   rY  = e(alpha_g1, r·beta_g2) + e(vk_x, r·gamma_g2)   (additive GT notation)
//   ct3 = blake3(rY_bytes) ⊕ msg
//
// Public outputs committed:
//   ct2_bytes        – compressed G2 encoding of r·delta_g2
//   ct3              – 32-byte masked message
//   h_msg            – SHA-256(msg)   (hashlock)
//   h_vk             – SHA-256(raw VK bytes)
//   h_public_inputs  – SHA-256(raw public-input bytes)
#![no_std]
#![no_main]
extern crate alloc;

use alloc::vec::Vec;

zkm_zkvm::entrypoint!(main);

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

// ── Field / curve helpers ─────────────────────────────────────────────────────

fn fq_from_le(b: &[u8; 32]) -> Fq {
    Fq::from_le_bytes_mod_order(b)
}

fn fr_from_le(b: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(b)
}

/// Deserialize an uncompressed G1Affine from 64 raw LE bytes in a slice: x‖y.
fn g1_from_slice(b: &[u8]) -> G1Affine {
    assert_eq!(b.len(), 64);
    let x = fq_from_le(b[..32].try_into().unwrap());
    let y = fq_from_le(b[32..].try_into().unwrap());
    G1Affine::new_unchecked(x, y)
}

/// Deserialize an uncompressed G2Affine from 128 raw LE bytes: x.c0‖x.c1‖y.c0‖y.c1.
fn g2_from_slice(b: &[u8]) -> G2Affine {
    assert_eq!(b.len(), 128);
    let x_c0 = fq_from_le(b[0..32].try_into().unwrap());
    let x_c1 = fq_from_le(b[32..64].try_into().unwrap());
    let y_c0 = fq_from_le(b[64..96].try_into().unwrap());
    let y_c1 = fq_from_le(b[96..128].try_into().unwrap());
    G2Affine::new_unchecked(Fq2::new(x_c0, x_c1), Fq2::new(y_c0, y_c1))
}

/// Random-oracle: blake3 hash of bytes → 32-byte mask (matches verifiable_circuit_babe::babe::h).
fn h(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    // ── 1. Read private witnesses ─────────────────────────────────────────────
    let r_bytes = zkm_zkvm::io::read::<[u8; 32]>();
    let msg     = zkm_zkvm::io::read::<[u8; 32]>();

    // ── 2. Read VK components as flat byte vectors ────────────────────────────
    // G1Affine = 64 bytes (x ‖ y, each 32-byte Fq LE)
    // G2Affine = 128 bytes (x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1, each 32-byte Fq LE)
    let alpha_g1_raw  = zkm_zkvm::io::read_vec(); // 64 bytes
    let beta_g2_raw   = zkm_zkvm::io::read_vec(); // 128 bytes
    let gamma_g2_raw  = zkm_zkvm::io::read_vec(); // 128 bytes
    let delta_g2_raw  = zkm_zkvm::io::read_vec(); // 128 bytes
    // gamma_abc_g1: flat array, n_pts × 64 bytes
    let gamma_abc_raw = zkm_zkvm::io::read_vec(); // (n+1) * 64 bytes

    // ── 3. Read public inputs ─────────────────────────────────────────────────
    // Each Fr is 32 bytes LE; total = n_inputs × 32 bytes
    let public_inputs_raw = zkm_zkvm::io::read_vec(); // n * 32 bytes

    // ── 4. Reconstruct curve points and scalars ───────────────────────────────
    let r        = fr_from_le(&r_bytes);
    let alpha_g1 = g1_from_slice(&alpha_g1_raw);
    let beta_g2  = g2_from_slice(&beta_g2_raw);
    let gamma_g2 = g2_from_slice(&gamma_g2_raw);
    let delta_g2 = g2_from_slice(&delta_g2_raw);

    assert_eq!(gamma_abc_raw.len() % 64, 0);
    let n_abc = gamma_abc_raw.len() / 64;
    let gamma_abc_g1: Vec<G1Affine> = (0..n_abc)
        .map(|i| g1_from_slice(&gamma_abc_raw[i * 64..(i + 1) * 64]))
        .collect();

    assert_eq!(public_inputs_raw.len() % 32, 0);
    let n_inputs = public_inputs_raw.len() / 32;
    let public_inputs: Vec<Fr> = (0..n_inputs)
        .map(|i| fr_from_le(public_inputs_raw[i * 32..(i + 1) * 32].try_into().unwrap()))
        .collect();

    // ── 5. Compute vk_x = gamma_abc_g1[0] + Σ gamma_abc_g1[i+1] · inp[i] ────
    assert_eq!(gamma_abc_g1.len(), public_inputs.len() + 1);
    let mut vk_x = gamma_abc_g1[0].into_group();
    for (i, inp) in public_inputs.iter().enumerate() {
        vk_x += gamma_abc_g1[i + 1].into_group() * *inp;
    }

    // ── 6. Compute ct2 = r · delta_g2 (one G2 scalar mult, unavoidable) ──────
    let r_delta = (delta_g2.into_group() * r).into_affine();
    let mut ct2_bytes = Vec::new();
    r_delta.serialize_compressed(&mut ct2_bytes).unwrap();

    // ── 7. Compute rY via G1 scalar mults + one multi-pairing ────────────────
    //
    // By bilinearity: e(alpha, r·beta) = e(r·alpha, beta)
    //                 e(vk_x,  r·gamma) = e(r·vk_x,  gamma)
    //
    // This replaces 2 expensive G2 scalar mults (over Fq²) with 2 cheap G1
    // scalar mults (over Fq), and uses multi_pairing so the costly final
    // exponentiation is computed only once instead of twice.
    let g1_proj = [alpha_g1.into_group() * r, vk_x * r];
    // Batch-normalize: one shared field inversion instead of two.
    let g1_aff = G1Projective::normalize_batch(&g1_proj);
    let r_y = Bn254::multi_pairing(g1_aff, [beta_g2, gamma_g2]);

    // ── 8. Compute ct3 = blake3(rY) ⊕ msg ────────────────────────────────────
    let mut ry_bytes = Vec::new();
    r_y.serialize_compressed(&mut ry_bytes).unwrap();
    let mask = h(&ry_bytes);
    let ct3: [u8; 32] = core::array::from_fn(|i| msg[i] ^ mask[i]);

    // ── 9. Compute public commitments ─────────────────────────────────────────

    // h_msg = SHA-256(msg)  — hashlock value posted on Bitcoin
    let h_msg: [u8; 32] = Sha256::digest(&msg).into();

    // h_vk = SHA-256(all VK raw bytes in canonical order)
    let mut vk_hasher = Sha256::new();
    vk_hasher.update(&alpha_g1_raw);
    vk_hasher.update(&beta_g2_raw);
    vk_hasher.update(&gamma_g2_raw);
    vk_hasher.update(&delta_g2_raw);
    vk_hasher.update(&gamma_abc_raw);
    let h_vk: [u8; 32] = vk_hasher.finalize().into();

    // h_public_inputs = SHA-256(concatenated raw Fr bytes)
    let h_public_inputs: [u8; 32] = Sha256::digest(&public_inputs_raw).into();

    // ── 10. Commit public outputs ─────────────────────────────────────────────
    zkm_zkvm::io::commit::<Vec<u8>>(&ct2_bytes);
    zkm_zkvm::io::commit::<[u8; 32]>(&ct3);
    zkm_zkvm::io::commit::<[u8; 32]>(&h_msg);
    zkm_zkvm::io::commit::<[u8; 32]>(&h_vk);
    zkm_zkvm::io::commit::<[u8; 32]>(&h_public_inputs);
}