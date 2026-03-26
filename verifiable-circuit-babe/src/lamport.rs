// ─── Lamport Signature Scheme ─────────────────────────────────────────────────

use ark_bn254::G1Affine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use crate::babe::{h, LAMPORT_N};
use crate::utils::pi1_to_bits;

/// Lamport signing key: LAMPORT_N pairs of 16-byte secrets.
/// Each secret has the same width as a GC input label.
#[derive(Debug, Clone)]
pub struct LamportSk(pub Vec<[[u8; 16]; 2]>);

/// Lamport verification key: pk[i][b] = SHA256(sk[i][b]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LamportPk(pub Vec<[[u8; 32]; 2]>);

/// Lamport signature: sig[i] = sk[i][bit_i(π₁)], for i in 0..LAMPORT_N.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LamportSig(pub Vec<[u8; 16]>);

pub fn lamport_keygen(rng: &mut impl RngCore) -> (LamportSk, LamportPk) {
    let mut sk_entries = Vec::with_capacity(LAMPORT_N);
    let mut pk_entries = Vec::with_capacity(LAMPORT_N);
    for _ in 0..LAMPORT_N {
        let mut s0 = [0u8; 16];
        let mut s1 = [0u8; 16];
        rng.fill_bytes(&mut s0);
        rng.fill_bytes(&mut s1);
        pk_entries.push([h(&s0), h(&s1)]);
        sk_entries.push([s0, s1]);
    }
    (LamportSk(sk_entries), LamportPk(pk_entries))
}

/// Sign π₁: reveal sk[i][bit_i(π₁)] for each bit.
pub fn lamport_sign(sk: &LamportSk, pi1: &G1Affine) -> LamportSig {
    let bits = pi1_to_bits(pi1);
    LamportSig(bits.iter().enumerate().map(|(i, &b)| sk.0[i][b as usize]).collect())
}

/// Verify a Lamport signature against lpk_P and π₁.
pub fn lamport_verify(pk: &LamportPk, pi1: &G1Affine, sig: &LamportSig) -> bool {
    if sig.0.len() != LAMPORT_N {
        return false;
    }
    let bits = pi1_to_bits(pi1);
    bits.iter().enumerate().all(|(i, &b)| h(&sig.0[i]) == pk.0[i][b as usize])
}
