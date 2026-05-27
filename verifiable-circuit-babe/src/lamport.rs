// ─── Lamport Signature Scheme ─────────────────────────────────────────────────

use ark_bn254::G1Affine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use garbled_snark_verifier::bag::S;
use crate::utils::{derive_hashlock, pi1_to_bits};

/// Lamport signing key: LAMPORT_N pairs of 16-byte secrets.
/// Each secret has the same width as a GC input label.
#[derive(Debug, Clone)]
pub struct LamportSk(pub Vec<[[u8; 16]; 2]>);

/// Lamport verification key: pk[i][b] = RIPEMD160(SHA256((sk[i][b])).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LamportPk(pub Vec<[[u8; 20]; 2]>);

/// Lamport signature: sig[i] = sk[i][bit_i(π₁)], for i in 0..LAMPORT_N.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LamportSig(pub Vec<[u8; 16]>);

pub fn lamport_keygen(
    rng: &mut impl RngCore,
    size: usize,
) -> (LamportSk, LamportPk) {
    let mut sk_entries = Vec::with_capacity(size);
    let mut pk_entries = Vec::with_capacity(size);
    for _ in 0..size {
        let mut s0 = [0u8; 16];
        let mut s1 = [0u8; 16];
        rng.fill_bytes(&mut s0);
        rng.fill_bytes(&mut s1);
        pk_entries.push([derive_hashlock(&s0), derive_hashlock(&s1)]);
        sk_entries.push([s0, s1]);
    }
    (LamportSk(sk_entries), LamportPk(pk_entries))
}

/// Sign π₁: reveal sk[i][bit_i(π₁)] for each bit.
pub fn lamport_sign_g1_affine(sk: &LamportSk, pi1: &G1Affine) -> LamportSig {
    let bits = pi1_to_bits(pi1);
    assert!(bits.len() <= sk.0.len());
    LamportSig(bits.iter().enumerate().map(|(i, &b)| sk.0[i][b as usize]).collect())
}

/// Verify a Lamport signature against lpk_P and π₁.
pub fn lamport_verify_g1_affine(pk: &LamportPk, pi1: &G1Affine, sig: &LamportSig) -> bool {
    assert!(sig.0.len() <= pk.0.len());
    let bits = pi1_to_bits(pi1);
    bits.iter().enumerate().all(|(i, &b)| derive_hashlock(&sig.0[i]) == pk.0[i][b as usize])
}

pub fn compute_lamport_epk_with_delta(encoding_keys: &[S], delta: S) -> LamportPk {
    let pairs = encoding_keys.iter().map(|&key| [derive_hashlock(&key.0), derive_hashlock(&(key ^ delta).0)]).collect();
    LamportPk(pairs)
}

pub fn compute_lamport_epk(encoding_keys: &[S]) -> LamportPk {
    use garbled_snark_verifier::core::utils::NON_CAC_DELTA;
    compute_lamport_epk_with_delta(encoding_keys, NON_CAC_DELTA)
}
