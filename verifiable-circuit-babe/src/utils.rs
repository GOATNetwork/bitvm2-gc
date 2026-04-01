use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use ripemd::{Ripemd160, Digest as RipemdDigest};
use sha2::{Digest, Sha256};

pub fn groth16_vk_x(
    vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
    public_inputs: &[Fr],
) -> Option<ark_bn254::G1Projective> {
    if vk.gamma_abc_g1.len() != public_inputs.len() + 1 {
        return None;
    }
    let mut acc = vk.gamma_abc_g1[0].into_group();
    for (i, x) in public_inputs.iter().enumerate() {
        acc += vk.gamma_abc_g1[i + 1].into_group() * *x;
    }
    Some(acc)
}

pub fn g2_to_ser(p: ark_bn254::G2Projective) -> Vec<u8> {
    let mut out = Vec::new();
    p.into_affine().serialize_compressed(&mut out).expect("serialize g2");
    out
}

pub fn g1_to_ser(p: ark_bn254::G1Projective) -> Vec<u8> {
    let mut out = Vec::new();
    p.into_affine().serialize_compressed(&mut out).expect("serialize g1");
    out
}

pub fn g1_from_ser_checked(v: &[u8]) -> Option<ark_bn254::G1Projective> {
    let a = G1Affine::deserialize_compressed(v).ok()?;
    if a.is_zero() || !a.is_on_curve() || !a.is_in_correct_subgroup_assuming_on_curve() {
        return None;
    }
    Some(a.into_group())
}

pub fn g2_from_ser_checked(v: &[u8]) -> Option<ark_bn254::G2Projective> {
    let a = G2Affine::deserialize_compressed(v).ok()?;
    if a.is_zero() || !a.is_on_curve() || !a.is_in_correct_subgroup_assuming_on_curve() {
        return None;
    }
    Some(a.into_group())
}

pub fn pi1_to_bits(pi1: &G1Affine) -> Vec<bool> {
    use garbled_snark_verifier::dv_bn254::fq::Fq as GcFq;
    GcFq::to_bits(pi1.x).into_iter().chain(GcFq::to_bits(pi1.y)).collect()
}

pub fn ro_from_pairing_bytes(seed: &[u8], msg_len: usize) -> Vec<u8> {
    let key = h_256(seed);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&h_256(&[b"babe-we-known-pi1-ro-nonce".as_slice(), seed].concat())[..12]);
    derive_stream_xor_keyed(key, nonce, msg_len)
}

fn derive_stream_xor_keyed(key: [u8; 32], nonce: [u8; 12], msg_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; msg_len];
    let mut ctr: u32 = 0;
    let mut off = 0usize;
    while off < msg_len {
        let mut blk = b"babe-we-stream".to_vec();
        blk.extend_from_slice(&key);
        blk.extend_from_slice(&nonce);
        blk.extend_from_slice(&ctr.to_le_bytes());
        let hblk = h_256(&blk);
        let take = core::cmp::min(32, msg_len - off);
        out[off..off + take].copy_from_slice(&hblk[..take]);
        ctr += 1;
        off += take;
    }
    out
}

#[inline(always)]
/// SHA256
pub fn h_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// RIPEMD160
pub fn h_160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// h_msg = RIPEMD160(SHA256(data)) — the hashlock value.
pub fn derive_hashlock(secret: &[u8]) -> [u8; 20] {
    h_160(&h_256(&secret))
}
