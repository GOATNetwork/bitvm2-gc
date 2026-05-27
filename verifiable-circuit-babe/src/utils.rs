#[cfg(not(target_os = "zkvm"))]
use ark_bn254::{Fr, G1Affine, G2Affine};
#[cfg(not(target_os = "zkvm"))]
use ark_ec::{AffineRepr, CurveGroup};
#[cfg(not(target_os = "zkvm"))]
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(not(target_os = "zkvm"))]
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use ripemd::{Ripemd160, Digest as RipemdDigest};
use sha2::{Digest, Sha256};
#[cfg(not(target_os = "zkvm"))]
use bitvm::signatures::{Wots, Wots64};

#[cfg(not(target_os = "zkvm"))]
pub type Wots64PublicKey = <Wots64 as Wots>::PublicKey;
#[cfg(not(target_os = "zkvm"))]
pub type Wots64Sig = <Wots64 as Wots>::Signature;

#[cfg(not(target_os = "zkvm"))]
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

#[cfg(not(target_os = "zkvm"))]
pub fn g2_to_ser(p: ark_bn254::G2Projective) -> Vec<u8> {
    let mut out = Vec::new();
    p.into_affine().serialize_compressed(&mut out).expect("serialize g2");
    out
}

#[cfg(not(target_os = "zkvm"))]
pub fn g1_to_ser(p: ark_bn254::G1Projective) -> Vec<u8> {
    let mut out = Vec::new();
    p.into_affine().serialize_compressed(&mut out).expect("serialize g1");
    out
}

#[cfg(not(target_os = "zkvm"))]
pub fn g1_from_ser_checked(v: &[u8]) -> Option<ark_bn254::G1Projective> {
    let a = G1Affine::deserialize_compressed(v).ok()?;
    if a.is_zero() || !a.is_on_curve() || !a.is_in_correct_subgroup_assuming_on_curve() {
        return None;
    }
    Some(a.into_group())
}

#[cfg(not(target_os = "zkvm"))]
pub fn g2_from_ser_checked(v: &[u8]) -> Option<ark_bn254::G2Projective> {
    let a = G2Affine::deserialize_compressed(v).ok()?;
    if a.is_zero() || !a.is_on_curve() || !a.is_in_correct_subgroup_assuming_on_curve() {
        return None;
    }
    Some(a.into_group())
}

#[cfg(not(target_os = "zkvm"))]
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



/// Encode pi1 into a 64-byte Wots64 message.
/// Layout: pi1.x LE-32 || pi1.y LE-32  (512 bits total, 508 used).
/// Padding: bits 254-255 of each 32-byte chunk are always 0 (BN254 Fq < 2^254).
#[cfg(not(target_os = "zkvm"))]
pub fn pi1_to_wots64_msg(pi1: &G1Affine) -> [u8; 64] {
    let mut msg = [0u8; 64];
    let mut tmp = Vec::new();

    pi1.x.serialize_uncompressed(&mut tmp).expect("serialize pi1.x");
    msg[..32].copy_from_slice(&tmp);

    tmp.clear();
    pi1.y.serialize_uncompressed(&mut tmp).expect("serialize pi1.y");
    msg[32..64].copy_from_slice(&tmp);

    msg
}

/// Verify a Wots64 signature against a public key and message.
///
/// For each digit position `i`, hashes `sig[i][..20]` exactly `(max_digit - d_i)` more
/// times and compares against `pk[i]`. Digits are derived independently from `msg`
/// (not trusted from the signature), matching `Wots64::sign` internals:
///   - LOG2_BASE = 4 → each byte encodes two nibbles
///   - digit order: bytes reversed, each byte split as [high_nibble, low_nibble]
///   - checksum appended MSD-first (big-endian base-16, matching checksum_to_digits)
#[cfg(not(target_os = "zkvm"))]
pub fn wots64_verify(pk: &Wots64PublicKey, msg: &[u8; 64], sig: &Wots64Sig) -> bool {
    use bitcoin::hashes::{hash160, Hash};

    const BASE: usize = 1 << 4;        // LOG2_BASE = 4 → base 16
    const MAX_DIGIT: usize = BASE - 1;  // 15
    let msg_digit_len = (Wots64::MSG_BYTE_LEN as usize) * 2; // 64 bytes × 2 nibbles = 128
    let total_digit_len = Wots64::TOTAL_DIGIT_LEN as usize;  // 131
    let chk_digit_len = total_digit_len - msg_digit_len;      // 3

    // message digits: bytes in reverse order, each split into [high_nibble, low_nibble]
    // matches output of message_to_digits(512, 4, msg) after its internal .reverse()
    let mut digits: Vec<usize> = msg
        .iter()
        .rev()
        .flat_map(|&b| [((b >> 4) & 0x0f) as usize, (b & 0x0f) as usize])
        .collect();

    // checksum encoded big-endian (MSD first), matching checksum_to_digits in utils.rs
    let checksum = MAX_DIGIT * msg_digit_len - digits.iter().sum::<usize>();
    let mut chk = checksum;
    let mut chk_digits = vec![0usize; chk_digit_len];
    for d in chk_digits.iter_mut().rev() {
        *d = chk % BASE;
        chk /= BASE;
    }
    digits.extend(chk_digits);

    // for each position i verify: hash_chain(sig[i], max_digit - d_i) == pk[i]
    for i in 0..total_digit_len {
        let d_i = digits[i];
        let mut h = hash160::Hash::from_byte_array(sig[i][..20].try_into().unwrap());
        for _ in 0..(MAX_DIGIT - d_i) {
            h = hash160::Hash::hash(h.as_byte_array());
        }
        if h.as_byte_array() != &pk[i] {
            return false;
        }
    }
    true
}

#[cfg(all(test, not(target_os = "zkvm")))]
mod tests {
    use super::*;
    use bitvm::signatures::WinternitzSecret;

    #[test]
    fn wots64_verify_roundtrip() {
        // deterministic secret (WinternitzSecret = Vec<u8> in bitvm::signatures)
        let secret = Wots64::generate_secret_key();
        let pk = Wots64::generate_public_key(&secret);
        let msg = [0x5au8; 64];
        let sig = Wots64::sign(&secret, &msg);

        assert!(wots64_verify(&pk, &msg, &sig), "valid sig must verify");

        // flipping one bit in the message must break verification
        let mut wrong_msg = msg;
        wrong_msg[0] ^= 0x01;
        assert!(!wots64_verify(&pk, &wrong_msg, &sig), "sig must not verify against a different message");
    }
}
