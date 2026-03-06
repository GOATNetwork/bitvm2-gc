use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use ark_bn254::Fq;
use ark_ff::PrimeField;
use garbled_snark_verifier::bag::S;
use crate::gc::adaptor::Ct;

fn fq_to_bytes(fq: &Fq) -> [u8; 32] {
    let bigint = fq.into_bigint(); // BigInt<4> = [u64; 4], little-endian limbs
    let mut out = [0u8; 32];
    for (i, limb) in bigint.0.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

fn bytes_to_fq(bytes: &[u8; 32]) -> Fq {
    Fq::from_le_bytes_mod_order(bytes)
}


// --- AES-128 encrypt/decrypt for Fq (32 bytes = 2 blocks) ---
//
// Block 0 uses the key directly.
// Block 1 tweaks the key (XOR last byte with 0x01) to avoid encrypting
// two plaintext blocks under the identical key (standard ECB weakness).
// Todo: Use Ziren AES precompile
pub fn aes_enc(fq: &Fq, key: &S) -> Ct {
    let plain = fq_to_bytes(fq);

    let mut ct = [0u8; 32];

    let cipher0 = Aes128::new(GenericArray::from_slice(&key.0));
    let mut block0 = *GenericArray::from_slice(&plain[..16]);
    cipher0.encrypt_block(&mut block0);
    ct[..16].copy_from_slice(&block0);

    let mut key1 = *key;
    key1.0[15] ^= 0x01; // tweak for second block to avoid ECB weakness
    let cipher1 = Aes128::new(GenericArray::from_slice(&key1.0));
    let mut block1 = *GenericArray::from_slice(&plain[16..]);
    cipher1.encrypt_block(&mut block1);
    ct[16..].copy_from_slice(&block1);

    ct
}

// Todo: Use Ziren AES precompile
pub fn aes_dec(ct: &Ct, key: &S) -> Fq {
    let cipher0 = Aes128::new(GenericArray::from_slice(&key.0));
    let mut block0 = *GenericArray::from_slice(&ct[..16]);
    cipher0.decrypt_block(&mut block0);

    let mut key1 = *key;
    key1.0[15] ^= 0x01; // tweak for second block to avoid ECB weakness
    let cipher1 = Aes128::new(GenericArray::from_slice(&key1.0));
    let mut block1 = *GenericArray::from_slice(&ct[16..]);
    cipher1.decrypt_block(&mut block1);

    let mut plain = [0u8; 32];
    plain[..16].copy_from_slice(&block0);
    plain[16..].copy_from_slice(&block1);

    bytes_to_fq(&plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_aes_enc_dec() {
        let key = S([0u8; 16]);
        let fq = Fq::from(123456789u64);
        let ct = aes_enc(&fq, &key);
        let decrypted = aes_dec(&ct, &key);
        println!("Decrypted: {:?}", decrypted);
        assert_eq!(fq, decrypted, "AES encryption/decryption failed");
    }
}