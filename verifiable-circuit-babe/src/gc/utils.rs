use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use ark_bn254::Fq;
use ark_ff::PrimeField;
use garbled_snark_verifier::bag::S;
use crate::gc::adaptor::Ct;

#[cfg(all(target_os = "zkvm"))]
use zkm_zkvm::lib::aes128::aes128_encrypt;

fn fq_to_bytes(fq: &Fq) -> [u8; 32] {
    // [u64; 4] and [u8; 32] are identical in memory on little-endian (RISC-V is LE)
    unsafe { std::mem::transmute(fq.into_bigint().0) }
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
#[inline(always)]
pub fn aes_enc(fq: &Fq, key: &[u8; 16]) -> Ct {
    let plain = fq_to_bytes(fq);

    let mut ct = [0u8; 32];
    cfg_if::cfg_if! {
        if #[cfg(all(target_os = "zkvm"))] {
            // transmute is zero-cost: reinterprets [u8;32] as [[u8;16];2] with no copy or bounds check
            let mut blocks: [[u8; 16]; 2] = unsafe { std::mem::transmute(plain) };
            aes128_encrypt(&mut blocks[0], key);
            let mut key1 = *key;
            key1[15] ^= 0x01;
            aes128_encrypt(&mut blocks[1], &key1);
            return unsafe { std::mem::transmute(blocks) };
        }
    }

    let cipher0 = Aes128::new(GenericArray::from_slice(key));
    let mut block0 = *GenericArray::from_slice(&plain[..16]);
    cipher0.encrypt_block(&mut block0);
    ct[..16].copy_from_slice(&block0);

    let mut key1 = *key;
    key1[15] ^= 0x01; // tweak for second block to avoid ECB weakness
    let cipher1 = Aes128::new(GenericArray::from_slice(&key1));
    let mut block1 = *GenericArray::from_slice(&plain[16..]);
    cipher1.encrypt_block(&mut block1);
    ct[16..].copy_from_slice(&block1);

    ct
}

pub fn aes_dec(ct: &Ct, key: &[u8; 16]) -> Fq {
    let cipher0 = Aes128::new(GenericArray::from_slice(key));
    let mut block0 = *GenericArray::from_slice(&ct[..16]);
    cipher0.decrypt_block(&mut block0);

    let mut key1 = *key;
    key1[15] ^= 0x01; // tweak for second block to avoid ECB weakness
    let cipher1 = Aes128::new(GenericArray::from_slice(&key1));
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
        let key = [0u8; 16];
        let fq = Fq::from(123456789u64);
        let ct = aes_enc(&fq, &key);
        let decrypted = aes_dec(&ct, &key);
        println!("Decrypted: {:?}", decrypted);
        assert_eq!(fq, decrypted, "AES encryption/decryption failed");
    }
}