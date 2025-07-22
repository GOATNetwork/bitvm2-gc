pub fn bit_to_usize(bit: bool) -> usize {
    if bit { 1 } else { 0 }
}

pub fn hash(input: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];

    #[cfg(feature = "_blake3")]
    {
        use blake3::hash;
        output = *hash(input).as_bytes();
    }

    #[cfg(feature = "_sha2")]
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();
        output.copy_from_slice(&result[..32]);
    }

    #[cfg(feature = "_poseidon2")]
    {
        use zkm_zkvm::lib::poseidon2::poseidon2;
        output = poseidon2(input);
    }
    output
}
