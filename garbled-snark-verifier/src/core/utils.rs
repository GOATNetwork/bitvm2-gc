pub fn bit_to_usize(bit: bool) -> usize {
    if bit { 1 } else { 0 }
}

pub fn hash(input: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];

    #[cfg(feature = "std")]
    {
        use blake3::hash;
        output = *hash(input).as_bytes();
    }

    #[cfg(feature = "sha2")]
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();
        output.copy_from_slice(&result[..32]);
    }

    #[cfg(all(not(feature = "std"), not(feature = "sha2")))]
    {
        use p3_field::{FieldAlgebra, PrimeField32};
        use p3_koala_bear::KoalaBear;
        let koalabear_input =
            input.iter().map(|&b| KoalaBear::from_canonical_u8(b)).collect::<Vec<_>>();
        let hash = zkm_primitives::poseidon2_hash(koalabear_input);
        for (i, x) in hash.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&x.as_canonical_u32().to_le_bytes());
        }
    }
    output
}
