use p3_field::{FieldAlgebra, PrimeField32};
use p3_koala_bear::KoalaBear;

pub fn bit_to_usize(bit: bool) -> usize {
    if bit { 1 } else { 0 }
}

pub fn poseidon2_hash(input: &[u8]) -> [u8; 32] {
    let koalabear_input =
        input.iter().map(|&b| KoalaBear::from_canonical_u8(b)).collect::<Vec<_>>();
    let hash = zkm_primitives::poseidon2_hash(koalabear_input);
    let mut output = [0u8; 32];
    for (i, x) in hash.iter().enumerate() {
        output[i * 4..(i + 1) * 4].copy_from_slice(&x.as_canonical_u32().to_le_bytes());
    }
    output
}
