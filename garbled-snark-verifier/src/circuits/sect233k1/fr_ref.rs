use num_bigint::BigUint;

use super::fr_ckt::FR_LEN;

pub(crate) type FrRef = BigUint;

pub fn frref_to_bits(n: &FrRef) -> [bool; FR_LEN] {
    let bytes = n.to_bytes_le();
    let mut bits = [false; FR_LEN];
    for i in 0..FR_LEN {
        let byte = if i / 8 < bytes.len() { bytes[i / 8] } else { 0 };
        let r = (byte >> (i % 8)) & 1;
        bits[i] = r != 0;
    }
    bits
}
