//! Reference implementation of different functions in base field to compare and test
//! circuit implementation of similar base field functions

#![cfg(test)]
use num_bigint::BigUint;
use num_traits::{One, Zero};

use super::gf_ckt::GF_LEN;

/// A field element in F₂²³³ represented as 4 × 64‐bit limbs (only 233 bits used).
pub(crate) type GfRef = BigUint;

// Returns the multiplicative identity (one element) of the field.
pub(crate) fn gfref_one() -> GfRef {
    BigUint::one()
}

pub(crate) fn gfref_add(a: &GfRef, b: &GfRef) -> GfRef {
    // For binary fields, addition is just XOR of corresponding limbs
    a ^ b
}

pub(crate) fn gfref_square(a: &GfRef) -> GfRef {
    gfref_mul(a, a)
}

/// Multiply two field elements: c = a * b mod (x^233 + x^74 + 1)
/// Direct GF(2) polynomial multiply+reduce for testing
/// Binary Circuit Version is fft_mul继续
pub(crate) fn gfref_mul(a: &GfRef, b: &GfRef) -> GfRef {
    let a = gfref_to_bits(a);
    let b = gfref_to_bits(b);

    const GF_POLYMUL_LEN: usize = GF_LEN * 2 - 1;
    let mut prod = vec![0u8; GF_POLYMUL_LEN];
    for i in 0..233 {
        if a[i] {
            for j in 0..233 {
                if b[j] {
                    prod[i + j] ^= 1;
                }
            }
        }
    }
    // reduce x^233 + x^74 + 1
    for i in (233..GF_POLYMUL_LEN).rev() {
        if prod[i] != 0 {
            prod[i] ^= 1;
            prod[i - 233] ^= 1;
            prod[i - 159] ^= 1;
        }
    }
    let mut out = [0u8; GF_LEN];
    out.copy_from_slice(&prod[..GF_LEN]);

    let out = out.map(|x| x != 0);

    bits_to_gfref(&out)
}

/// Convert BigUint → fixed-size 233-bit array (LSB at index 0)
pub(crate) fn gfref_to_bits(n: &BigUint) -> [bool; 233] {
    let bytes = n.to_bytes_le();
    let mut bits = [false; 233];
    for i in 0..233 {
        let byte = if i / 8 < bytes.len() { bytes[i / 8] } else { 0 };
        let r = (byte >> (i % 8)) & 1;
        bits[i] = r != 0;
    }
    bits
}

/// Convert 233-bit array → BigUint (LSB at index 0)
pub(crate) fn bits_to_gfref(bits: &[bool; 233]) -> GfRef {
    let mut n = BigUint::zero();
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            n |= BigUint::one() << i;
        }
    }
    n
}
