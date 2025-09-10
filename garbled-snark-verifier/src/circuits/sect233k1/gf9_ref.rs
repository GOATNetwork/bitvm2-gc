//! Module for non-circuit implementation of different functions over GF(2^9)
use super::gf9_ckt::GF9_LEN;

pub(crate) type Gf9Ref = u16;

/// Reference carry-less multiply in GF(2^9)
pub(crate) fn gf9ref_mul(mut a: Gf9Ref, mut b: Gf9Ref) -> Gf9Ref {
    const TOP: Gf9Ref = 1 << 9;
    const MOD: Gf9Ref = 0x211;
    let mut r: Gf9Ref = 0;
    a &= TOP - 1;
    b &= TOP - 1;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        b >>= 1;
        a <<= 1;
        if a & TOP != 0 {
            a ^= MOD;
        }
    }
    r & (TOP - 1)
}

/// Raise to power in F₂⁹ (mod x⁹+x⁴+1)
pub(crate) fn gf9ref_pow(mut a: Gf9Ref, mut e: u32) -> Gf9Ref {
    let mut r: Gf9Ref = 1;
    while e != 0 {
        if e & 1 != 0 {
            r = gf9ref_mul(r, a);
        }
        a = gf9ref_mul(a, a); // replace with square
        e >>= 1;
    }
    r
}

pub(crate) fn gf9ref_inv(a: Gf9Ref) -> Gf9Ref {
    gf9ref_pow(a, (1 << GF9_LEN) - 2)
}
