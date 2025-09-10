//! Basic base field element operations in binary circuit
pub(crate) const GF_LEN: usize = 233;
/// Representation of a base field element as wire labels
pub(crate) type Gf = [usize; GF_LEN];

use super::{builder::CircuitTrait, curve_ckt::CompressedCurvePoint, gf_mul_ckt::emit_gf_mul};

/* Input  : two 233-wire operands, little-endian bit order          */
/* Output : 233 wires, bit-wise XOR                                 */
pub(crate) fn emit_gf_add<T: CircuitTrait>(b: &mut T, a: &Gf, c: &Gf) -> Gf {
    let v: Vec<usize> = (0..GF_LEN).map(|i| b.xor_wire(a[i], c[i])).collect();
    v.try_into().unwrap()
}

pub(crate) fn emit_gf_trace<T: CircuitTrait>(bld: &mut T, a: &Gf) -> usize {
    let mut acc = *a;
    let mut t = *a;
    for _ in 1..GF_LEN {
        t = emit_gf_square(bld, &t);
        acc = emit_gf_add(bld, &acc, &t);
    }
    acc[0]
}

pub(crate) fn emit_gf_halftrace<T: CircuitTrait>(bld: &mut T, a: &Gf) -> Gf {
    const ROUNDS: usize = (GF_LEN - 1) / 2; // 116 for m=233
    let mut acc = [bld.zero(); GF_LEN];
    let mut t = *a;
    for _ in 0..=ROUNDS {
        acc = emit_gf_add(bld, &acc, &t); // acc ^= t
        t = emit_gf_square(bld, &t);
        t = emit_gf_square(bld, &t); // t = t^{2²}
    }
    acc
}

pub(crate) fn emit_gf_inv<T: CircuitTrait>(bld: &mut T, a: Gf) -> Gf {
    let y = emit_gf_square(bld, &a); // a^2
    let x = emit_gf_mul(bld, &y, &a); // a^3

    let y = emit_gf_square(bld, &x); // a^6
    let x = emit_gf_mul(bld, &y, &a); // a^7

    let y = {
        let mut base = x;
        let n = 3;
        for _ in 0..n {
            base = emit_gf_square(bld, &base)
        }
        base
    }; // a^56
    let x = emit_gf_mul(bld, &y, &x); // a^(56+7)=a^63

    let y = emit_gf_square(bld, &x); // a^126
    let x = emit_gf_mul(bld, &y, &a); // a^127

    let y = {
        let mut base = x;
        let n = 7;
        for _ in 0..n {
            base = emit_gf_square(bld, &base)
        }
        base
    }; // a^(127 * 2^7)
    let x = emit_gf_mul(bld, &y, &x); // a^(2^14 -1)

    let y = {
        let mut base = x;
        let n = 14;
        for _ in 0..n {
            base = emit_gf_square(bld, &base)
        }
        base
    }; // a^(2^28 - 2^14)
    let x = emit_gf_mul(bld, &y, &x); // a^(2^28 -1)

    let y = emit_gf_square(bld, &x); // a^(2^28 -1)
    let x = emit_gf_mul(bld, &y, &a); // a^(2^29 -1)

    let y = {
        let mut base = x;
        let n = 29;
        for _ in 0..n {
            base = emit_gf_square(bld, &base)
        }
        base
    }; // a^(2^58 - 2^29)
    let x = emit_gf_mul(bld, &y, &x); // a^(2^58 -1)

    let y = {
        let mut base = x;
        let n = 58;
        for _ in 0..n {
            base = emit_gf_square(bld, &base)
        }
        base
    }; // a^(2^116 - 2^58)
    let x = emit_gf_mul(bld, &y, &x); // a^(2^116 -1)

    let y = {
        let mut base = x;
        let n = 116;
        for _ in 0..n {
            base = emit_gf_square(bld, &base);
        }
        base
    }; // a^(2^232 - 2^116)
    let x = emit_gf_mul(bld, &y, &x); // a^(2^232 -1)

    // a^(2^232 -2)

    emit_gf_square(bld, &x)
}

/// Decode base field element and a label that indicates where the field element was valid
// validity is checked by ensuring bits greater than equal array index - GF_LEN(233) has not been set
pub(crate) fn emit_gf_decode<T: CircuitTrait>(
    bld: &mut T,
    src: &CompressedCurvePoint,
) -> (Gf, usize) {
    // ---- 1. Copy into a 32-byte buffer (matching the original memset). ----
    let mut buf = [[bld.zero(); 8]; 32];
    buf[..30].copy_from_slice(src);

    // Build the BigUint from little-endian bytes.
    let dst: Gf = {
        let tmp = buf.as_flattened();
        tmp[0..GF_LEN].try_into().unwrap()
    };

    let last = src[29];

    let valid = {
        let mut tmp = last[1];
        for last_i in last.iter().skip(2) {
            tmp = bld.or_wire(tmp, *last_i);
        }
        let one = bld.one();

        bld.xor_wire(tmp, one)
    };
    (dst, valid)
}

/// interleave zeros:  b_k = a_{k/2}  if k even, else 0
fn square_spread<T: CircuitTrait>(b: &mut T, a: &Gf) -> [usize; GF_LEN * 2] {
    let z = b.zero();
    let mut h = [z; 466]; // 0…465
    for i in 0..GF_LEN {
        h[2 * i] = a[i]; // copy to even positions
    }
    h
}

/// full squaring gadget
pub(crate) fn emit_gf_square<T: CircuitTrait>(b: &mut T, a: &Gf) -> Gf {
    /* Step-1: spread (aᵢ → bit 2·i) */
    let mut h = square_spread(b, a);

    /* Step-2: modular reduction  (exactly the scalar reduce_466) */
    for i in (233..466).rev() {
        let bit_i = h[i];
        /* clear bit_i in place is unnecessary – we never read it again */

        /* fold into i-233  */
        let d1 = b.xor_wire(h[i - 233], bit_i);
        h[i - 233] = d1;

        /* fold into (i-233)+74 = i-159 */
        let d2 = b.xor_wire(h[i - 159], bit_i);
        h[i - 159] = d2;
    }

    /* Step-3: first 233 wires are the reduced square */
    let mut out = [b.zero(); GF_LEN];
    out.copy_from_slice(&h[..GF_LEN]);
    out
}

/// Check if a base field elemnt is zero
pub(crate) fn emit_gf_is_zero<T: CircuitTrait>(bld: &mut T, w: Gf) -> usize {
    let mut acc = bld.zero();
    for x in w {
        acc = bld.or_wire(acc, x);
    }
    let one = bld.one();

    bld.xor_wire(acc, one)
}

// #[cfg(test)]
// mod test {
//     use std::os::raw::c_void;
//
//     use super::*;
//     use crate::builder::CktBuilder;
//     use crate::curve_ckt::COMPRESSED_POINT_LEN;
//     use crate::gf_ref::{GfRef, gfref_mul};
//     use num_traits::FromPrimitive;
//     use num_traits::One;
//     use xs233_sys::xsk233_generator;
//
//     /// Reverse of `to_u64_digits()`:
//     ///   Vec<u64> little-endian → BigUint
//     fn gf_from_u64_digits(digits: Vec<u64>) -> GfRef {
//         // radix = 2^64
//         let radix: GfRef = GfRef::one() << 64;
//         // fold from most-significant limb to least
//         digits.into_iter().rev().fold(GfRef::ZERO, |acc, limb| {
//             // BigUint::from_u64 returns Option, but limb < 2^64 always fits.
//             (acc * &radix) + GfRef::from_u64(limb).unwrap()
//         })
//     }
//
//     #[test]
//     fn test_gf233_square_random() {
//         use rand::{Rng, SeedableRng, rngs::StdRng};
//         let mut rng = StdRng::seed_from_u64(0xD1CE_FADE);
//
//         for _ in 0..500 {
//             /* --- random 233-bit element -------------------------------- */
//             let mut words = [0u64; 4];
//             words[0] = rng.r#gen();
//             words[1] = rng.r#gen();
//             words[2] = rng.r#gen();
//             words[3] = rng.r#gen::<u64>() & ((1u64 << 41) - 1); // top 41 bits
//             let a_big = gf_from_u64_digits(words.to_vec());
//             // let a_bits: GF = {
//             //     let mut v = [0usize; 233];
//             //     for i in 0..233 {
//             //         let w = (words[i >> 6] >> (i & 63)) & 1;
//             //         v[i] = if w == 1 { 1 } else { 0 }; // placeholder; overwritten below
//             //     }
//             //     v
//             // };
//
//             /* --- build circuit ----------------------------------------- */
//             let mut bld = CktBuilder::default();
//             let mut in_bits = [0usize; 233];
//             let mut witness = Vec::<bool>::with_capacity(233);
//             for i in 0..233 {
//                 in_bits[i] = bld.fresh_one();
//                 witness.push(((words[i >> 6] >> (i & 63)) & 1) == 1);
//             }
//             let out_bits = emit_gf_square(&mut bld, &in_bits);
//
//             let wires = bld.eval_gates(&witness);
//
//             /* --- collect hardware result ------------------------------- */
//             let mut r_words = [0u64; 4];
//             for i in 0..233 {
//                 if wires[out_bits[i]] {
//                     r_words[i >> 6] |= 1u64 << (i & 63);
//                 }
//             }
//             let hw = gf_from_u64_digits(r_words.to_vec());
//
//             /* --- reference --------------------------------------------- */
//             let sw = gfref_mul(&a_big, &a_big);
//             assert_eq!(hw, sw, "square mismatch for random a");
//         }
//     }
//
//     #[test]
//     fn test_emit_gf_decode() {
//         let mut bld = CktBuilder::default();
//
//         let src = {
//             let mut bytes = Vec::new();
//             for _ in 0..COMPRESSED_POINT_LEN {
//                 let byte: [usize; 8] = bld.fresh();
//                 bytes.push(byte);
//             }
//             let bytes: CompressedCurvePoint = bytes.try_into().unwrap();
//             bytes
//         };
//
//         let (_, valid_label) = emit_gf_decode(&mut bld, &src);
//
//         // witness
//         let mut witness = {
//             unsafe {
//                 let pt = xsk233_generator;
//                 let mut dst = [0u8; COMPRESSED_POINT_LEN];
//                 xs233_sys::xsk233_encode(dst.as_mut_ptr() as *mut c_void, &pt);
//                 let mut wit = Vec::new();
//                 for d in dst {
//                     let mut vs: Vec<bool> = (0..8).map(|i| (d >> i) & 1 != 0).collect();
//                     wit.append(&mut vs);
//                 }
//                 wit
//             }
//         };
//         let wires = bld.eval_gates(&witness);
//         let valid = wires[valid_label];
//         assert!(valid);
//
//         // bit higher than 233 if set is not a valid field element as it is not within bounds
//         // in such cases, `valid_label` emits false
//         witness[GF_LEN] = true;
//         let wires = bld.eval_gates(&witness);
//         let valid = wires[valid_label];
//         assert!(!valid);
//     }
// }
