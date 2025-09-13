//! GF(2^9) polynomial multiplication.
//! GF(2^233) polynomials are evaluated at points in GF(2^9).
//! These evaluations are then multiplied in pair.
//!
//! Module provides necessary functions for this multiplication.
use super::builder::{CircuitTrait, xor_many, xor_three, xor_vec};

pub(crate) const GF9_LEN: usize = 9;
pub(crate) type GF9 = [u32; GF9_LEN];

fn add_shifted<T: CircuitTrait>(b: &mut T, dst: &mut [Option<u32>], shift: usize, src: &[u32]) {
    for (i, &w) in src.iter().enumerate() {
        let idx = i + shift;
        dst[idx] = match dst[idx] {
            None => Some(w),
            Some(prev) => Some(b.xor_wire(prev, w)),
        };
    }
}

/* ──────────────────  GF(2⁹)  ·  squaring (XOR-only)  ─────────────────── */
/*
   Mapping derived from  (Σ aᵢ xⁱ)²  mod (x⁹ + x⁴ + 1):

       r₀ = a₀ ⊕ a₇
       r₁ = a₅
       r₂ = a₁ ⊕ a₈
       r₃ = a₆
       r₄ = a₂ ⊕ a₇
       r₅ = a₅ ⊕ a₇
       r₆ = a₃ ⊕ a₈
       r₇ = a₆ ⊕ a₈
       r₈ = a₄
*/
pub(crate) fn emit_gf9_square<T: CircuitTrait>(b: &mut T, a: GF9) -> GF9 {
    [
        b.xor_wire(a[0], a[7]), // r0
        a[5],                   // r1 (direct wire)
        b.xor_wire(a[1], a[8]), // r2
        a[6],                   // r3
        b.xor_wire(a[2], a[7]), // r4
        b.xor_wire(a[5], a[7]), // r5
        b.xor_wire(a[3], a[8]), // r6
        b.xor_wire(a[6], a[8]), // r7
        a[4],                   // r8
    ]
}

/* 17-bit → 9-bit reduction network */
fn reduce17_to9<T: CircuitTrait>(b: &mut T, p: [u32; 17]) -> GF9 {
    [
        xor_many(b, [p[0], p[9], p[14]]),         // r0
        xor_many(b, [p[1], p[10], p[15]]),        // r1
        xor_many(b, [p[2], p[11], p[16]]),        // r2
        xor_many(b, [p[3], p[12]]),               // r3
        xor_many(b, [p[4], p[9], p[13], p[14]]),  // r4
        xor_many(b, [p[5], p[10], p[14], p[15]]), // r5
        xor_many(b, [p[6], p[11], p[15], p[16]]), // r6
        xor_many(b, [p[7], p[12], p[16]]),        // r7
        xor_many(b, [p[8], p[13]]),               // r8
    ]
}

/* ─────────────── 3 × 3 carry-less multiply (6 AND) ──────────────── */
/*  inputs  a,b   : little-endian 3-bit limbs  [a0,a1,a2]             */
/*  output        : 5-bit product, little-endian                      */
fn m33<T: CircuitTrait>(b: &mut T, a: [u32; 3], c: [u32; 3]) -> [u32; 5] {
    /* --- non-linear core (six AND) ------------------------------------ */
    let m0 = b.and_wire(a[0], c[0]); // a0 & b0
    let m1 = b.and_wire(a[1], c[1]); // a1 & b1
    let m2 = b.and_wire(a[2], c[2]); // a2 & b2

    /* (a0⊕a1) & (b0⊕b1) */
    let a0_xor_a1 = b.xor_wire(a[0], a[1]);
    let b0_xor_b1 = b.xor_wire(c[0], c[1]);
    let m3 = b.and_wire(a0_xor_a1, b0_xor_b1);

    /* (a0⊕a2) & (b0⊕b2) */
    let a0_xor_a2 = b.xor_wire(a[0], a[2]);
    let b0_xor_b2 = b.xor_wire(c[0], c[2]);
    let m4 = b.and_wire(a0_xor_a2, b0_xor_b2);

    /* (a1⊕a2) & (b1⊕b2) */
    let a1_xor_a2 = b.xor_wire(a[1], a[2]);
    let b1_xor_b2 = b.xor_wire(c[1], c[2]);
    let m5 = b.and_wire(a1_xor_a2, b1_xor_b2);

    /* --- linear layer (XOR only) -------------------------------------- */
    // t1 = m3 ⊕ m0 ⊕ m1
    let t1 = xor_three(b, m3, m0, m1);
    // t2 = m4 ⊕ m0 ⊕ m1 ⊕ m2
    let tmp0 = b.xor_wire(m0, m1);
    let t2 = xor_three(b, m4, tmp0, m2);
    // t3 = m5 ⊕ m1 ⊕ m2
    let t3 = xor_three(b, m5, m1, m2);

    /* --- assemble 5-bit result  --------------------------------------- */
    [
        m0, // bit 0
        t1, // bit 1
        t2, // bit 2
        t3, // bit 3
        m2, // bit 4
    ]
}

/// 9-bit × 9-bit → 9-bit using 3-way Toom–Cook (~30 AND)
pub(crate) fn emit_gf9_mul<T: CircuitTrait>(bld: &mut T, a: GF9, c: GF9) -> GF9 {
    /* 1 · split into three 3-bit limbs */
    let (a0, a1, a2) = ([a[0], a[1], a[2]], [a[3], a[4], a[5]], [a[6], a[7], a[8]]);
    let (b0, b1, b2) = ([c[0], c[1], c[2]], [c[3], c[4], c[5]], [c[6], c[7], c[8]]);

    /* 2 · six 3×3 core products (each → 5 wires) */
    let m0 = m33(bld, a0, b0); // a0·b0
    let m1 = m33(bld, a1, b1); // a1·b1
    let m2 = m33(bld, a2, b2); // a2·b2

    /* build (a0⊕a1) and (b0⊕b1) first */
    let a0_plus_a1 =
        [bld.xor_wire(a0[0], a1[0]), bld.xor_wire(a0[1], a1[1]), bld.xor_wire(a0[2], a1[2])];
    let b0_plus_b1 =
        [bld.xor_wire(b0[0], b1[0]), bld.xor_wire(b0[1], b1[1]), bld.xor_wire(b0[2], b1[2])];
    let m3 = m33(bld, a0_plus_a1, b0_plus_b1); // (a0+a1)(b0+b1)

    let a0_plus_a2 =
        [bld.xor_wire(a0[0], a2[0]), bld.xor_wire(a0[1], a2[1]), bld.xor_wire(a0[2], a2[2])];
    let b0_plus_b2 =
        [bld.xor_wire(b0[0], b2[0]), bld.xor_wire(b0[1], b2[1]), bld.xor_wire(b0[2], b2[2])];
    let m4 = m33(bld, a0_plus_a2, b0_plus_b2); // (a0+a2)(b0+b2)

    let a1_plus_a2 =
        [bld.xor_wire(a1[0], a2[0]), bld.xor_wire(a1[1], a2[1]), bld.xor_wire(a1[2], a2[2])];
    let b1_plus_b2 =
        [bld.xor_wire(b1[0], b2[0]), bld.xor_wire(b1[1], b2[1]), bld.xor_wire(b1[2], b2[2])];
    let m5 = m33(bld, a1_plus_a2, b1_plus_b2); // (a1+a2)(b1+b2)

    /* 3 · Toom-Cook interpolation */
    let c0 = m0; // 5 bits
    let c4 = m2; // 5 bits
    let f0 = xor_vec(bld, &m3, &m0);
    let c1 = xor_vec(bld, &f0, &m1);
    let f1 = xor_vec(bld, &m4, &m0);
    let mut c2 = xor_vec(bld, &f1, &m1);
    c2 = xor_vec(bld, &c2, &m2);
    let f2 = xor_vec(bld, &m5, &m1);
    let c3 = xor_vec(bld, &f2, &m2);

    /* 4 · assemble 18-bit raw product */
    let mut tmp = [None; 17];
    add_shifted(bld, &mut tmp, 0, &c0); // c0
    add_shifted(bld, &mut tmp, 3, &c1); // c1 << 3
    add_shifted(bld, &mut tmp, 6, &c2); // c2 << 6
    add_shifted(bld, &mut tmp, 9, &c3); // c3 << 9
    add_shifted(bld, &mut tmp, 12, &c4); // c4 << 12

    let prod18: [u32; 17] = tmp.map(|x| x.unwrap());

    /* 5 · reduce modulo x⁹+x⁴+1 */
    reduce17_to9(bld, prod18)
}

// #[cfg(test)]
// mod test {
//     use super::*;
//
//     use crate::{builder::CktBuilder, gf9_ref::gf9ref_mul};
//
//     use rand::{Rng, SeedableRng, rngs::StdRng};
//
//     #[test]
//     fn random_pairs_agree_with_reference() {
//         let mut rng = StdRng::seed_from_u64(0xC0FFEE);
//
//         for _ in 0..1 {
//             let a: u16 = rng.r#gen::<u16>() & 0x1FF; // random 9-bit ints
//             let b: u16 = rng.r#gen::<u16>() & 0x1FF;
//
//             /* build one circuit instance */
//             let mut bld = CktBuilder::default();
//             let a_bits: [usize; 9] = bld.fresh();
//             let b_bits: [usize; 9] = bld.fresh();
//             let out_bits = emit_gf9_mul(&mut bld, a_bits, b_bits);
//             let out_bits_k = emit_gf9_mul(&mut bld, a_bits, b_bits);
//
//             /* prepare witness */
//             let mut witness = Vec::<bool>::with_capacity(18);
//             witness.extend((0..9).map(|i| (a >> i) & 1 != 0));
//             witness.extend((0..9).map(|i| (b >> i) & 1 != 0));
//
//             /* run the circuit */
//             let wires = bld.eval_gates(&witness);
//
//             /* read 9-bit hardware result */
//             let hw: u16 = out_bits
//                 .iter()
//                 .enumerate()
//                 .fold(0, |acc, (i, &w_id)| acc | ((wires[w_id] as u16) << i));
//             let chw: u16 = out_bits_k
//                 .iter()
//                 .enumerate()
//                 .fold(0, |acc, (i, &w_id)| acc | ((wires[w_id] as u16) << i));
//
//             let nhw = gf9ref_mul(a, b);
//             assert_eq!(hw, nhw, "Mismatch for a=0x{:03x}, b=0x{:03x}", a, b);
//             assert_eq!(chw, nhw, "Mismatches for a=0x{:03x}, b=0x{:03x}", a, b);
//         }
//     }
//
//     #[test]
//     fn random_pairs_agree_with_reference_for_square() {
//         let mut rng = StdRng::seed_from_u64(0xC0FFEE);
//
//         for _ in 0..1_000 {
//             let a: u16 = rng.r#gen::<u16>() & 0x1FF; // random 9-bit ints
//
//             /* build one circuit instance */
//             let mut bld = CktBuilder::default();
//             let a_bits: [usize; 9] = bld.fresh();
//             let out_bits = emit_gf9_square(&mut bld, a_bits);
//
//             /* prepare witness */
//             let mut witness = Vec::<bool>::with_capacity(18);
//             witness.extend((0..9).map(|i| (a >> i) & 1 != 0));
//
//             /* run the circuit */
//             let wires = bld.eval_gates(&witness);
//
//             /* read 9-bit hardware result */
//             let hw: u16 = out_bits
//                 .iter()
//                 .enumerate()
//                 .fold(0, |acc, (i, &w_id)| acc | ((wires[w_id] as u16) << i));
//
//             let nhw = gf9ref_mul(a, a);
//             assert_eq!(hw, nhw, "Mismatch for a=0x{:03x}, b=0x{:03x}", a, a);
//         }
//     }
// }
