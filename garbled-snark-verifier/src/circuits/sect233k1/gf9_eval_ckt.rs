//! Module to evaluate polynomial in GF(2^233) at sample points in GF(2^9)

use super::{
    builder::CircuitTrait,
    gf_ckt::Gf,
    gf9_ckt::{GF9, GF9_LEN},
    gf9_ref::Gf9Ref,
};

/* bits are numbered a₀ (LSB) … a₈ (MSB)                                           */
fn matrix_multiply(a: [[u8; 9]; 9], b: [[u8; 9]; 9]) -> [[u8; 9]; 9] {
    // Initialize a new 9x9 result matrix with all zeros.
    let mut result = [[0u8; 9]; 9];

    // Iterate over each row of the first matrix 'a'.
    for i in 0..9 {
        // Iterate over each column of the second matrix 'b'.
        for j in 0..9 {
            // Calculate the dot product of row `i` of `a` and column `j` of `b`.
            let mut dot_product = 0;
            for (k, b_k) in b.iter().enumerate() {
                // The element of the resulting matrix is the sum (XOR)
                // of the products (AND) of the corresponding row and column elements.
                dot_product ^= a[i][k] * b_k[j];
            }
            result[i][j] = dot_product;
        }
    }

    result
}

// This logic would be executed at compile time (e.g., in a build.rs script or a procedural macro)
fn compute_transformation_matrix(const_c: Gf9Ref) -> [[u8; 9]; 9] {
    // Represents the linear transformation for multiplication by 'x' in the Galois Field.
    // This is a constant matrix derived from the xtime_bits function logic.
    let t_x: [[u8; 9]; 9] = [
        // Input vector v:
        // v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8]
        //-----------------------------------------------------------
        [0, 0, 0, 0, 0, 0, 0, 0, 1], // new_v[0] = v[8]
        [1, 0, 0, 0, 0, 0, 0, 0, 0], // new_v[1] = v[0]
        [0, 1, 0, 0, 0, 0, 0, 0, 0], // new_v[2] = v[1]
        [0, 0, 1, 0, 0, 0, 0, 0, 0], // new_v[3] = v[2]
        [0, 0, 0, 1, 0, 0, 0, 0, 1], // new_v[4] = v[3] XOR v[8]
        [0, 0, 0, 0, 1, 0, 0, 0, 0], // new_v[5] = v[4]
        [0, 0, 0, 0, 0, 1, 0, 0, 0], // new_v[6] = v[5]
        [0, 0, 0, 0, 0, 0, 1, 0, 0], // new_v[7] = v[6]
        [0, 0, 0, 0, 0, 0, 0, 1, 0], // new_v[8] = v[7]
    ];
    let mut acc_matrix = [[0; 9]; 9];
    // Represents the current multiplicand's transformation.
    // Starts as the identity matrix because initially, cur = word_bits (the input).
    let mut cur_matrix: [[u8; 9]; 9] = [
        [1, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 1, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 1],
    ];

    for i in 0..9 {
        if (const_c >> i) & 1 == 1 {
            // acc_matrix = acc_matrix XOR cur_matrix
            for r in 0..9 {
                for c in 0..9 {
                    acc_matrix[r][c] ^= cur_matrix[r][c];
                }
            }
        }
        // cur_matrix = T_x * cur_matrix
        cur_matrix = matrix_multiply(t_x, cur_matrix);
    }
    acc_matrix
}

// The function that builds the actual circuit
pub(crate) fn emit_mul_by_const<T: CircuitTrait>(
    b: &mut T,
    word_bits: GF9, /* secret  a */
    const_c: Gf9Ref, /* PUBLIC  C */
) -> GF9 {
    // This matrix M is pre-computed and stored as a constant
    let m = compute_transformation_matrix(const_c);

    let mut acc = [0; GF9_LEN];

    for r in 0..9 {
        // For each output bit
        let mut terms_to_xor = Vec::new();
        for (c, word_bits_c) in word_bits.iter().enumerate() {
            // Check which input bits contribute
            if m[r][c] == 1 {
                terms_to_xor.push(*word_bits_c);
            }
        }

        // Build a single (potentially large) XOR gate from the collected terms
        if terms_to_xor.is_empty() {
            acc[r] = b.zero();
        } else {
            // xor_many would be a helper to build an efficient XOR tree
            acc[r] = xor_many(b, &terms_to_xor);
        }
    }
    acc
}

// Helper to build an XOR tree
fn xor_many<T: CircuitTrait>(b: &mut T, wires: &[u32]) -> u32 {
    if wires.len() == 1 {
        return wires[0];
    }
    let mut res = wires[0];
    for &wire in &wires[1..] {
        res = b.xor_wire(res, wire);
    }
    res
}

/* ──────────────────  GF(2⁹)  ·  Horner evaluation  ──────────────────── */
/* Every coefficient bit is ONE secret wire (0/1).  Sample points are     */
/* PUBLIC 9-bit constants.  Result for each point is 9 secret wires.      */

/* 9 zero-wires helper --------------------------------------------------- */
fn zero_9<T: CircuitTrait>(b: &mut T) -> GF9 {
    let z = b.zero();
    [z; 9]
}

/* Horner evaluation for ONE public sample point ------------------------ */
fn emit_poly_eval_fixed<T: CircuitTrait>(
    b: &mut T,
    coeff_bits: &Gf, /* secret coeffs, bit-LSB order  a₀…a₂₃₂ */
    sample_const: Gf9Ref, /* PUBLIC sample point           ( <512 )*/
) -> GF9 {
    /* acc starts at 0 */
    let mut acc = zero_9(b);

    /* iterate highest degree → lowest (reverse order) */
    for &bit_wire in coeff_bits.iter().rev() {
        /* acc ← acc · sample_const     (XOR-only network) */
        acc = emit_mul_by_const(b, acc, sample_const);

        /* acc ← acc ⊕ bit             (bit goes to LSB) */
        acc[0] = b.xor_wire(acc[0], bit_wire);
    }
    acc
}

/* Evaluate over an entire PUBLIC domain -------------------------------- */
pub(crate) fn emit_poly_eval_domain<T: CircuitTrait>(
    b: &mut T,
    coeff_bits: &Gf,
    domain: &[Gf9Ref], /* list of sample points         */
) -> Vec<GF9> {
    domain.iter().map(|&alpha| emit_poly_eval_fixed(b, coeff_bits, alpha)).collect()
}

// #[cfg(test)]
// mod test {
//     use rand::{Rng, SeedableRng, rngs::StdRng};
//
//     use crate::{builder::CktBuilder, gf_ckt::Gf, gf9_ref::gf9ref_mul};
//
//     /// Reference Function: Evaluate a 233-bit polynomial (bit vector) at all x in `xs`
//     pub(crate) fn ref_evaluate_poly_at_fixed_gf9(
//         polynom: &[u8; 233],
//         domain: &[Gf9Ref],
//     ) -> Vec<Gf9Ref> {
//         use crate::gf9_ref::gf9ref_mul;
//
//         let mut evals = Vec::with_capacity(domain.len());
//         for &sample_pt in domain {
//             let mut acc: u16 = 0;
//             let mut xp: u16 = 1;
//             for &bit in polynom.iter() {
//                 if bit != 0 {
//                     acc ^= xp;
//                 }
//                 xp = gf9ref_mul(xp, sample_pt);
//             }
//             evals.push(acc);
//         }
//         evals
//     }
//     use super::*;
//
//     #[test]
//     fn test_poly_eval_fixed() {
//         let mut rng = StdRng::seed_from_u64(0xDEC0_FFE1);
//
//         /* fixed random coefficient pattern                                */
//         let mut coeffs_arr = [0u8; 233];
//         for bit in &mut coeffs_arr {
//             *bit = rng.r#gen::<u8>() & 1;
//         }
//
//         /* random public domain of 5–15 points                              */
//         let domain_len = rng.gen_range(5..=15);
//         let mut domain = Vec::<u16>::with_capacity(domain_len);
//         for _ in 0..domain_len {
//             domain.push(rng.r#gen::<u16>() & 0x1FF); // 9-bit constants
//         }
//
//         /* ----------- build circuit ------------------------------------- */
//         let mut bld = CktBuilder::default();
//
//         /* allocate 233 secret input wires for the bits  a₀…a₂₃₂          */
//         let coeff_wires: Vec<usize> = (0..233).map(|_| bld.fresh_one()).collect();
//         let coeff_bits: &Gf = coeff_wires.as_slice().try_into().unwrap();
//
//         /* circuit outputs */
//         let eval_wires = emit_poly_eval_domain(&mut bld, coeff_bits, &domain);
//
//         /* witness: 233 coefficient bits                                   */
//         let mut witness = Vec::<bool>::with_capacity(233);
//         for carr_i in &coeffs_arr {
//             witness.push(*carr_i != 0);
//         }
//
//         let wires = bld.eval_gates(&witness);
//
//         /* read hardware results ---------------------------------------- */
//         let hw_evals: Vec<u16> = eval_wires
//             .iter()
//             .map(|bits| (0..9).fold(0u16, |acc, i| acc | ((wires[bits[i]] as u16) << i)))
//             .collect();
//
//         /* software reference check ------------------------------------- */
//         let sw_evals = ref_evaluate_poly_at_fixed_gf9(&coeffs_arr, &domain);
//         assert_eq!(hw_evals, sw_evals, "mismatch in Horner evaluation");
//     }
//
//     #[test]
//     fn random_pairs_agree_with_reference() {
//         let mut rng = StdRng::seed_from_u64(0xC0FFEE);
//         let b: u16 = rng.r#gen::<u16>() & 0x1FF;
//
//         /* build one circuit instance */
//         let mut bld = CktBuilder::default();
//         let a_bits: GF9 = bld.fresh();
//         //let b_bits: GF9 = bld.fresh();
//         let out_bits_k = emit_mul_by_const(&mut bld, a_bits, b);
//         bld.show_gate_counts();
//
//         for _ in 0..1_000 {
//             let a: u16 = rng.r#gen::<u16>() & 0x1FF; // random 9-bit ints
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
//             let chw: u16 = out_bits_k
//                 .iter()
//                 .enumerate()
//                 .fold(0, |acc, (i, &w_id)| acc | ((wires[w_id] as u16) << i));
//
//             let nhw = gf9ref_mul(a, b);
//             assert_eq!(chw, nhw, "Mismatch for a=0x{:03x}, b=0x{:03x}", a, b);
//         }
//     }
// }
