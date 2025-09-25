//! Interpolate evaluations at point in GF(2^9) to obtain a polynomial that represents result of base field multiplication in GF(2^233)
//!
//! DISCLAIMER:
//! A much better approach would have been to use Binary IFFT directly e.g. "Frobenius Additive Fast Fourier Transform - Wen-Ding Li"
//! but this seems to be limited to fields of powers of 2 i.e. GF(2^{2^m}) for m=0,1,.., which GF(2^9) doesn't meet.
//! For now (this prototype code), we make do with the following less clean implementation for interpolation.
//! Tracking git issue #5

use super::builder::{CircuitTrait, xor_many};
use super::gf_ckt::Gf;
use super::gf9_eval_ckt::emit_mul_by_const;
use super::gf9_ref::gf9ref_inv as gf9_inv;
use super::gf9_ref::{gf9ref_mul, gf9ref_pow};

#[inline]
pub(crate) fn xor_gf9<T: CircuitTrait>(b: &mut T, x: &[usize; 9], y: &[usize; 9]) -> [usize; 9] {
    let mut out = [0; 9];
    for i in 0..9 {
        out[i] = b.xor_wire(x[i], y[i]);
    }
    out
}

/// Convert coefficients in F₂⁹ to bits by taking trace
pub(crate) fn emit_gf9_to_bits<T: CircuitTrait>(bld: &mut T, cf: &[[usize; 9]]) -> Vec<usize> {
    cf.iter().map(|&c| xor_many(bld, c)).collect()
}

/* ──────────────────  Reduce mod  x²³³ + x⁷⁴ + 1  (correct) ────────────────── */
pub(crate) fn emit_reduce_mod<T: CircuitTrait>(b: &mut T, h: &[usize]) -> Gf {
    /* 0‥464 working copy (pad with zero wires) */
    let z = b.zero();
    let mut c: Vec<usize> = (0..465).map(|i| *h.get(i).unwrap_or(&z)).collect();

    /* fold high terms downward, high-to-low */
    for i in (233..465).rev() {
        let bit_i = c[i]; // secret control bit

        /* c[i-233] ^= bit_i */
        let d1 = b.xor_wire(c[i - 233], bit_i);
        c[i - 233] = d1;

        /* c[i-159] ^= bit_i   (because  i-233+74 = i-159) */
        let d2 = b.xor_wire(c[i - 159], bit_i);
        c[i - 159] = d2;
        /* c[i] itself is left unchanged; we simply don't read it again   */
    }

    /* first 233 wires are the reduced polynomial                         */
    let mut out = [z; 233];
    out.copy_from_slice(&c[..233]);
    out
}

const N: usize = 511; // |F₂⁹×| = 2⁹ − 1

// primitive element g = 0x02 for the poly x⁹ + x⁴ + 1
const G: u16 = 0x02;

type W = [usize; 9];
// ---------------------------------------------------------------------------
//  ω‑power table  (ω = G has order 511)
// ---------------------------------------------------------------------------
pub(crate) fn pow_table() -> [u16; N] {
    let mut p = [0u16; N];
    p[0] = 1;
    for j in 1..N {
        p[j] = gf9ref_mul(p[j - 1], G);
    }
    p
}

/// Computes a size-511 NTT or INTT using the mixed-radix (7x73) algorithm.
fn ntt_mixed_radix_511<T: CircuitTrait>(bld: &mut T, data: &mut [W], is_inverse: bool) {
    const N1: usize = 7;
    const N2: usize = 73;

    // --- Stage 1: Column Transforms (73 DFTs of size 7) ---
    let root_n1 = gf9ref_pow(G, N2 as u32);
    let mut matrix: Vec<[W; N1]> = (0..N2)
        .map(|col_idx| {
            let mut column = [[0; 9]; N1];
            for i in 0..N1 {
                column[i] = data[i * N2 + col_idx];
            }
            dft_7(bld, &column, root_n1, is_inverse)
        })
        .collect();

    // --- Stage 2: Twiddle Factor Multiplication ---
    let twiddle_root = if is_inverse { gf9_inv(G) } else { G };
    for j1 in 0..N1 {
        for (j2, matrix_j2) in matrix.iter_mut().enumerate().take(N2) {
            let exponent = (j1 * j2) as u32;
            let twiddle = gf9ref_pow(twiddle_root, exponent);
            matrix_j2[j1] = emit_mul_by_const(bld, matrix_j2[j1], twiddle);
        }
    }

    // --- Stage 3: Row Transforms (7 DFTs of size 73) ---
    let root_n2 = gf9ref_pow(G, N1 as u32);
    let final_matrix: Vec<[W; 73]> = (0..N1)
        .map(|row_idx| {
            let mut row = [[0; 9]; N2];
            for i in 0..N2 {
                row[i] = matrix[i][row_idx];
            }
            dft_73(bld, &row, root_n2, is_inverse)
        })
        .collect();

    // --- Step 4: Read out transposed results ---
    for k1 in 0..N1 {
        for k2 in 0..N2 {
            data[k2 * N1 + k1] = final_matrix[k1][k2];
        }
    }
}

/// The main INTT function. Replaces the old quadratic loop with a call
/// to the fast mixed-radix NTT, followed by scaling.
pub(crate) fn gf9_interpolate_inverse_fft<T: CircuitTrait>(bld: &mut T, y: &[W; N]) -> [W; N] {
    // In a characteristic-2 field, 1/N is 1/1 = 1, because N=511 is odd.
    //let ninv = 1u16;
    let mut c_mut = *y;

    ntt_mixed_radix_511(bld, &mut c_mut, true);

    // for val in c_mut.iter_mut() {
    //     *val = gf9_mul(*val, ninv);
    // }

    c_mut
}

// Interpolate from full evaluation vector to 233‑bit element
#[allow(non_snake_case)]
pub(crate) fn emit_gf9_interpolate_fft<T: CircuitTrait>(bld: &mut T, Y: &[W; N]) -> Gf {
    let coeffs = gf9_interpolate_inverse_fft(bld, Y);
    let bits = emit_gf9_to_bits(bld, &coeffs);
    emit_reduce_mod(bld, &bits)
}

/// A dedicated, "hand-unrolled" kernel for the 7-point DFT.
/// For now, it's a direct implementation, ready for future optimization.
fn dft_7<T: CircuitTrait>(bld: &mut T, input: &[W; 7], root: u16, is_inverse: bool) -> [W; 7] {
    let mut output = [[0; 9]; 7];
    let w = if is_inverse { gf9_inv(root) } else { root };

    // Pre-compute powers of the root for this specific transform
    let mut powers = [0; 7];
    powers[0] = 1;
    for i in 1..7 {
        powers[i] = gf9ref_mul(powers[i - 1], w);
    }

    for (j, output_j) in output.iter_mut().enumerate() {
        let mut sum = [bld.zero(); 9];
        for (k, input_k) in input.iter().enumerate().take(7) {
            let exponent = (j * k) % 7;
            let twiddle = powers[exponent];
            let term = emit_mul_by_const(bld, *input_k, twiddle);
            sum = xor_gf9(bld, &sum, &term);
        }
        *output_j = sum;
    }
    output
}

/* ---------- helpers shared by all tests ---------- */
//const P: usize = 73;
const LEN: usize = 72;
const GEN: u8 = 5; // generator of ℤ₇₃×
//const GEN_INV: u8 = 44; // 5⁻¹ mod 73

/* build a[] and b[]  -------------------------------------------------- */
fn build_rader_vectors<T: CircuitTrait>(
    bld: &mut T,
    src: &[W; 73],
    ω: u16,
    inverse: bool,
) -> ([W; LEN], [u16; LEN], W, W /*x0, Σ src */) {
    let x0 = src[0];
    let sum_all = src.iter().fold([bld.zero(); 9], |acc, &v| xor_gf9(bld, &acc, &v));

    let ω_adj = if inverse { gf9_inv(ω) } else { ω };

    let mut seq: u8 = 1;
    let mut a = [[0; 9]; LEN];
    let mut b = [0; LEN];

    for m in 0..LEN {
        a[m] = src[seq as usize];
        b[m] = gf9ref_pow(ω_adj, seq as u32);
        seq = ((seq as u16 * GEN as u16) % 73) as u8; // ALWAYS +GEN
    }
    (a, b, x0, sum_all)
}

/// The size at which the recursive Karatsuba multiplication will stop
/// and fall back to the naive O(n^2) algorithm. This is important for
/// performance, as recursion has overhead. 18 is a reasonable choice here.
const KARATSUBA_CUTOFF: usize = 2;

/// Naive O(n^2) polynomial multiplication.
/// Serves as the base case for the recursion. Accepts slices.
fn poly_mul_naive<T: CircuitTrait>(bld: &mut T, a: &[W], b: &[u16]) -> Vec<W> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let mut c = vec![[bld.zero(); 9]; a.len() + b.len() - 1];
    for i in 0..a.len() {
        for j in 0..b.len() {
            let tmp = emit_mul_by_const(bld, a[i], b[j]);
            c[i + j] = xor_gf9(bld, &c[i + j], &tmp);
        }
    }
    c
}

/// A fully recursive implementation of Karatsuba's algorithm for
/// polynomial multiplication.
fn poly_mul<T: CircuitTrait>(bld: &mut T, a: &[W], b: &[u16]) -> Vec<W> {
    // End recursion if inputs are empty or too small
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    if a.len() < KARATSUBA_CUTOFF || b.len() < KARATSUBA_CUTOFF {
        return poly_mul_naive(bld, a, b);
    }

    // Determine split point. `mid` is the length of the lower half.
    let mid = a.len().max(b.len()).div_ceil(2);

    // Split inputs into two halves.
    let (a0, a1) = a.split_at(std::cmp::min(mid, a.len()));
    let (b0, b1) = b.split_at(std::cmp::min(mid, b.len()));

    // Three recursive calls for the sub-problems.
    let p0 = poly_mul(bld, a0, b0); // p0 = a₀ * b₀
    let p1 = poly_mul(bld, a1, b1); // p1 = a₁ * b₁

    // For p_sum = (a₀+a₁) * (b₀+b₁), we first need to sum the parts.
    let mut a_sum = a0.to_vec();
    for i in 0..a1.len() {
        a_sum[i] = xor_gf9(bld, &a_sum[i], &a1[i]);
    }
    let mut b_sum = b0.to_vec();
    for i in 0..b1.len() {
        b_sum[i] ^= b1[i];
    }
    let p_sum = poly_mul(bld, &a_sum, &b_sum);

    // Calculate cross term: cross = p_sum - p0 - p1
    let mut cross = p_sum;
    for i in 0..p0.len() {
        cross[i] = xor_gf9(bld, &cross[i], &p0[i]);
    }
    for i in 0..p1.len() {
        cross[i] = xor_gf9(bld, &cross[i], &p1[i]);
    }

    // Assemble the final result from the parts:
    // Result(x) = p0(x) + cross(x) * x^mid + p1(x) * x^(2*mid)
    let mut result = vec![[bld.zero(); 9]; a.len() + b.len() - 1];
    for i in 0..p0.len() {
        result[i] = xor_gf9(bld, &result[i], &p0[i]);
    }
    for i in 0..cross.len() {
        result[i + mid] = xor_gf9(bld, &result[i + mid], &cross[i]);
    }
    for i in 0..p1.len() {
        result[i + 2 * mid] = xor_gf9(bld, &result[i + 2 * mid], &p1[i]);
    }

    result
}

// --- Karatsuba CONVOLUTION function ---
fn cyclic_convolve_72_karatsuba<T: CircuitTrait>(
    bld: &mut T,
    a: &[W; LEN],
    b: &[u16; LEN],
) -> [W; LEN] {
    const HALF: usize = LEN / 2;

    let (a0, a1) = a.split_at(HALF);
    let (b0, b1) = b.split_at(HALF);

    // Perform three LINEAR multiplications using the new recursive function.
    let p0 = poly_mul(bld, a0, b0); // p0 = a₀ * b₀
    let p1 = poly_mul(bld, a1, b1); // p1 = a₁ * b₁

    let a_sum = a0.iter().zip(a1.iter()).map(|(x, y)| xor_gf9(bld, x, y)).collect::<Vec<_>>();
    let b_sum = b0.iter().zip(b1.iter()).map(|(x, y)| x ^ y).collect::<Vec<_>>();
    let p_sum = poly_mul(bld, &a_sum, &b_sum);

    // Calculate cross term (A₀B₁ + A₁B₀)
    let mut cross = p_sum;
    for i in 0..p0.len() {
        cross[i] = xor_gf9(bld, &cross[i], &p0[i]);
    }
    for i in 0..p1.len() {
        cross[i] = xor_gf9(bld, &cross[i], &p1[i]);
    }

    // Assemble and reduce modulo (x⁷² − 1)
    let mut out = [[bld.zero(); 9]; LEN];
    let prod_len = p0.len(); // All products p0, p1, cross will have length 2*HALF-1 = 71
    for i in 0..prod_len {
        let tmp = xor_gf9(bld, &p0[i], &p1[i]);
        out[i] = xor_gf9(bld, &tmp, &out[i]);
        out[(i + HALF) % LEN] = xor_gf9(bld, &out[(i + HALF) % LEN], &cross[i]);
    }
    out
}

/// Computes cyclic cross-correlation using the fully recursive Karatsuba convolution.
pub(crate) fn cyclic_cross_correlation_72_karatsuba<T: CircuitTrait>(
    bld: &mut T,
    a: &[W; LEN],
    b: &[u16; LEN],
) -> [W; LEN] {
    let mut a_rev = [[0; 9]; LEN];
    a_rev[0] = a[0];
    for i in 1..LEN {
        a_rev[i] = a[LEN - i];
    }
    cyclic_convolve_72_karatsuba(bld, &a_rev, b)
}

/* 3 assemble outputs ---------------------------------------------------- */
fn assemble_rader_out<T: CircuitTrait>(bld: &mut T, x0: W, c: &[W; LEN]) -> [W; 73] {
    let mut out = [[bld.zero(); 9]; 73];
    //out[0] = [0;9];                // placeholder, caller fills DC

    let mut seq: u8 = 1; // g⁰
    for c_s in c.iter().take(LEN) {
        out[seq as usize] = xor_gf9(bld, &x0, c_s);
        seq = ((seq as u16 * GEN as u16) % 73) as u8;
    }
    out
}

/* Glue them back together so production code still calls `dft_73()` */
pub(crate) fn dft_73<T: CircuitTrait>(
    bld: &mut T,
    inp: &[W; 73],
    ω: u16,
    inverse: bool,
) -> [W; 73] {
    let (a, b, x0, sum) = build_rader_vectors(bld, inp, ω, inverse);
    let c = cyclic_cross_correlation_72_karatsuba(bld, &a, &b);
    let mut out = assemble_rader_out(bld, x0, &c);
    out[0] = sum; // DC slot
    out
}

#[cfg(test)]
mod test {
    use rand::{Rng, SeedableRng, rngs::StdRng};

    use crate::circuits::sect233k1::builder::CircuitAdapter;

    use super::*;

    fn binary_vec_to_decimal(bits: Vec<u8>) -> u32 {
        assert_eq!(bits.len(), 9);
        let mut decimal = 0u32;
        for (i, bit) in bits.iter().enumerate() {
            assert!(*bit == 0 || *bit == 1, "Vec should only contain 0s and 1s");
            decimal |= (*bit as u32) << i;
        }
        decimal
    }

    fn ref_poly_mul(a: &[u16], b: &[u16]) -> Vec<u16> {
        if a.is_empty() || b.is_empty() {
            return Vec::new();
        }
        let mut c = vec![0u16; a.len() + b.len() - 1];
        for i in 0..a.len() {
            if a[i] == 0 {
                continue;
            }
            for j in 0..b.len() {
                c[i + j] ^= gf9ref_mul(a[i], b[j]);
            }
        }
        c
    }

    #[test]
    fn test_poly_mul() {
        for i in 0..1 {
            const P: usize = 72;
            let mut rng = StdRng::seed_from_u64(i);
            let mut a = [0u16; P];
            for a_i in a.iter_mut().take(P) {
                *a_i = rng.r#gen::<u16>() & 0x1FF;
            }
            let mut b = [0u16; P];
            for b_i in b.iter_mut().take(P) {
                *b_i = rng.r#gen::<u16>() & 0x1FF;
            }
            let ref_out_val = ref_poly_mul(&a, &b);

            let mut input_a_wire_labels = [[0usize; 9]; P];

            let mut witness = Vec::<bool>::new();

            let mut bld = CircuitAdapter::default();

            let mut push_bits = |val: u16, arr: &mut [usize; 9]| {
                for (i, arr_i) in arr.iter_mut().enumerate().take(9) {
                    *arr_i = bld.fresh_one();
                    witness.push((val >> i) & 1 != 0);
                }
            };

            for i in 0..input_a_wire_labels.len() {
                push_bits(a[i], &mut input_a_wire_labels[i]);
            }

            let out_bits = poly_mul(&mut bld, &input_a_wire_labels, &b);
            let wires = bld.eval_gates(&witness);

            let result: Vec<u16> = (0..out_bits.len())
                .map(|i| {
                    let result: Vec<u8> = out_bits[i].iter().map(|id| wires[*id] as u8).collect();
                    let result_sum = binary_vec_to_decimal(result);
                    result_sum as u16
                })
                .collect();

            assert_eq!(result, ref_out_val);
            let stats = bld.gate_counts();
            println!("{stats}");
        }
    }

    /// naive evaluator: P(x_k) at all 511 points
    fn eval_poly(coeff: &[u16; N]) -> [u16; N] {
        let pow = pow_table();
        let mut out = [0u16; N];
        for k in 0..N {
            let x = pow[k];
            let mut x_pow = 1u16;
            let mut acc = 0u16;
            for &c in coeff.iter() {
                acc ^= gf9ref_mul(c, x_pow);
                x_pow = gf9ref_mul(x_pow, x);
            }
            out[k] = acc;
        }
        out
    }

    #[test]
    fn test_inverse_interpolate() {
        let mut rng = rand::thread_rng();

        let mut coeff = [0u16; N];
        for coeff_i in &mut coeff {
            *coeff_i = rng.r#gen::<u16>() & 0x1FF;
        }
        let evals = eval_poly(&coeff);

        let mut bld = CircuitAdapter::default();

        let mut y_bits = [[0usize; 9]; 511];
        let mut witness = Vec::<bool>::new();

        let mut push_bits = |val: u16, arr: &mut [usize; 9]| {
            for (i, arr_i) in arr.iter_mut().enumerate().take(9) {
                *arr_i = bld.fresh_one();
                witness.push((val >> i) & 1 != 0);
            }
        };

        for i in 0..evals.len() {
            push_bits(evals[i], &mut y_bits[i]);
        }

        let out_bits = emit_gf9_interpolate_fft(&mut bld, &y_bits);
        /* run the circuit */
        let wires = bld.eval_gates(&witness);

        let _result: Vec<u8> = out_bits.iter().map(|id| wires[*id] as u8).collect();

        //assert_eq!(out_bits.to_vec(), result);
        let stats = bld.gate_counts();
        println!("{stats}");
    }
}
