//! Binary circuit implementation of scalar field multiplication
//! Uses karatsuba for multiplication and pseudo mersenne prime reduction for modular reduction

use super::builder::CircuitTrait;

pub(crate) const FR_LEN: usize = 232;
pub(crate) type Fr = [usize; FR_LEN];

const REDUCTION_SPLIT: usize = 231; // 2^231 limb boundary
const THRESH: usize = 32;

#[cfg(test)]
const MOD_HEX: &str = "8000000000000000000000000000069d5bb915bcd46efb1ad5f173abdf"; // n

type Bits = Vec<usize>;

#[inline]
fn not<T: CircuitTrait>(b: &mut T, x: usize) -> usize {
    let one_gate = b.one();
    b.xor_wire(x, one_gate)
}

// ───────── unsigned ADD  (variable length, ripple-carry) ─────────
pub(crate) fn add_unsigned<T: CircuitTrait>(b: &mut T, a: &[usize], c: &[usize]) -> Vec<usize> {
    let n = a.len().max(c.len());
    let mut out = vec![b.zero(); n];
    let mut carry = b.zero();

    for (i, out_i) in out.iter_mut().enumerate().take(n) {
        let ai = *a.get(i).unwrap_or(&b.zero());
        let ci = *c.get(i).unwrap_or(&b.zero());
        let (s, co) = full_add(b, ai, ci, carry);
        *out_i = s;
        carry = co;
    }
    out.push(carry); // keep final carry (matches reference)
    out
}

// ───────── unsigned SUB  (assumes a ≥ b, but lengths may differ) ─────────
pub(crate) fn sub_unsigned<T: CircuitTrait>(b: &mut T, a: &[usize], c: &[usize]) -> Vec<usize> {
    let n = a.len(); // a is the minuend, guaranteed ≥ b
    let mut out = vec![b.zero(); n];
    let mut borrow = b.zero();

    for i in 0..n {
        let ai = a[i];
        let ci = *c.get(i).unwrap_or(&b.zero()); // treat missing bits as 0
        let tmp = b.xor_wire(ai, ci);
        let diff = b.xor_wire(tmp, borrow);

        /* borrow_out = (~a & b) | ((~a | b) & borrow) */
        let m0 = not(b, ai);
        let t1 = b.and_wire(m0, ci);
        let m1 = b.or_wire(m0, ci);
        let t2 = b.and_wire(m1, borrow);
        borrow = b.or_wire(t1, t2);

        out[i] = diff;
    }
    /* we know borrow == 0 because a ≥ b */
    out
}

fn full_add<T: CircuitTrait>(b: &mut T, a: usize, b_: usize, cin: usize) -> (usize, usize) {
    let p = b.xor_wire(a, b_); // propagate
    let g = b.and_wire(a, b_); // generate
    let sum = b.xor_wire(p, cin);
    let t0 = b.and_wire(p, cin);
    let carry = b.xor_wire(g, t0);
    (sum, carry)
}

// ───────────────────  a ≥ b   (one wire, MSB first)  ─────────────────────
//  Gate cost: 4·W XOR + 3·W AND
pub(crate) fn ge_unsigned<T: CircuitTrait>(b: &mut T, a: &[usize], c: &[usize]) -> usize {
    let w = a.len();
    let mut gt = b.zero();
    let mut eq = b.one();
    for i in (0..w).rev() {
        let ai = a[i];
        let bi = c[i];
        let m0 = not(b, bi);
        let ai_gt_bi = b.and_wire(ai, m0);
        //let _m1 = not(b, ai);
        //let ai_lt_bi = b.and_wire(m1, bi);
        let m2 = b.and_wire(eq, ai_gt_bi);
        gt = b.or_wire(gt, m2);
        let m3 = b.xor_wire(ai, bi);
        let m4 = not(b, m3);
        eq = b.and_wire(eq, m4); // keep eq flag
    }
    b.or_wire(gt, eq) // ge = gt ∨ eq
}

/// shift-left by `k` bits  (prepend `k` zeros, keep length = v.len()+k)
///
/// * `v` – little-endian bit slice (LSB first, one wire-ID per bit)
/// * returns a fresh `Vec<usize>` with `k` leading zeros.
///
/// **Gate cost:** zero (just copies wire IDs).
pub(crate) fn emit_shl_bits<T: CircuitTrait>(b: &mut T, v: &[usize], k: usize) -> Vec<usize> {
    let zero_wire = b.zero();
    let mut out = Vec::with_capacity(v.len() + k);
    out.extend(std::iter::repeat_n(zero_wire, k)); // k leading zeros
    out.extend_from_slice(v); // then the input bits
    out
}

fn csa<T: CircuitTrait>(b: &mut T, x: usize, y: usize, z: usize) -> (usize, usize) {
    let tmp = b.xor_wire(x, y);
    let sum = b.xor_wire(tmp, z);
    let t = b.xor_wire(x, y); // p = x⊕y
    let t0 = b.and_wire(x, y);
    let t1 = b.and_wire(t, z);
    let carry = b.xor_wire(t0, t1); // g ⊕ (p&z)
    (sum, carry) // carry is already shifted ↑1
}

pub(crate) fn mul_school<T: CircuitTrait>(bld: &mut T, a: &Bits, b: &Bits) -> Bits {
    let max_len = a.len() + b.len();

    // 1. collect ANDs per column
    let mut cols: Vec<Vec<usize>> = vec![Vec::new(); max_len];
    for i in 0..a.len() {
        for j in 0..b.len() {
            let bit = bld.and_wire(a[i], b[j]);
            cols[i + j].push(bit);
        }
    }

    // 2. Wallace reduction with 3:2 CSAs
    let mut col = 0;
    while col < cols.len() {
        while cols[col].len() >= 3 {
            let (s, c) = {
                let z = cols[col].pop().unwrap();
                let y = cols[col].pop().unwrap();
                let x = cols[col].pop().unwrap();
                csa(bld, x, y, z)
            };
            cols[col].push(s);
            if col + 1 == cols.len() {
                cols.push(Vec::new());
            }
            cols[col + 1].push(c);
        }
        col += 1;
    }

    // 3. gather the two rows
    let zero = bld.zero();
    let mut row0 = Vec::with_capacity(cols.len());
    let mut row1 = Vec::with_capacity(cols.len());
    for col in cols {
        match col.as_slice() {
            [a, b] => {
                row0.push(*a);
                row1.push(*b);
            }
            [a] => {
                row0.push(*a);
                row1.push(zero);
            }
            [] => {
                row0.push(zero);
                row1.push(zero);
            }
            _ => unreachable!(),
        }
    }

    // 4. final carry‑propagate once

    add_unsigned(bld, &row0, &row1)
}

pub(crate) fn mul_kara_rec<T: CircuitTrait>(bld: &mut T, a: &Bits, b: &Bits) -> Bits {
    if a.len() <= THRESH || b.len() <= THRESH {
        return mul_school(bld, a, b);
    }
    let n = a.len().max(b.len());
    let m = n / 2; // split position

    // split a and b
    let a0: Bits = a[..m].to_vec();
    let a1: Bits = a[m..].to_vec();
    let b0: Bits = b[..m].to_vec();
    let b1: Bits = b[m..].to_vec();
    let z0 = mul_kara_rec(bld, &a0, &b0);
    let z2 = mul_kara_rec(bld, &a1, &b1);
    let a0p1 = add_unsigned(bld, &a0, &a1);
    let b0p1 = add_unsigned(bld, &b0, &b1);
    let z1 = mul_kara_rec(bld, &a0p1, &b0p1);
    let t0 = &sub_unsigned(bld, &z1, &z0);
    let t = sub_unsigned(bld, t0, &z2);
    let t1 = &emit_shl_bits(bld, &z2, 2 * m);
    let t2 = &emit_shl_bits(bld, &t, m);
    let t3 = &add_unsigned(bld, t2, &z0);
    add_unsigned(bld, t1, t3)
}

// ──────────────────────────  2-way mux  (sel ? a : b)  ────────────────────
#[inline]
fn mux<T: CircuitTrait>(b: &mut T, sel: usize, a: usize, d: usize) -> usize {
    let m0 = b.xor_wire(a, d);
    let m1 = b.and_wire(sel, m0);
    b.xor_wire(d, m1)
}
fn mux_vec<T: CircuitTrait>(b: &mut T, sel: usize, a: &[usize], d: &[usize]) -> Vec<usize> {
    a.iter().zip(d).map(|(&x, &y)| mux(b, sel, x, y)).collect()
}

#[inline]
pub(crate) fn pad_to<T: CircuitTrait>(b: &mut T, mut v: Vec<usize>, n: usize) -> Vec<usize> {
    if v.len() < n {
        v.extend(std::iter::repeat_n(b.zero(), n - v.len()));
    }
    v
}

/// t · C      with C = 0x69d5bb915bcd46efb1ad5f173abdf   (115 bit)
/// Uses the published w‑NAF‑6 table but **never propagates carries**
/// until the very end: all partial products are merged in two Wallace
/// trees (positive / negative digits).
pub(crate) fn emit_mul_const_c_csa<T: CircuitTrait>(b: &mut T, t: &[usize]) -> Vec<usize> {
    /* w‑NAF‑6 digits:  (shift , signed_digit) */
    const TABLE: &[(usize, i8)] = &[
        (0, 31),
        (6, -17),
        (12, -5),
        (18, 29),
        (24, -15),
        (33, -21),
        (40, 27),
        (48, -5),
        (56, -17),
        (63, -23),
        (69, -25),
        (78, 23),
        (84, 17),
        (91, -9),
        (98, 23),
        (104, 29),
        (111, 13),
    ];

    /* ── 1. buckets “per bit‑position” for +ve and –ve digits ───────── */
    let max_len = t.len() + 120; // generous upper bound
    let mut cols_pos: Vec<Vec<usize>> = vec![Vec::new(); max_len];
    let mut cols_neg: Vec<Vec<usize>> = vec![Vec::new(); max_len];

    for &(shift, digit) in TABLE {
        let neg = digit < 0;
        let mag = digit.unsigned_abs(); // 1 … 31 (odd)

        /* decompose ‘mag’ into its set bits  (k = Σ 2^bit) */
        for bit in 0..5 {
            if (mag >> bit) & 1 == 0 {
                continue;
            }
            let global_shift = shift + bit as usize; // (t << bit) << shift
            for (i, &w) in t.iter().enumerate() {
                let bucket = if neg { &mut cols_neg } else { &mut cols_pos };
                bucket[i + global_shift].push(w);
            }
        }
    }

    /* ── 2. Wallace‑tree reduction  (identical for pos / neg) ───────── */
    fn reduce_cols<T: CircuitTrait>(
        b: &mut T,
        mut cols: Vec<Vec<usize>>,
    ) -> (Vec<usize>, Vec<usize>) {
        let mut k = 0;
        while k < cols.len() {
            while cols[k].len() >= 3 {
                let z = cols[k].pop().unwrap();
                let y = cols[k].pop().unwrap();
                let x = cols[k].pop().unwrap();
                let (s, c) = csa(b, x, y, z);
                cols[k].push(s);
                if k + 1 == cols.len() {
                    cols.push(Vec::new());
                }
                cols[k + 1].push(c);
            }
            k += 1;
        }
        /* collect the *two* remaining rows */
        let zero = b.zero();
        let mut r0 = Vec::with_capacity(cols.len());
        let mut r1 = Vec::with_capacity(cols.len());
        for col in cols {
            match col.as_slice() {
                [a, b] => {
                    r0.push(*a);
                    r1.push(*b);
                }
                [a] => {
                    r0.push(*a);
                    r1.push(zero);
                }
                [] => {
                    r0.push(zero);
                    r1.push(zero);
                }
                _ => unreachable!(),
            }
        }
        (r0, r1)
    }

    let (p0, p1) = reduce_cols(b, cols_pos);
    let (n0, n1) = reduce_cols(b, cols_neg);

    /* ── 3. final carry‑propagate once per side ───────── */
    let pos = add_unsigned(b, &p0, &p1); // ≤ 2·|t|+120 bits
    let neg = add_unsigned(b, &n0, &n1);

    /* ── 4. compute  pos − neg  (pos ≥ neg, proof: C > 0) ──────────── */
    let len = pos.len().max(neg.len());
    let pos_pad = pad_to(b, pos, len);
    let neg_pad = pad_to(b, neg, len);

    sub_unsigned(b, &pos_pad, &neg_pad) // 3 AND/bit once
}

/// little-endian bit vector of the modulus  n
pub(crate) fn const_mod_n<T: CircuitTrait>(b: &mut T) -> Vec<usize> {
    const MOD_HEX: &str = "08000000000000000000000000000069d5bb915bcd46efb1ad5f173abdf";
    let mut out = Vec::<usize>::new();
    for ch in MOD_HEX.chars().rev() {
        let nib = ch.to_digit(16).unwrap();
        for i in 0..4 {
            let bit = (nib >> i) & 1 == 1;
            out.push(if bit { b.one() } else { b.zero() });
        }
    }
    out.truncate(FR_LEN);
    out
}

pub(crate) fn emit_reduce_pseudo_mersenne<T: CircuitTrait>(
    b: &mut T,
    prod: &[usize],
) -> Vec<usize> {
    /* base case: prod < 2²³¹  → already <  n  */
    if prod.len() <= REDUCTION_SPLIT {
        return prod.to_vec(); // just wires, no gates
    }

    /* split prod = t0  +  t1 · 2²³¹ */
    let t0 = prod[..REDUCTION_SPLIT].to_vec(); // low 231 bits
    let t1 = prod[REDUCTION_SPLIT..].to_vec(); // high limb

    /* p1 = (t1 · C)   with C = n − 2²³¹  (115-bit) */
    let p1_unreduced = emit_mul_const_c_csa(b, &t1);
    let p1_reduced = emit_reduce_pseudo_mersenne(b, &p1_unreduced); // recurse

    /* decide if t0 ≥ p1_reduced  */
    let len = t0.len().max(p1_reduced.len());
    let t0_pad = pad_to(b, t0.clone(), len);
    let p1_pad = pad_to(b, p1_reduced.clone(), len);
    let ge_t0_p1 = ge_unsigned(b, &t0_pad, &p1_pad); // 1 when t0 ≥ p1

    /* branch 1:   r₁ = t0 − p1_reduced                */
    let r1 = sub_unsigned(b, &t0_pad, &p1_pad);

    /* branch 2:   r₂ = t0 − p1 + n  =  n − (p1 − t0)  */
    let diff = sub_unsigned(b, &p1_pad, &t0_pad); // p1 − t0 (positive)
    let n_bits = const_mod_n(b);
    let n_pad = pad_to(b, n_bits.clone(), diff.len());
    let r2 = sub_unsigned(b, &n_pad, &diff); // n − diff

    /* first selection */
    let mut r = mux_vec(b, ge_t0_p1, &r1, &r2);

    /* final guard: if r ≥ n, subtract once more        */
    let len2 = r.len().max(n_bits.len());
    r = pad_to(b, r, len2);
    let n2 = pad_to(b, n_bits.clone(), len2);
    let ge_r_n = ge_unsigned(b, &r, &n2);
    let r_sub = sub_unsigned(b, &r, &n2);
    r = mux_vec(b, ge_r_n, &r_sub, &r);

    r
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------
pub(crate) fn emit_fr_mul<T: CircuitTrait>(bld: &mut T, a: &Fr, b: &Fr) -> Fr {
    let prod = mul_kara_rec(bld, &a.to_vec(), &b.to_vec());
    let res: [usize; FR_LEN] = emit_reduce_pseudo_mersenne(bld, &prod).try_into().unwrap();
    res
}

// fr add
pub(crate) fn emit_fr_add<T: CircuitTrait>(bld: &mut T, a: &Fr, b: &Fr) -> Fr {
    let one = bld.one();
    let sum = add_unsigned(bld, a, b); // a+b
    let mut modul = const_mod_n(bld);
    modul.push(bld.zero());
    assert_eq!(sum.len(), modul.len());
    let reduced_sum = sub_unsigned(bld, &sum, &modul); // a+b-n
    let ge = ge_unsigned(bld, &sum, &modul); // a+b>=n
    let nge = bld.xor_wire(ge, one);
    let masked_reduced_sum: Vec<usize> = reduced_sum.iter().map(|r| bld.and_wire(*r, ge)).collect(); // (a+b-n)*ge
    let masked_sum: Vec<usize> = sum.iter().map(|r| bld.and_wire(*r, nge)).collect(); // (a+b)*ge'
    assert_eq!(masked_reduced_sum.len(), masked_sum.len());
    let res: Vec<usize> =
        masked_reduced_sum.iter().zip(masked_sum).map(|(x0, x1)| bld.xor_wire(*x0, x1)).collect(); // (a+b)*ge' ^ (a+b-n)*ge
    let res: [usize; FR_LEN] = res[0..FR_LEN].try_into().unwrap();
    res
}

pub(crate) fn emit_fr_sub<T: CircuitTrait>(bld: &mut T, a: &Fr, b: &Fr) -> Fr {
    let one = bld.one();

    let ge = ge_unsigned(bld, a, b);
    let mut a_minus_b = sub_unsigned(bld, a, b); // a >= b
    let modul = const_mod_n(bld);
    assert_eq!(a_minus_b.len(), modul.len());
    let a_plus_r = add_unsigned(bld, a, &modul);
    let a_plus_r_minus_b = sub_unsigned(bld, &a_plus_r, b); // a < b
    a_minus_b.push(bld.zero());
    assert_eq!(a_plus_r_minus_b.len(), a_minus_b.len());

    let nge = bld.xor_wire(ge, one);

    let masked_a_minus_b: Vec<usize> = a_minus_b.iter().map(|r| bld.and_wire(*r, ge)).collect();
    let masked_a_plus_r_minus_b: Vec<usize> =
        a_plus_r_minus_b.iter().map(|r| bld.and_wire(*r, nge)).collect();

    assert_eq!(masked_a_minus_b.len(), masked_a_plus_r_minus_b.len());
    let res: Vec<usize> = masked_a_minus_b
        .iter()
        .zip(masked_a_plus_r_minus_b)
        .map(|(x0, x1)| bld.xor_wire(*x0, x1))
        .collect();
    let res: Fr = res[0..FR_LEN].try_into().unwrap();
    res
}

#[cfg(test)]
mod tests {
    use super::super::{builder::CircuitAdapter, fr_ref::frref_to_bits};

    use super::*;
    use num_bigint::{BigUint, RandomBits};
    use num_traits::Num;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    #[test]
    fn test_fr_mul() {
        let mut bld = CircuitAdapter::default();

        let a_labels: Fr = bld.fresh();
        let b_labels: Fr = bld.fresh();

        let c_labels = emit_fr_mul(&mut bld, &a_labels, &b_labels);

        for i in 0..100 {
            let mut rng = rand::thread_rng();
            let a_bi: BigUint = rng.sample(RandomBits::new((i + 1) * 2));
            let b_bi: BigUint = rng.sample(RandomBits::new((i + 1) * 2));

            let n = BigUint::from_str_radix(MOD_HEX, 16).unwrap();
            let ref_r = (&a_bi * &b_bi) % n;

            let mut witness = Vec::<bool>::new();

            let a_bits = frref_to_bits(&a_bi);
            let b_bits = frref_to_bits(&b_bi);
            witness.extend_from_slice(&a_bits);
            witness.extend_from_slice(&b_bits);

            let wires = bld.eval_gates(&witness);

            let c_bits_calc: [bool; FR_LEN] = c_labels.map(|id| wires[id]);
            assert_eq!(c_bits_calc, frref_to_bits(&ref_r));
        }
    }

    #[test]
    fn test_fr_add_batch() {
        let mut bld = CircuitAdapter::default();
        let a_labels: Fr = bld.fresh();
        let b_labels: Fr = bld.fresh();

        let c_labels = emit_fr_add(&mut bld, &a_labels, &b_labels);

        let mut rng = StdRng::seed_from_u64(42);

        for i in 0..300 {
            let a_bi: BigUint = rng.sample(RandomBits::new((i + 1) % 2));
            let b_bi: BigUint = rng.sample(RandomBits::new((i + 1) % 2));

            let n = BigUint::from_str_radix(MOD_HEX, 16).unwrap();
            let ref_r = (&a_bi + &b_bi) % n;

            let mut witness = Vec::<bool>::new();

            let a_bits = frref_to_bits(&a_bi);
            let b_bits = frref_to_bits(&b_bi);
            witness.extend_from_slice(&a_bits);
            witness.extend_from_slice(&b_bits);

            let wires = bld.eval_gates(&witness);

            let c_bits_calc: [bool; FR_LEN] = c_labels.map(|id| wires[id]);
            assert_eq!(c_bits_calc, frref_to_bits(&ref_r));
        }
    }

    #[test]
    fn test_fr_sub_batch() {
        let mut bld = CircuitAdapter::default();
        let a_labels: Fr = bld.fresh();
        let b_labels: Fr = bld.fresh();

        let c_labels = emit_fr_sub(&mut bld, &a_labels, &b_labels);

        let mut rng = StdRng::seed_from_u64(42);

        for i in 0..300 {
            let a_bi: BigUint = rng.sample(RandomBits::new((i + 1) % 2));
            let b_bi: BigUint = rng.sample(RandomBits::new((i + 1) % 2));

            let n = BigUint::from_str_radix(MOD_HEX, 16).unwrap();
            let ref_r = if a_bi >= n { (&a_bi - &b_bi) % n } else { (&a_bi + &n - &b_bi) % n };

            let mut witness = Vec::<bool>::new();

            let a_bits = frref_to_bits(&a_bi);
            let b_bits = frref_to_bits(&b_bi);
            witness.extend_from_slice(&a_bits);
            witness.extend_from_slice(&b_bits);

            let wires = bld.eval_gates(&witness);

            let c_bits_calc: [bool; FR_LEN] = c_labels.map(|id| wires[id]);
            assert_eq!(c_bits_calc, frref_to_bits(&ref_r));
        }
    }
}
