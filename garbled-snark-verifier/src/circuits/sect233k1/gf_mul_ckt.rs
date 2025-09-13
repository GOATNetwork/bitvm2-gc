//! FFT based base field multiplication
use super::{
    builder::CircuitTrait,
    gf_ckt::Gf,
    gf_interpolate_ckt::{emit_gf9_interpolate_fft, pow_table},
    gf9_ckt::{emit_gf9_mul, emit_gf9_square},
    gf9_eval_ckt::emit_poly_eval_domain,
    gf9_ref::{gf9ref_mul, gf9ref_pow},
};

/// Generate all 58 orbit representatives modulo 2⁹-1=511
// multiples of 73 have orbit of size 3, while the rest have orbits of size 9
fn representatives() -> Vec<usize> {
    let mut seen = [false; 511];
    let mut reps = Vec::with_capacity(52);
    for k in 1..511 {
        if seen[k] {
            continue;
        }
        reps.push(k);
        let mut t = k;
        let rounds = if t % 73 == 0 { 3 } else { 9 };
        for _ in 0..rounds {
            seen[t] = true;
            t = (t * 2) % 511;
        }
    }
    reps
}

#[allow(clippy::manual_is_multiple_of)]
fn extend_domain(rep: &[usize], xs: &[u16]) -> Vec<u16> {
    let mut exts = Vec::with_capacity(511);
    assert_eq!(rep.len() + 1, xs.len());
    assert_eq!(xs[0], 1); //G^0 -> G^0 is the only point in its orbit, treating it separately
    exts.push(1);
    for i in 1..xs.len() {
        let mut t = xs[i];
        let rounds = if rep[i - 1] % 73 == 0 { 3 } else { 9 };
        for _ in 0..rounds {
            exts.push(t);
            t = gf9ref_mul(t, t);
        }
    }
    exts
}

/// Build domain consisting of orbit representatives
// This can be extended to the full domain consisting of 511 points with `extend_domain`
fn domain(reps: &[usize]) -> Vec<u16> {
    let mut xs = Vec::with_capacity(reps.len() + 1);
    xs.push(1); // G^0
    const G: u16 = 0x02;
    for &r in reps.iter() {
        let t = gf9ref_pow(G, r as u32);
        xs.push(t);
    }
    xs
}

#[allow(clippy::manual_is_multiple_of)]
/// Evaluation over the represetative domain
fn extend_evaluation<T: CircuitTrait>(
    bld: &mut T,
    reps: &[usize],
    rep_evs: &[[u32; 9]],
) -> Vec<[u32; 9]> {
    // first two evs are 0, 1
    // rest should be for representatives
    let mut ys: Vec<[u32; 9]> = Vec::with_capacity(511);
    ys.push(rep_evs[0]);

    for i in 1..rep_evs.len() {
        let mut t = rep_evs[i];
        let rounds = if reps[i - 1] % 73 == 0 { 3 } else { 9 };
        for _ in 0..rounds {
            ys.push(t);
            t = emit_gf9_square(bld, t);
        }
    }
    ys
}

/// Base field multiplication using an FFT-like approach.
///
/// FFT MULTIPLICATION:
/// We select a handful of important points called `representatives` to evaluate each of the polynomial inputs `a` and `b`.
/// We then multiply their respective evaluations and then extend this evaluation to the full domain
/// Finally we interpolate the full set of evaluations into a polynomial
/// This polynomial is reduced to fit within the base field and returned as result
///
/// SELCECTING_DOMAIN:
/// Since the product of two polynomials in GF(2^233) is a 465 degree polynomial, we need > 465 evaluation points.
/// These evaluation points (domain) can be chosen from GF(2^9). The "orbit" property comes from this binary field.
pub(crate) fn emit_gf_mul<T: CircuitTrait>(bld: &mut T, a: &Gf, b: &Gf) -> Gf {
    // Find representative of orbits
    let rep = representatives();

    // Find domain
    let xs = domain(&rep);

    // Evaluate polynomials on domain
    let ya = emit_poly_eval_domain(bld, a, &xs);
    let yb = emit_poly_eval_domain(bld, b, &xs);
    let yc: Vec<[u32; 9]> =
        ya.iter().zip(yb.iter()).map(|(&u, &v)| emit_gf9_mul(bld, u, v)).collect();
    assert_eq!(yc.len(), 59); // 58 representatives + 1 primitive point G^0
    let ycs = extend_evaluation(bld, &rep, &yc);

    let xs = extend_domain(&rep, &xs); // todo: replace with cheap extend_domain
    assert_eq!(xs.len(), ycs.len());

    // reorder domain and evals in the fft domain order
    let pys = {
        let pxs = pow_table();

        let mut xs_sorted = xs.to_vec();
        xs_sorted.sort_unstable();

        let mut pxs_sorted = pow_table(); // returns Vec<T>
        pxs_sorted.sort_unstable();

        assert_eq!(xs_sorted, pxs_sorted, "pow_table() is NOT a permutation of xs");

        let mut pos_map = vec![0; pxs.len()]; // pxs-index → xs-index

        for (xs_idx, &x) in xs.iter().enumerate() {
            if let Some(pxs_idx) = pxs.iter().position(|&p| p == x) {
                pos_map[pxs_idx] = xs_idx;
            }
        }

        let mut pys = vec![[0; 9]; pxs.len()];
        for (i, &xs_idx) in pos_map.iter().enumerate() {
            pys[i] = ycs[xs_idx];
        }
        pys
    };

    let pys: [[u32; 9]; 511] = pys.try_into().unwrap();

    // Convert evaluations back to polynomial, reduce and return as result
    emit_gf9_interpolate_fft(bld, &pys)
}

// #[cfg(test)]
// mod tests {
//     use std::time::Instant;
//
//     use crate::{
//         builder::CktBuilder,
//         gf_ref::{bits_to_gfref, gfref_mul, gfref_to_bits},
//     };
//
//     use super::*;
//     use num_bigint::{BigUint, RandomBits};
//     use rand::{Rng, SeedableRng, rngs::StdRng};
//
//     #[test]
//     fn test_emit_gf_mul() {
//         let mut rng = StdRng::seed_from_u64(0xC0FFEE);
//
//         let a: u64 = rng.r#gen::<u64>() & 0x1FF; // random 9-bit ints
//         let b: u64 = rng.r#gen::<u64>() & 0x1FF;
//         let size = 64;
//
//         let mut bld = CktBuilder::default();
//         let a_bits: Gf = bld.fresh();
//         let b_bits: Gf = bld.fresh();
//         let r = Instant::now();
//         let out_bits = emit_gf_mul(&mut bld, &a_bits, &b_bits);
//         let el = r.elapsed();
//         println!("emit_gf_mul takes {:?} seconds", el.as_secs());
//
//         let mut witness = Vec::<bool>::with_capacity(233 * 2);
//         witness.extend((0..size).map(|i| (a >> i) & 1 != 0));
//         witness.extend((size..233).map(|_| false));
//         witness.extend((0..size).map(|i| (b >> i) & 1 != 0));
//         witness.extend((size..233).map(|_| false));
//
//         let wires = bld.eval_gates(&witness);
//
//         let hw = bits_to_gfref(&out_bits.map(|w_id| wires[w_id]));
//
//         let chw = gfref_mul(&BigUint::from(a), &BigUint::from(b));
//         bld.show_gate_counts();
//         assert_eq!(hw, chw);
//     }
//
//     #[test]
//     fn test_emit_gf_mul2() {
//         let mut rng = StdRng::seed_from_u64(0xC0FFEE);
//
//         let a: BigUint = rng.sample(RandomBits::new(232));
//         let b: BigUint = rng.sample(RandomBits::new(232));
//
//         let mut bld = CktBuilder::default();
//         let a_bits: Gf = bld.fresh();
//         let b_bits: Gf = bld.fresh();
//         let out_bits = emit_gf_mul(&mut bld, &a_bits, &b_bits);
//
//         let mut witness = Vec::<bool>::with_capacity(233 * 2);
//         witness.extend(gfref_to_bits(&a));
//         witness.extend(gfref_to_bits(&b));
//         assert_eq!(witness.len(), 233 * 2);
//         let wires = bld.eval_gates(&witness);
//
//         let hw = bits_to_gfref(&out_bits.map(|w_id| wires[w_id]));
//
//         let chw = gfref_mul(&a, &b);
//         assert_eq!(hw, chw);
//
//         bld.show_gate_counts()
//     }
// }
