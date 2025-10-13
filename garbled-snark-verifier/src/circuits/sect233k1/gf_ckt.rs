//! Basic base field element operations in binary circuit
pub(crate) const GF_LEN: usize = 233;
/// Representation of a base field element as wire labels
pub(crate) type Gf = [usize; GF_LEN];

use super::builder::CircuitTrait;

/* Input  : two 233-wire operands, little-endian bit order          */
/* Output : 233 wires, bit-wise XOR                                 */
pub(crate) fn emit_gf_add<T: CircuitTrait>(b: &mut T, a: &Gf, c: &Gf) -> Gf {
    let v: Vec<usize> = (0..GF_LEN).map(|i| b.xor_wire(a[i], c[i])).collect();
    v.try_into().unwrap()
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

/// Check two field elements for equality
pub(crate) fn emit_gf_equals<T: CircuitTrait>(bld: &mut T, a: &Gf, b: &Gf) -> usize {
    let mut acc = bld.one();
    let one = bld.one();
    for i in 0..GF_LEN {
        let eq = bld.xor_wire(a[i], b[i]);
        let eq = bld.xor_wire(eq, one); // NOT
        acc = bld.and_wire(acc, eq);
    }
    acc
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::circuits::sect233k1::builder::CircuitAdapter;
    use crate::circuits::sect233k1::gf_ref::{GfRef, gfref_mul};
    use num_traits::FromPrimitive;
    use num_traits::One;

    /// Reverse of `to_u64_digits()`:
    ///   Vec<u64> little-endian → BigUint
    fn gf_from_u64_digits(digits: Vec<u64>) -> GfRef {
        // radix = 2^64
        let radix: GfRef = GfRef::one() << 64;
        // fold from most-significant limb to least
        digits.into_iter().rev().fold(GfRef::ZERO, |acc, limb| {
            // BigUint::from_u64 returns Option, but limb < 2^64 always fits.
            (acc * &radix) + GfRef::from_u64(limb).unwrap()
        })
    }

    #[test]
    fn test_gf233_square_random() {
        use rand::{Rng, SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(0xD1CE_FADE);

        for _ in 0..500 {
            /* --- random 233-bit element -------------------------------- */
            let mut words = [0u64; 4];
            words[0] = rng.r#gen();
            words[1] = rng.r#gen();
            words[2] = rng.r#gen();
            words[3] = rng.r#gen::<u64>() & ((1u64 << 41) - 1); // top 41 bits
            let a_big = gf_from_u64_digits(words.to_vec());
            // let a_bits: GF = {
            //     let mut v = [0usize; 233];
            //     for i in 0..233 {
            //         let w = (words[i >> 6] >> (i & 63)) & 1;
            //         v[i] = if w == 1 { 1 } else { 0 }; // placeholder; overwritten below
            //     }
            //     v
            // };

            /* --- build circuit ----------------------------------------- */
            let mut bld = CircuitAdapter::default();
            let mut in_bits = [0usize; 233];
            let mut witness = Vec::<bool>::with_capacity(233);
            for i in 0..233 {
                in_bits[i] = bld.fresh_one();
                witness.push(((words[i >> 6] >> (i & 63)) & 1) == 1);
            }
            let out_bits = emit_gf_square(&mut bld, &in_bits);

            let wires = bld.eval_gates(&witness);

            /* --- collect hardware result ------------------------------- */
            let mut r_words = [0u64; 4];
            for i in 0..233 {
                if wires[out_bits[i]] {
                    r_words[i >> 6] |= 1u64 << (i & 63);
                }
            }
            let hw = gf_from_u64_digits(r_words.to_vec());

            /* --- reference --------------------------------------------- */
            let sw = gfref_mul(&a_big, &a_big);
            assert_eq!(hw, sw, "square mismatch for random a");
        }
    }
}
