//! Point Scalar Multiplication in Binary Circuit
//! Implementation referenced from "Efficient Arithmetic on Koblitz Curves - Jerome A. Solinas" and xs233-sys

const TAU_ADIC_LEN: usize = 470;

/// Tau-adic representation: k = Sum u_i τ^i
/// A scalar is represented by sum of powers of τ, u_i here can be 0 or 1
/// For a 232 bit scalar field element, i ranges over twice that value i.e. 232x2
/// We use this representation with windowed point scalar multiplication, we have found that window size of 5 digits is optimal,
/// therefore multiple of 5 greater than 232x2 = 470 is chosen as `TAU_ADIC_LEN`
///
/// solinas2000 provides algorithm for windowed tau-adic NAF
/// xs233-sys has implementation also for windowed tau-adic NAF
/// However our implementation for now follows windowed tau-adic representation only.
///
/// Algorithm: Repeated Division by tau.
/// Much the same way a decimal number can be converted into binary digits by repeateded division by 2,
/// we can convert an integer into tau-adic representation by repeatedly dividing by tau and taking remainder sequence as result
/// solinas2000 explains when a number is divisible by tau and how to collect its remainder as the result.
///
/// The element c_0 + c_1 τ is divisible by τ if and only if c_0 is even. If it is divisble by τ, remainder is 0, else 1.
/// So LSB of c_0 gives the remainder, which is collected to get the output.
/// Rule for division: (c_0 + c_1 τ) / τ = (c1 - c0/2) + (-c_0/2) τ
///
/// With tau adic representation, you can substitute point doubling in double-and-add algorithm with squaring operation,
/// which is linear and only uses XOR gates
mod tau_adic_repr {
    use super::super::fr_ckt::FR_LEN;
    use super::super::{builder::CircuitTrait, fr_ckt::Fr};
    use super::TAU_ADIC_LEN;

    #[cfg(test)]
    pub(crate) fn tau_adic_repr_bits(k_bits: &[u8; FR_LEN]) -> [u8; TAU_ADIC_LEN] {
        // full‑adder for one bit returning (sum, carry)
        let full_add = |x: u8, y: u8, c: u8| -> (u8, u8) {
            let sum = x ^ y ^ c;
            let carry = (x & y) | (x & c) | (y & c);
            (sum, carry)
        };

        // add two W‑bit vectors, two‑complement
        let add_vec = |x: &Vec<u8>, y: &Vec<u8>| -> Vec<u8> {
            let mut out = vec![0u8; FR_LEN];
            let mut carry = 0u8;
            for i in 0..FR_LEN {
                let (s, c) = full_add(x[i], y[i], carry);
                out[i] = s;
                carry = c; // discard carry while working with 2's complement
            }
            out
        };

        // negate two‑complement via NOT + 1
        let negate = |v: &Vec<u8>| -> Vec<u8> {
            // invert
            let mut inv: Vec<u8> = v.iter().map(|b| 1 ^ *b).collect();
            // add 1
            let mut carry = 1u8;
            for inv_i in inv.iter_mut().take(FR_LEN) {
                let (s, c) = full_add(*inv_i, 0, carry);
                *inv_i = s;
                carry = c; // discard carry while working with 2's complement
            }
            inv
        };

        // arithmetic right‑shift by 1 (sign‑extend)
        let arith_shift_right = |v: &Vec<u8>| -> Vec<u8> {
            let mut out = vec![0u8; FR_LEN];
            out[..(FR_LEN - 1)].copy_from_slice(&v[1..((FR_LEN - 1) + 1)]);
            out[FR_LEN - 1] = v[FR_LEN - 1]; // sign bit (MSB) of 'v' in 2's complement form remains the same
            out
        };

        // subtract 1 (only used when u == 1)
        let sub_one = |v: &mut Vec<u8>| {
            let mut borrow = 1u8;
            for bit in v.iter_mut() {
                let new_bit = *bit ^ borrow; // XOR performs bit‑ subtraction
                borrow &= !*bit; // borrow propagates if bit was 0
                *bit = new_bit;
                if borrow == 0 {
                    break;
                }
            }
        };

        // -----------------------------------------------------------------------
        // Registers c0, c1  (two‑complement)
        let mut c0: Vec<u8> = k_bits.to_vec(); // copy input bits LSB‑first
        let mut c1: Vec<u8> = vec![0u8; FR_LEN];

        // output digits
        let mut out = [0u8; TAU_ADIC_LEN];

        // Element c0 + c1 \tau is divisible by \tau if an only if c0 is even
        for out_r in out.iter_mut().take(TAU_ADIC_LEN) {
            let u = c0[0]; // LSB
            *out_r = u;

            if u == 1 {
                // c0 is odd
                sub_one(&mut c0); // c0 <- c0 - u
            }

            let half = arith_shift_right(&c0);
            let d = negate(&half); // -c0/2

            let c = add_vec(&c1, &d); // c1 + \mew c0/2 => c1 - c0/2

            c0 = c;
            c1 = d;
        }
        out
    }

    fn full_add<T: CircuitTrait>(b: &mut T, x: usize, y: usize, c: usize) -> (usize, usize) {
        let t = b.xor_wire(x, y); // x ⊕ y
        let sum = b.xor_wire(t, c); // SUM  = x ⊕ y ⊕ c

        /* majority: carry = (x&y) ⊕ (c&(x ⊕ y))  —  2 ANDs */
        let a1 = b.and_wire(x, y); // x & y
        let a2 = b.and_wire(c, t); // c & (x⊕y)
        let carry = b.xor_wire(a1, a2);

        (sum, carry)
    }

    // ★ HALF-ADDER : 1 AND
    fn half_add<T: CircuitTrait>(b: &mut T, x: usize, c: usize) -> (usize, usize) {
        (b.xor_wire(x, c), b.and_wire(x, c))
    }

    /* c = a + d     and     nz =  OR_i (c_i | d_i)     */
    fn add_vec_with_flag<T: CircuitTrait>(b: &mut T, a: &Fr, d: &Fr) -> Fr {
        let mut out = [b.zero(); FR_LEN];
        let mut carry = b.zero();

        for i in 0..FR_LEN {
            let (s, c) = full_add(b, a[i], d[i], carry);
            out[i] = s;
            carry = c;
        }
        out
    }

    /* NOT + 1  (two-complement negate) */
    fn negate<T: CircuitTrait>(b: &mut T, v: &Fr) -> Fr {
        let ones = b.one(); // broadcast 1
        let mut inv = [b.zero(); FR_LEN];
        for i in 0..FR_LEN {
            inv[i] = b.xor_wire(v[i], ones);
        } // bitwise NOT
        // +1 with half-adder chain (1 AND / bit) ★
        let mut carry = b.one();
        for inv_i in inv.iter_mut().take(FR_LEN) {
            let (s, c) = half_add(b, *inv_i, carry);
            *inv_i = s;
            carry = c;
        }
        inv
    }
    /* arithmetic right-shift by one (sign extend) */
    fn arith_shift_right<T: CircuitTrait>(bld: &mut T, v: &Fr) -> Fr {
        let mut out = [bld.zero(); FR_LEN];
        out[..(FR_LEN - 1)].copy_from_slice(&v[1..((FR_LEN - 1) + 1)]);
        out[FR_LEN - 1] = v[FR_LEN - 1];
        out
    }

    fn sub_bit<T: CircuitTrait>(a: &mut Fr, u: usize, b: &mut T) {
        let mut borrow = u; // 0 or 1 wire
        let one_gate = b.one();
        for bit in a.iter_mut() {
            // sum   = bit ⊕ borrow
            // carry = (¬bit) ∧ borrow
            let sum = b.xor_wire(*bit, borrow);
            let nbit = b.xor_wire(*bit, one_gate); // ¬bit
            let carry = b.and_wire(nbit, borrow);

            *bit = sum;
            borrow = carry;
            // optional early exit (borrow == 0) is legal but not required
        }
    }

    pub(crate) fn emit_tau_adic_repr_bits<T: CircuitTrait>(
        b: &mut T,
        k_bits: &Fr,
    ) -> [usize; TAU_ADIC_LEN] {
        let mut a: Fr = *k_bits;
        let mut breg: Fr = [b.zero(); FR_LEN];
        let mut out = [b.zero(); TAU_ADIC_LEN];

        for out_i in out.iter_mut().take(TAU_ADIC_LEN) {
            /* u = a₀  --------------------------------------------------*/
            let u = a[0];
            *out_i = u;

            /* a ← a − u  (reuse existing helper)                                */
            sub_bit(&mut a, u, b);

            /* d = −((a)>>1)  ----------------------------------------------------*/
            let half = arith_shift_right(b, &a);
            let d = negate(b, &half);

            /* c = b + d   and   nz = OR(c , d)  ------------------------------- */
            let c = add_vec_with_flag(b, &breg, &d);

            a = c;
            breg = d;
        }
        out
    }

    // #[cfg(test)]
    // mod test {
    //     use num_bigint::{BigUint, RandomBits};
    //     use rand::Rng;
    //
    //     use crate::{
    //         builder::CktBuilder,
    //         curve_scalar_mul_ckt::tau_adic_repr::{emit_tau_adic_repr_bits, tau_adic_repr_bits},
    //         fr_ref::frref_to_bits,
    //     };
    //
    //     use super::*;
    //
    //     #[test]
    //     fn test_tau_adic_repr_bits_circuit() {
    //         let mut rng = rand::thread_rng();
    //         let k: BigUint = rng.sample(RandomBits::new(232));
    //
    //         let kbits = {
    //             let mut k256 = [0u8; FR_LEN];
    //             let kbits = frref_to_bits(&k).map(|b| b as u8);
    //             k256[0..FR_LEN].copy_from_slice(&kbits);
    //             k256
    //         };
    //
    //         let rd_ref = tau_adic_repr_bits(&kbits);
    //
    //         let mut bld = CktBuilder::default();
    //
    //         let mut witness = Vec::<bool>::new();
    //
    //         let mut k_bits = [0; FR_LEN];
    //         for i in 0..k_bits.len() {
    //             k_bits[i] = bld.fresh_one();
    //             witness.push(kbits[i] & 1 != 0);
    //         }
    //
    //         let out_bits = emit_tau_adic_repr_bits(&mut bld, &k_bits);
    //         let wires = bld.eval_gates(&witness);
    //         let result: Vec<u8> = out_bits.iter().map(|id| wires[*id] as u8).collect();
    //         assert_eq!(rd_ref.to_vec(), result);
    //
    //         bld.show_gate_counts()
    //     }
    // }
}

/// Windowed tau-adic representation works by precomputing a 1 << w sized lookup table with multiples of a CurvePoint per row
mod precompute_table {
    use super::super::{
        builder::{CircuitTrait, Template},
        curve_ckt::{CurvePoint, emit_point_frob},
        gf_ckt::GF_LEN,
    };

    /// lookup precompute table
    // indices in little-endian form
    // table: [0..2^w-1]P
    pub(crate) fn emit_lookup<T: CircuitTrait>(
        bld: &mut T,
        table: &[CurvePoint],
        indices: Vec<usize>,
    ) -> CurvePoint {
        fn mux<T: CircuitTrait>(
            bld: &mut T,
            s: &CurvePoint,
            other: &CurvePoint,
            sel: &CurvePoint,
        ) -> CurvePoint {
            let mut r = CurvePoint::identity(bld);

            for i in 0..GF_LEN {
                let d = bld.xor_wire(s.x[i], other.x[i]);
                let xd = bld.and_wire(sel.x[i], d);
                r.x[i] = bld.xor_wire(xd, s.x[i]);
            }
            for i in 0..GF_LEN {
                let d = bld.xor_wire(s.s[i], other.s[i]);
                let xd = bld.and_wire(sel.s[i], d);
                r.s[i] = bld.xor_wire(xd, s.s[i]);
            }
            for i in 0..GF_LEN {
                let d = bld.xor_wire(s.z[i], other.z[i]);
                let xd = bld.and_wire(sel.z[i], d);
                r.z[i] = bld.xor_wire(xd, s.z[i]);
            }
            for i in 0..GF_LEN {
                let d = bld.xor_wire(s.t[i], other.t[i]);
                let xd = bld.and_wire(sel.t[i], d);
                r.t[i] = bld.xor_wire(xd, s.t[i]);
            }
            r
        }

        assert!(table.len().is_power_of_two(), "table length must be a power-of-two");
        let mut level: Vec<CurvePoint> = table.to_vec();

        let mut bit = 0;
        while level.len() > 1 {
            let sel_mask = CurvePoint {
                x: [indices[bit]; GF_LEN],
                s: [indices[bit]; GF_LEN],
                z: [indices[bit]; GF_LEN],
                t: [indices[bit]; GF_LEN],
            };
            let mut next = Vec::<CurvePoint>::with_capacity(level.len() / 2);
            for j in 0..(level.len() / 2) {
                let a = &level[2 * j];
                let b = &level[2 * j + 1];
                next.push(mux(bld, a, b, &sel_mask));
            }
            level = next;
            bit += 1;
        }
        level[0]
    }

    // generate precompute table
    pub(crate) fn emit_precompute_table<T: CircuitTrait>(
        bld: &mut T,
        p: &CurvePoint,
        w: usize,
    ) -> Vec<CurvePoint> {
        let table_size = 1 << w;
        let iden = CurvePoint::identity(bld);

        let mut table = Vec::with_capacity(table_size);
        table.push(iden);

        // 1. Precompute basis points P_j = frob^j(P)
        let mut basis_points = Vec::with_capacity(w);
        basis_points.push(*p); // basis_points[0] = P = frob^0(P)
        for _ in 1..w {
            let next_p = emit_point_frob(bld, basis_points.last().unwrap());
            basis_points.push(next_p);
        }

        // 2. Build the full table iteratively
        for (k, basis_point_i) in basis_points.iter().enumerate().take(w) {
            let current_size = 1 << k;

            // For each point already in the table, compute a new point by adding the k-th basis point.
            // This extends the table from size `current_size` to `2 * current_size`.
            for i in 0..current_size {
                let new_point = Template::emit_point_add_custom(bld, &table[i], basis_point_i);
                table.push(new_point);
            }
        }

        table
    }

    // #[cfg(test)]
    // mod test {
    //     use std::time::Instant;
    //
    //     use super::super::super::{
    //         builder::CircuitTrait,
    //         curve_ref::{point_add, point_frob},
    //     };
    //     use num_bigint::{BigUint, RandomBits};
    //     use num_traits::FromPrimitive;
    //     use rand::Rng;
    //
    //     use super::super::super::{
    //         builder::CircuitAdapter,
    //         curve_ckt::CurvePoint,
    //         curve_ref::CurvePointRef as InnerPointRef,
    //         // point_scalar_mul::precompute_table,
    //         curve_scalar_mul_ckt::precompute_table::emit_lookup,
    //         gf_ref::{gfref_mul, gfref_to_bits},
    //     };
    //
    //     use super::emit_precompute_table;
    //
    //     pub(crate) fn ref_precompute_table(p: &InnerPointRef, w: usize) -> Vec<InnerPointRef> {
    //         let table_size = 1 << w;
    //
    //         if w == 0 {
    //             // For a 0-bit window, the table only contains the identity point.
    //             return vec![InnerPointRef::identity()];
    //         }
    //
    //         let mut table = Vec::with_capacity(table_size);
    //         table.push(InnerPointRef::identity());
    //
    //         // 1. Precompute basis points P_j = frob^j(P)
    //         let mut basis_points = Vec::with_capacity(w);
    //         basis_points.push(p.clone()); // basis_points[0] = P = frob^0(P)
    //         for _ in 1..w {
    //             // basis_points[i] = frob(basis_points[i-1])
    //             let next_p = point_frob(basis_points.last().unwrap());
    //             basis_points.push(next_p);
    //         }
    //
    //         // 2. Build the full table iteratively
    //         for (k, basis_point) in basis_points.iter().enumerate().take(w) {
    //             let current_size = 1 << k;
    //
    //             // For each point already in the table, compute a new point by adding the k-th basis point.
    //             // This extends the table from size `current_size` to `2 * current_size`.
    //             for i in 0..current_size {
    //                 let new_point = point_add(&table[i], basis_point);
    //                 table.push(new_point);
    //             }
    //         }
    //
    //         table
    //     }
    //
    //     #[test]
    //     fn test_emit_precompute_table() {
    //         let w = 2;
    //         let pt_ref = InnerPointRef::generator();
    //         let tables_ref = ref_precompute_table(&pt_ref, w);
    //
    //         let mut bld = CircuitAdapter::default();
    //         let pt_gen = CurvePoint::generator(&mut bld);
    //
    //         let mut witness = Vec::<bool>::new();
    //         for pt in [pt_ref.x, pt_ref.s, pt_ref.z, pt_ref.t] {
    //             let pt_bits = gfref_to_bits(&pt);
    //             witness.extend_from_slice(&pt_bits);
    //         }
    //
    //         let st = Instant::now();
    //         let tables_ckt = emit_precompute_table(&mut bld, &pt_gen, w);
    //         let el = st.elapsed();
    //         bld.show_gate_counts();
    //         println!("emit_precompute_table took {} seconds ", el.as_secs());
    //         assert_eq!(tables_ref.len(), tables_ckt.len());
    //
    //         let wires = bld.eval_gates(&witness);
    //
    //         for i in 0..tables_ref.len() {
    //             let ckt_x: Vec<bool> = tables_ckt[i].x.iter().map(|id| wires[*id]).collect();
    //             let ref_x: Vec<bool> = gfref_to_bits(&tables_ref[i].x).to_vec();
    //             assert_eq!(ckt_x, ref_x);
    //             let ckt_x: Vec<bool> = tables_ckt[i].s.iter().map(|id| wires[*id]).collect();
    //             let ref_x: Vec<bool> = gfref_to_bits(&tables_ref[i].s).to_vec();
    //             assert_eq!(ckt_x, ref_x);
    //             let ckt_x: Vec<bool> = tables_ckt[i].z.iter().map(|id| wires[*id]).collect();
    //             let ref_x: Vec<bool> = gfref_to_bits(&tables_ref[i].z).to_vec();
    //             assert_eq!(ckt_x, ref_x);
    //             let ckt_x: Vec<bool> = tables_ckt[i].t.iter().map(|id| wires[*id]).collect();
    //             let ref_x: Vec<bool> = gfref_to_bits(&tables_ref[i].t).to_vec();
    //             assert_eq!(ckt_x, ref_x);
    //         }
    //     }
    //
    //     #[test]
    //     fn test_emit_lookup_table() {
    //         fn random_point() -> InnerPointRef {
    //             let mut rng = rand::thread_rng();
    //             let x = rng.sample(RandomBits::new(232));
    //             let s = rng.sample(RandomBits::new(232));
    //             let z = rng.sample(RandomBits::new(232));
    //
    //             let t = gfref_mul(&x, &z);
    //
    //             InnerPointRef { x, s, z, t }
    //         }
    //
    //         let window = 5;
    //
    //         let table_len = 1 << window;
    //         let mut tables_ref = Vec::with_capacity(table_len);
    //         let mut tables_ckt = Vec::with_capacity(table_len);
    //
    //         let mut bld = CircuitAdapter::default();
    //
    //         let mut rng = rand::thread_rng();
    //         let lookup_index: u8 = rng.r#gen::<u8>() as u8 % table_len as u8;
    //         let lookup_index_bits = gfref_to_bits(&BigUint::from_u8(lookup_index).unwrap());
    //         let lookup_index_bits = lookup_index_bits[0..window].to_vec();
    //
    //         println!("lookup_index_bits {:?} and lookup index {}", lookup_index_bits, lookup_index);
    //         let mut witness = Vec::<bool>::new();
    //         let mut lookup_index_bit_labels = vec![];
    //         for bit in lookup_index_bits.iter().take(window) {
    //             lookup_index_bit_labels.push(bld.fresh_one());
    //             witness.push(*bit);
    //         }
    //
    //         for _ in 0..table_len {
    //             let rt = random_point();
    //             tables_ref.push(rt.clone());
    //
    //             let x = gfref_to_bits(&rt.x);
    //             let s = gfref_to_bits(&rt.s);
    //             let z = gfref_to_bits(&rt.z);
    //             let t = gfref_to_bits(&rt.t);
    //
    //             let x = x.map(|xi| if xi { bld.one() } else { bld.zero() });
    //             let s = s.map(|xi| if xi { bld.one() } else { bld.zero() });
    //             let z = z.map(|xi| if xi { bld.one() } else { bld.zero() });
    //             let t = t.map(|xi| if xi { bld.one() } else { bld.zero() });
    //
    //             let pt = CurvePoint { x, s, z, t };
    //             tables_ckt.push(pt);
    //         }
    //
    //         let entry_bits = emit_lookup(&mut bld, &tables_ckt, lookup_index_bit_labels);
    //
    //         bld.show_gate_counts();
    //         let wires = bld.eval_gates(&witness);
    //         let ckt_x: Vec<bool> = entry_bits.x.iter().map(|id| wires[*id]).collect();
    //         let ckt_s: Vec<bool> = entry_bits.s.iter().map(|id| wires[*id]).collect();
    //         let ckt_z: Vec<bool> = entry_bits.z.iter().map(|id| wires[*id]).collect();
    //         let ckt_t: Vec<bool> = entry_bits.t.iter().map(|id| wires[*id]).collect();
    //
    //         for (i, table_i) in tables_ref.iter().enumerate() {
    //             let ref_x: Vec<bool> = gfref_to_bits(&table_i.x).to_vec();
    //             if i == lookup_index as usize {
    //                 assert_eq!(ckt_x, ref_x);
    //             } else {
    //                 assert_ne!(ckt_x, ref_x);
    //             }
    //             let ref_s: Vec<bool> = gfref_to_bits(&table_i.s).to_vec();
    //             if i == lookup_index as usize {
    //                 assert_eq!(ckt_s, ref_s);
    //             } else {
    //                 assert_ne!(ckt_s, ref_s);
    //             }
    //             let ref_z: Vec<bool> = gfref_to_bits(&table_i.z).to_vec();
    //             if i == lookup_index as usize {
    //                 assert_eq!(ckt_z, ref_z);
    //             } else {
    //                 assert_ne!(ckt_z, ref_z);
    //             }
    //             let ref_t: Vec<bool> = gfref_to_bits(&table_i.t).to_vec();
    //             if i == lookup_index as usize {
    //                 assert_eq!(ckt_t, ref_t);
    //             } else {
    //                 assert_ne!(ckt_t, ref_t);
    //             }
    //         }
    //     }
    // }
}

/// Windowed tau-adic point scalar multiplication
// TODO: Use PRTNAF for lower gate counts
pub(crate) mod point_scalar_mul {
    use super::super::{
        builder::{CircuitTrait, Template},
        curve_ckt::{CurvePoint, emit_point_frob},
        fr_ckt::Fr,
    };

    use super::{
        TAU_ADIC_LEN,
        precompute_table::{emit_lookup, emit_precompute_table},
        tau_adic_repr::emit_tau_adic_repr_bits,
    };

    pub(crate) fn emit_mul_windowed_tau<T: CircuitTrait>(
        bld: &mut T,
        k: &Fr,
        point_p: &CurvePoint,
        w: usize,
    ) -> CurvePoint {
        let mut tau_bits = emit_tau_adic_repr_bits(bld, k);
        tau_bits.reverse(); // start from msb

        let table = emit_precompute_table(bld, point_p, w);

        let mut r = CurvePoint::identity(bld);

        for i in (0..TAU_ADIC_LEN).step_by(w) {
            for _ in 0..w {
                r = emit_point_frob(bld, &r);
            }

            let mut lidx = tau_bits[i..i + w].to_vec();
            lidx.reverse(); // into little endian form undoes `tau_bits.reverse()`, tau_bits itself was in little-endian when received as input

            let q = emit_lookup(bld, &table, lidx);

            r = Template::emit_point_add_custom(bld, &r, &q);
        }
        r
    }

    // #[cfg(test)]
    // mod test {
    //     use std::time::Instant;
    //
    //     use num_bigint::{BigUint, RandomBits};
    //     use rand::Rng;
    //
    //     use super::super::super::builder::{CircuitAdapter, CircuitTrait};
    //     use super::super::super::curve_ref::CurvePointRef as InnerPointRef;
    //     use super::super::super::curve_ref::point_scalar_multiplication;
    //     use super::super::super::fr_ref::frref_to_bits;
    //     use super::super::super::gf_ref::{bits_to_gfref, gfref_to_bits};
    //     use super::*;
    //
    //     // ignore because of long running test
    //     #[test]
    //     #[ignore]
    //     fn test_msm() {
    //         let window = 5;
    //         let gref = InnerPointRef::generator();
    //
    //         let mut rng = rand::thread_rng();
    //         let k: BigUint = rng.sample(RandomBits::new(231));
    //
    //         let out_ref = point_scalar_multiplication(&k, &gref);
    //
    //         // +++++++++++
    //         let mut bld = CircuitAdapter::default();
    //         let mut witness = Vec::<bool>::new();
    //
    //         let kwitness = frref_to_bits(&k);
    //         let ptwitness: Vec<bool> = [&gref.x, &gref.s, &gref.z, &gref.t]
    //             .iter()
    //             .flat_map(|k| {
    //                 let kb: Vec<bool> = gfref_to_bits(k).to_vec();
    //                 kb
    //             })
    //             .collect();
    //
    //         let klabels: Fr = bld.fresh();
    //         let ptlabels: CurvePoint =
    //             CurvePoint { x: bld.fresh(), s: bld.fresh(), z: bld.fresh(), t: bld.fresh() };
    //
    //         witness.extend_from_slice(&kwitness);
    //         witness.extend_from_slice(&ptwitness);
    //
    //         println!("emit_mul_windowed_tau");
    //         let st = Instant::now();
    //
    //         let out_bits = emit_mul_windowed_tau(&mut bld, &klabels, &ptlabels, window);
    //
    //         let st = st.elapsed();
    //         println!("emit_mul_windowed_tau took {} seconds", st.as_secs());
    //
    //         // bld.write_bristol_periodic("psm4.bristol").unwrap(); // uncomment if you want to dump to bristol file
    //
    //         bld.show_gate_counts();
    //
    //         let wires = bld.eval_gates(&witness);
    //
    //         println!("validating input witness");
    //         let kwitness_calc: Vec<bool> = klabels.iter().map(|id| wires[*id]).collect();
    //         let ptwitness_x: Vec<bool> = ptlabels.x.iter().map(|id| wires[*id]).collect();
    //         let ptwitness_s: Vec<bool> = ptlabels.s.iter().map(|id| wires[*id]).collect();
    //         let ptwitness_z: Vec<bool> = ptlabels.z.iter().map(|id| wires[*id]).collect();
    //         let ptwitness_t: Vec<bool> = ptlabels.t.iter().map(|id| wires[*id]).collect();
    //         let pwitness_calc: Vec<bool> = vec![ptwitness_x, ptwitness_s, ptwitness_z, ptwitness_t]
    //             .into_iter()
    //             .flatten()
    //             .collect();
    //         assert_eq!(kwitness_calc, kwitness);
    //         assert_eq!(pwitness_calc, ptwitness);
    //
    //         println!("validating output");
    //         let ckt_x = out_bits.x.map(|id| wires[id]);
    //         let ckt_s = out_bits.s.map(|id| wires[id]);
    //         let ckt_z = out_bits.z.map(|id| wires[id]);
    //         let ckt_t = out_bits.t.map(|id| wires[id]);
    //
    //         let ckt_out = InnerPointRef {
    //             x: bits_to_gfref(&ckt_x),
    //             s: bits_to_gfref(&ckt_s),
    //             z: bits_to_gfref(&ckt_z),
    //             t: bits_to_gfref(&ckt_t),
    //         };
    //
    //         assert_eq!(ckt_out, out_ref);
    //     }
    // }
}
