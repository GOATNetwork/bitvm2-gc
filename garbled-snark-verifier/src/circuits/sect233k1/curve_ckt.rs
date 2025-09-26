//! Curve Point representation and operations are referenced from xs233-sys library

use std::str::FromStr;

use super::{
    builder::{CircuitTrait, GateOperation, Template},
    gf_ckt::{
        GF_LEN, Gf, emit_gf_add, emit_gf_decode, emit_gf_halftrace, emit_gf_inv, emit_gf_is_zero,
        emit_gf_square, emit_gf_trace,
    },
    gf_mul_ckt::emit_gf_mul,
};
use crate::circuits::sect233k1::builder::{CircuitAdapter, Operation};
use num_bigint::BigUint;

/// Representation of a point, on the xsk233 curve in projective co-ordinates, as wire labels
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub(crate) struct CurvePoint {
    pub x: Gf,
    pub s: Gf,
    pub z: Gf,
    pub t: Gf,
}

/// Size of a compressed Curve Point is 30 bytes
pub(crate) const COMPRESSED_POINT_LEN: usize = 30;
/// Representation of a compressed Curve Point as wire labels
pub(crate) type CompressedCurvePoint = [[usize; 8]; COMPRESSED_POINT_LEN];
/// Representation of a compressed curve point as 30 byte array
pub(crate) type CompressedCurvePointRef = [u8; COMPRESSED_POINT_LEN];

/// Wire labels representing base field element ZERO
fn gf_zero<T: CircuitTrait>(b: &mut T) -> Gf {
    let z = b.zero();
    [z; GF_LEN]
}

/// Wire labels representing base field element ONE
fn gf_one<T: CircuitTrait>(b: &mut T) -> Gf {
    let z = b.zero();
    let o = b.one();
    let mut zs = [z; GF_LEN];
    zs[0] = o; // lsb at 0 bit
    zs
}

/// Equality of CurvePoints
pub(crate) fn emit_point_equals<T: CircuitTrait>(
    bld: &mut T,
    p1: &CurvePoint,
    p2: &CurvePoint,
) -> usize {
    // tmp1 = S₁·T₂
    let tmp1: Gf = emit_gf_mul(bld, &p1.s, &p2.t);

    // tmp2 = S₂·T₁
    let tmp2: Gf = emit_gf_mul(bld, &p2.s, &p1.t);

    let mut or_res = bld.zero();
    tmp1.iter().zip(tmp2).for_each(|(a, b)| {
        let a_xor_b = bld.xor_wire(*a, b);
        or_res = bld.or_wire(a_xor_b, or_res);
    });
    let one = bld.one();

    bld.xor_wire(or_res, one)
}

impl CurvePoint {
    /// Returns the identity element (point at infinity) of the curve.
    pub(crate) fn identity<T: CircuitTrait>(bld: &mut T) -> Self {
        CurvePoint {
            x: gf_zero(bld),
            s: gf_one(bld), // Or Y=1
            z: gf_one(bld),
            t: gf_zero(bld), // Often X*Z = 0 for identity
        }
    }

    /// Generator, actual values referenced from xs233-sys lib
    pub(crate) fn generator<T: CircuitTrait>(bld: &mut T) -> Self {
        fn gfref_to_bits(n: &BigUint) -> [bool; 233] {
            let bytes = n.to_bytes_le();
            let mut bits = [false; 233];
            for i in 0..233 {
                let byte = if i / 8 < bytes.len() { bytes[i / 8] } else { 0 };
                let r = (byte >> (i % 8)) & 1;
                bits[i] = r != 0;
            }
            bits
        }

        let x = BigUint::from_str(
            "13283792768796718556929275469989697816663440403339868882741001477299174",
        )
        .unwrap();
        let s = BigUint::from_str(
            "6416386389908495168242210184454780244589215014363767030073322872085145",
        )
        .unwrap();
        let z = BigUint::from_str("1").unwrap();
        let t = BigUint::from_str(
            "13283792768796718556929275469989697816663440403339868882741001477299174",
        )
        .unwrap();

        let x = gfref_to_bits(&x);
        let s = gfref_to_bits(&s);
        let z = gfref_to_bits(&z);
        let t = gfref_to_bits(&t);

        let x = x.map(|xi| if xi { bld.one() } else { bld.zero() });
        let s = s.map(|xi| if xi { bld.one() } else { bld.zero() });
        let z = z.map(|xi| if xi { bld.one() } else { bld.zero() });
        let t = t.map(|xi| if xi { bld.one() } else { bld.zero() });

        CurvePoint { x, s, z, t }
    }
}

/// Add points in curve
pub(crate) fn emit_point_add<T: CircuitTrait>(
    bld: &mut T,
    p1: &CurvePoint,
    p2: &CurvePoint,
) -> CurvePoint {
    /*
     * x1x2 <- X1*X2
     * s1s2 <- S1*S2
     * z1z2 <- Z1*Z2
     * d <- (S1 + T1)*(S2 + T2)
     * f <- x1x2^2
     * g <- z1z2^2
     * X3 <- d + s1s2
     * S3 <- sqrt(b)*(g*s1s2 + f*d) note: sqrt(b) = 1 for xsk233
     * Z3 <- sqrt(b)*(f + g)
     * T3 <- X3*Z3
     */

    // Step 1: Calculate products
    let x1x2 = emit_gf_mul(bld, &p1.x, &p2.x);
    let s1s2 = emit_gf_mul(bld, &p1.s, &p2.s);
    let z1z2 = emit_gf_mul(bld, &p1.z, &p2.z);

    // Step 2: Calculate d = (S1 + T1)*(S2 + T2)
    let tmp1 = emit_gf_add(bld, &p1.s, &p1.t);
    let tmp2 = emit_gf_add(bld, &p2.s, &p2.t);
    let d = emit_gf_mul(bld, &tmp1, &tmp2);

    // Step 3: Calculate squares
    let f = emit_gf_square(bld, &x1x2);
    let g = emit_gf_square(bld, &z1z2);

    // Step 4: Calculate output coordinates
    let p3_x = emit_gf_add(bld, &d, &s1s2);

    let tmp1 = emit_gf_mul(bld, &s1s2, &g);
    let tmp2 = emit_gf_mul(bld, &d, &f);
    let p3_s = emit_gf_add(bld, &tmp1, &tmp2);

    let p3_z = emit_gf_add(bld, &f, &g);
    let p3_t = emit_gf_mul(bld, &p3_x, &p3_z);

    CurvePoint { x: p3_x, s: p3_s, z: p3_z, t: p3_t }
}

/// Apply the Frobenius endomorphism on a point (i.e. square all coordinates).
///
/// Squares all coordinates of a xsk233 curve point.
pub(crate) fn emit_point_frob<T: CircuitTrait>(bld: &mut T, p1: &CurvePoint) -> CurvePoint {
    // Square all coordinates
    let p3_x = emit_gf_square(bld, &p1.x);
    let p3_z = emit_gf_square(bld, &p1.z);
    let p3_s = emit_gf_square(bld, &p1.s);
    let p3_t = emit_gf_square(bld, &p1.t);
    CurvePoint { x: p3_x, s: p3_s, z: p3_z, t: p3_t }
}

/// Decodes a compressed curve point if valid
// Emits (decoded CurvePoint, validity_bit) where validity_bit is 0 if the input was invalid
pub(crate) fn emit_xsk233_decode<T: CircuitTrait>(
    bld: &mut T,
    src: &CompressedCurvePoint,
) -> (CurvePoint, usize) {
    let (w, ve) = emit_gf_decode(bld, src);
    let wz = emit_gf_is_zero(bld, w); //wz = w == 0

    let d = emit_gf_square(bld, &w); // d = w^2 + w
    let d = emit_gf_add(bld, &d, &w);
    let d_is_zero = emit_gf_is_zero(bld, d);
    let one = bld.one();
    let rp = bld.xor_wire(d_is_zero, one); //rp= d != 0

    let e = emit_gf_square(bld, &d); //e=d^-2
    let e = emit_gf_inv(bld, e);
    let etr = emit_gf_trace(bld, &e); // etr = Tr(e)
    let rp_tr = bld.xor_wire(etr, one);
    let rp = bld.and_wire(rp, rp_tr);

    let f = emit_gf_halftrace(bld, &e);

    let x = emit_gf_mul(bld, &d, &f);
    let xtr = emit_gf_trace(bld, &x);
    let rp_tr = bld.xor_wire(xtr, one);
    let rp = bld.and_wire(rp, rp_tr);

    let g = emit_gf_halftrace(bld, &x);

    let g = emit_gf_add(bld, &g, &w);
    let g = emit_gf_mul(bld, &g, &x);
    let g_tr = emit_gf_trace(bld, &g);
    let masked_d = {
        let mut tmp = [0; GF_LEN];
        for i in 0..GF_LEN {
            tmp[i] = bld.and_wire(d[i], g_tr);
        }
        tmp
    };
    let x = emit_gf_add(bld, &x, &masked_d);

    let s = emit_gf_square(bld, &w);
    let s = emit_gf_mul(bld, &s, &x);

    // condset
    let rp_or_wz = bld.or_wire(rp, wz);
    let success = bld.and_wire(ve, rp_or_wz);

    (CurvePoint { x, s, z: gf_one(bld), t: x }, success)
}

// Generate Circuit Configuration for Point Addition
pub(crate) fn template_emit_point_add() -> Template {
    println!("Initializing template_emit_point_add");
    let mut bld = CircuitAdapter::default();
    // define const wires
    let const_wire_zero = bld.zero();
    let const_wire_one = bld.one();
    let p1 = CurvePoint { x: bld.fresh(), s: bld.fresh(), z: bld.fresh(), t: bld.fresh() };
    let p2 = CurvePoint { x: bld.fresh(), s: bld.fresh(), z: bld.fresh(), t: bld.fresh() };
    // serialize wire labels in a known order
    // this same order is respected when these specific wire labels are later referenced
    // for evaluation or to generate instance of PointAdd Circuit
    let mut input_wires = vec![];
    input_wires.extend_from_slice(&p1.x);
    input_wires.extend_from_slice(&p1.s);
    input_wires.extend_from_slice(&p1.z);
    input_wires.extend_from_slice(&p1.t);

    input_wires.extend_from_slice(&p2.x);
    input_wires.extend_from_slice(&p2.s);
    input_wires.extend_from_slice(&p2.z);
    input_wires.extend_from_slice(&p2.t);

    let start_wire_idx = bld.next_wire();
    let res = emit_point_add(&mut bld, &p1, &p2);
    let end_wire_idx = bld.next_wire();

    let mut output_wires = vec![];
    output_wires.extend_from_slice(&res.x);
    output_wires.extend_from_slice(&res.s);
    output_wires.extend_from_slice(&res.z);
    output_wires.extend_from_slice(&res.t);

    let gates = bld.get_gates();

    let stats = {
        let mut temp_and_gates_count = 0;
        let mut temp_xor_gates_count = 0;
        let mut temp_or_gates_count = 0;
        for g in gates {
            if let GateOperation::Base(bg) = g {
                match bg {
                    Operation::Add(_, _, _) => {
                        temp_xor_gates_count += 1;
                    }
                    Operation::Mul(_, _, _) => {
                        temp_and_gates_count += 1;
                    }
                    Operation::Or(_, _, _) => {
                        temp_or_gates_count += 1;
                    }
                    _ => unreachable!(),
                }
            }
        }
        (temp_and_gates_count, temp_xor_gates_count, temp_or_gates_count)
    };

    Template {
        input_wires,
        output_wires,
        gates: gates.clone(),
        start_wire_idx,
        end_wire_idx,
        const_wire_one,
        const_wire_zero,
        stats,
    }
}

#[cfg(all(test, feature = "verify"))]
mod test {
    use std::{os::raw::c_void, str::FromStr, time::Instant};

    use crate::circuits::sect233k1::{
        builder::CircuitTrait,
        curve_ckt::{COMPRESSED_POINT_LEN, CompressedCurvePoint, emit_xsk233_decode},
        gf_ref::bits_to_gfref,
    };
    use num_bigint::{BigUint, RandomBits};
    use rand::Rng;
    use xs233_sys::xsk233_generator;

    use crate::circuits::sect233k1::{
        builder::CircuitAdapter,
        curve_ref::{CurvePointRef as InnerPointRef, point_add as ref_point_add},
        gf_ref::{gfref_mul, gfref_to_bits},
    };

    use super::{CurvePoint, emit_point_add};

    // Creates a random point ensuring T = X*Z
    fn random_point() -> InnerPointRef {
        let mut rng = rand::thread_rng();
        let max_bit_len = 232;
        let x = rng.sample(RandomBits::new(max_bit_len));
        let s = rng.sample(RandomBits::new(max_bit_len));
        let z = rng.sample(RandomBits::new(max_bit_len));

        let t = gfref_mul(&x, &z);

        InnerPointRef { x, s, z, t }
    }

    #[test]
    fn test_point_add() {
        let pt = InnerPointRef {
            x: BigUint::from_str(
                "13283792768796718556929275469989697816663440403339868882741001477299174",
            )
            .unwrap(),
            s: BigUint::from_str(
                "6416386389908495168242210184454780244589215014363767030073322872085145",
            )
            .unwrap(),
            z: BigUint::from_str("1").unwrap(),
            t: BigUint::from_str(
                "13283792768796718556929275469989697816663440403339868882741001477299174",
            )
            .unwrap(),
        };

        let pt2 = random_point();
        let ptadd = ref_point_add(&pt, &pt2);

        let mut bld = CircuitAdapter::default();
        let c_pt = CurvePoint { x: bld.fresh(), s: bld.fresh(), z: bld.fresh(), t: bld.fresh() };

        let c_pt2 = CurvePoint { x: bld.fresh(), s: bld.fresh(), z: bld.fresh(), t: bld.fresh() };

        let st = Instant::now();
        let c_ptadd = emit_point_add(&mut bld, &c_pt, &c_pt2);
        let el = st.elapsed();
        println!("emit_point_add took {} seconds to compile ", el.as_secs());
        let stats = bld.gate_counts();
        println!("{stats}");

        let mut witness = Vec::<bool>::with_capacity(233 * 8);
        witness.extend(gfref_to_bits(&pt.x));
        witness.extend(gfref_to_bits(&pt.s));
        witness.extend(gfref_to_bits(&pt.z));
        witness.extend(gfref_to_bits(&pt.t));

        witness.extend(gfref_to_bits(&pt2.x));
        witness.extend(gfref_to_bits(&pt2.s));
        witness.extend(gfref_to_bits(&pt2.z));
        witness.extend(gfref_to_bits(&pt2.t));

        let wires = bld.eval_gates(&witness);

        let c_ptadd_x = bits_to_gfref(&c_ptadd.x.map(|w_id| wires[w_id]));
        let c_ptadd_s = bits_to_gfref(&c_ptadd.s.map(|w_id| wires[w_id]));
        let c_ptadd_z = bits_to_gfref(&c_ptadd.z.map(|w_id| wires[w_id]));
        let c_ptadd_t = bits_to_gfref(&c_ptadd.t.map(|w_id| wires[w_id]));

        let c_ptadd_val = InnerPointRef { x: c_ptadd_x, s: c_ptadd_s, z: c_ptadd_z, t: c_ptadd_t };
        assert_eq!(c_ptadd_val, ptadd);
    }

    #[test]
    fn test_point_decode_roundtrip() {
        let mut bld = CircuitAdapter::default();

        let src = {
            let mut bytes = Vec::new();
            for _ in 0..COMPRESSED_POINT_LEN {
                let byte: [usize; 8] = bld.fresh();
                bytes.push(byte);
            }
            let bytes: CompressedCurvePoint = bytes.try_into().unwrap();
            bytes
        };
        let (c_ptadd, out_ok_label) = emit_xsk233_decode(&mut bld, &src);

        let witness = {
            unsafe {
                let pt = xsk233_generator;
                let mut dst = [0u8; COMPRESSED_POINT_LEN];
                xs233_sys::xsk233_encode(dst.as_mut_ptr() as *mut c_void, &pt);
                let mut wit = Vec::new();
                for d in dst {
                    let mut vs: Vec<bool> = (0..8).map(|i| (d >> i) & 1 != 0).collect();
                    wit.append(&mut vs);
                }
                wit
            }
        };

        let wires = bld.eval_gates(&witness);

        let c_ptadd_x = bits_to_gfref(&c_ptadd.x.map(|w_id| wires[w_id]));
        let c_ptadd_s = bits_to_gfref(&c_ptadd.s.map(|w_id| wires[w_id]));
        let c_ptadd_z = bits_to_gfref(&c_ptadd.z.map(|w_id| wires[w_id]));
        let c_ptadd_t = bits_to_gfref(&c_ptadd.t.map(|w_id| wires[w_id]));

        let c_ptadd_val = InnerPointRef { x: c_ptadd_x, s: c_ptadd_s, z: c_ptadd_z, t: c_ptadd_t };

        assert_eq!(c_ptadd_val, InnerPointRef::generator());

        let out_label = wires[out_ok_label];
        println!("out_label {}", out_label);
        assert!(out_label, "should be 1 for valid input");
        let stats = bld.gate_counts();
        println!("{stats}");
    }
}
