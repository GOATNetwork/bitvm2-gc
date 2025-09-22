//! Reference implementation for curve operations.
//! The following functions do not assume binary circuit representation and are used
//! only to validate their respective implementation in binary circuit through tests

#![cfg(test)]
use std::{os::raw::c_void, str::FromStr};

use num_bigint::BigUint;
use num_traits::One;
use num_traits::ToPrimitive;
#[cfg(feature = "verify")]
use xs233_sys::{xsk233_neutral, xsk233_point};

use super::curve_ckt::CompressedCurvePointRef;
use super::gf_ref::gfref_square;
use super::gf_ref::{GfRef, gfref_add, gfref_mul, gfref_one};

/// A point on the xsk233 curve in internal representation
#[derive(Debug, Clone)]
pub(crate) struct CurvePointRef {
    pub x: GfRef,
    pub s: GfRef,
    pub z: GfRef,
    pub t: GfRef,
}

impl CurvePointRef {
    /// Create a new point with zero values
    pub(crate) fn new() -> Self {
        CurvePointRef { x: GfRef::ZERO, s: GfRef::ZERO, z: GfRef::ZERO, t: GfRef::ZERO }
    }

    /// Returns the identity element (point at infinity) of the curve.
    /// The exact representation depends on the coordinate system.
    /// For projective coordinates (X, S, Z), it's often (0, 1, 0).
    pub(crate) fn identity() -> Self {
        CurvePointRef {
            x: GfRef::ZERO,
            s: gfref_one(), // Or Y=1
            z: gfref_one(),
            t: GfRef::ZERO, // Often X*Z = 0 for identity
        }
    }

    pub(crate) fn generator() -> Self {
        CurvePointRef {
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
        }
    }

    // Decode from extern crate point type `xsk233_point`
    #[cfg(feature = "verify")]
    pub(crate) fn from_xsk233_point(w: &xsk233_point) -> CurvePointRef {
        let w = w.opaque;
        fn from_limbs(limbs: &[u64]) -> BigUint {
            // limb0..2 are 58‑bit, limb3 is 59‑bit
            let limb0 = BigUint::from(limbs[0]); // bits 0‥57
            let limb1 = BigUint::from(limbs[1]) << 58; // bits 58‥115
            let limb2 = BigUint::from(limbs[2]) << 116; // bits 116‥173
            let limb3 = BigUint::from(limbs[3]) << 174; // bits 174‥232 (≤59 bits)

            limb0 | limb1 | limb2 | limb3
        }

        let x = from_limbs(&w[0..4]);
        let s = from_limbs(&w[4..8]);
        let z = from_limbs(&w[8..12]);
        let t = from_limbs(&w[12..16]);

        CurvePointRef { x, s, z, t }
    }

    /// Decode from byte representation of compressed curve point
    #[cfg(feature = "verify")]
    pub(crate) fn from_compressed_point(src: &CompressedCurvePointRef) -> (Self, bool) {
        unsafe {
            let mut src = *src;
            let mut pt2 = xsk233_neutral;
            let success = xs233_sys::xsk233_decode(&mut pt2, src.as_mut_ptr() as *mut c_void);
            let pt_ref = Self::from_xsk233_point(&pt2);
            (pt_ref, success != 0)
        }
    }

    #[cfg(feature = "verify")]
    pub(crate) fn to_xsk233_point(&self) -> xsk233_point {
        fn to_limbs(b: &BigUint) -> [u64; 4] {
            debug_assert!(b.bits() <= 233, "coordinate exceeds 233 bits");

            // masks: 58-bit and 59-bit
            let mask58 = (&BigUint::one() << 58) - 1u32;
            let mask59 = (&BigUint::one() << 59) - 1u32;

            let limb0 = b & &mask58;
            let limb0 = limb0.to_u64().unwrap();
            let limb1: BigUint = (b >> 58) & &mask58;
            let limb1 = limb1.to_u64().unwrap();
            let limb2: BigUint = (b >> 116) & &mask58;
            let limb2 = limb2.to_u64().unwrap();
            let limb3: BigUint = (b >> 174) & &mask59;
            let limb3 = limb3.to_u64().unwrap(); // already ≤ 59 bits

            [limb0, limb1, limb2, limb3]
        }
        assert!(
            self.x.bits() <= 233
                || self.s.bits() <= 233
                || self.z.bits() <= 233
                || self.t.bits() <= 233
        );

        let mut w = [0u64; 16];

        // x │ s │ z │ t   – each contributes 4 limbs
        w[0..4].copy_from_slice(&to_limbs(&self.x));
        w[4..8].copy_from_slice(&to_limbs(&self.s));
        w[8..12].copy_from_slice(&to_limbs(&self.z));
        w[12..16].copy_from_slice(&to_limbs(&self.t));

        xsk233_point { opaque: w }
    }
}

impl PartialEq for CurvePointRef {
    fn eq(&self, other: &Self) -> bool {
        point_equals(self, other)
    }
}

pub(crate) fn point_equals(p1: &CurvePointRef, p2: &CurvePointRef) -> bool {
    // tmp1 = S₁·T₂
    let tmp1: GfRef = gfref_mul(&p1.s, &p2.t);

    // tmp2 = S₂·T₁
    let tmp2: GfRef = gfref_mul(&p2.s, &p1.t);

    tmp1 == tmp2
}

/// Inner addition function on xsk233 curve.
///
/// Performs point addition: p3 = p1 + p2
pub(crate) fn point_add(p1: &CurvePointRef, p2: &CurvePointRef) -> CurvePointRef {
    let mut p3 = CurvePointRef::new();
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
    let x1x2 = gfref_mul(&p1.x, &p2.x);
    let s1s2 = gfref_mul(&p1.s, &p2.s);
    let z1z2 = gfref_mul(&p1.z, &p2.z);

    // Step 2: Calculate d = (S1 + T1)*(S2 + T2)
    let tmp1 = gfref_add(&p1.s, &p1.t);
    let tmp2 = gfref_add(&p2.s, &p2.t);
    let d = gfref_mul(&tmp1, &tmp2);

    // Step 3: Calculate squares
    let f = gfref_square(&x1x2);
    let g = gfref_square(&z1z2);

    // Step 4: Calculate output coordinates
    p3.x = gfref_add(&d, &s1s2);

    let tmp1 = gfref_mul(&s1s2, &g);
    let tmp2 = gfref_mul(&d, &f);
    p3.s = gfref_add(&tmp1, &tmp2);

    p3.z = gfref_add(&f, &g);
    p3.t = gfref_mul(&p3.x, &p3.z);
    p3
}

/// Apply the Frobenius endomorphism on a point (i.e. square all coordinates).
///
/// Squares all coordinates of a xsk233 curve point.
pub(crate) fn point_frob(p1: &CurvePointRef) -> CurvePointRef {
    let mut p3 = CurvePointRef::new();
    // Square all coordinates
    p3.x = gfref_square(&p1.x);
    p3.z = gfref_square(&p1.z);
    p3.s = gfref_square(&p1.s);
    p3.t = gfref_square(&p1.t);
    p3
}

#[cfg(feature = "verify")]
pub(crate) fn point_scalar_multiplication(k: &GfRef, point_p: &CurvePointRef) -> CurvePointRef {
    fn fr_to_le_bytes(fr: &BigUint) -> Vec<u8> {
        let limbs = fr.to_u64_digits();

        let mut bytes = Vec::with_capacity(32);
        for limb in limbs.iter() {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
        bytes.truncate(30);

        // remove trailing zeros
        // helps reduce iteration in double-and-add iterations
        while let Some(&last) = bytes.last() {
            if last == 0 {
                bytes.pop();
            } else {
                break;
            }
        }
        bytes
    }

    unsafe {
        let mut by_mul = xs233_sys::xsk233_neutral;
        let scalar = fr_to_le_bytes(k);
        let nptc = point_p.to_xsk233_point();
        xs233_sys::xsk233_mul(&mut by_mul, &nptc, scalar.as_ptr() as *const _, scalar.len());
        CurvePointRef::from_xsk233_point(&by_mul)
    }
}

#[cfg(all(test, feature = "verify"))]
mod xsys_test {
    use std::str::FromStr;

    use crate::circuits::sect233k1::{
        curve_ref::{CurvePointRef, point_add, point_scalar_multiplication},
        gf_ref::gfref_mul,
    };

    // Creates a random point ensuring T = X*Z
    fn random_point() -> CurvePointRef {
        let mut rng = rand::thread_rng();
        let x = rng.sample(RandomBits::new(232));
        let s = rng.sample(RandomBits::new(232));
        let z = rng.sample(RandomBits::new(232));

        let t = gfref_mul(&x, &z);

        CurvePointRef { x, s, z, t }
    }

    use num_bigint::{BigUint, RandomBits};
    use num_traits::FromPrimitive;
    use rand::Rng;
    use xs233_sys::xsk233_equals;

    #[test]
    fn test_point_add() {
        unsafe {
            let pt = CurvePointRef {
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

            let ptadd = point_add(&pt, &pt2);

            let npt = pt.to_xsk233_point();

            let npt2 = pt2.to_xsk233_point();

            let mut nptadd: xs233_sys::xsk233_point = xs233_sys::xsk233_neutral;
            // println!("nptiden {:?}", nptadd);
            // println!("nptiden {:?}", encode_inner_point_to_xs_opq(&InnerPoint::identity()));
            xs233_sys::xsk233_add(&mut nptadd, &npt, &npt2);

            assert_eq!(nptadd.opaque, ptadd.to_xsk233_point().opaque);
        }
    }

    #[test]
    fn test_point_scalar_mul() {
        unsafe {
            let genr = xs233_sys::xsk233_generator;

            let nptc = genr;
            let nptc2 = genr;
            let nptc3 = genr;

            let mut nptadd: xs233_sys::xsk233_point = xs233_sys::xsk233_neutral;
            xs233_sys::xsk233_add(&mut nptadd, &nptc2, &nptc3);

            let mut scalar = [0u8; 30];
            scalar[0] = 2; // little-endian 2

            let mut by_mul = xs233_sys::xsk233_neutral;
            xs233_sys::xsk233_mul(&mut by_mul, &nptc, scalar.as_ptr() as *const _, scalar.len());

            let res = xs233_sys::xsk233_equals(&by_mul, &nptadd);

            assert!(res != 0);
        }
    }

    #[test]
    fn test_point_scalar_mul2() {
        unsafe {
            let genr = xs233_sys::xsk233_generator;

            // For point addition (doubling)
            let p1 = genr;
            let p2 = genr;
            let mut result_add = xs233_sys::xsk233_neutral;
            xs233_sys::xsk233_add(&mut result_add, &p1, &p2);

            // For scalar multiplication by 2
            let mut scalar = [0u8; 30];
            scalar[0] = 2; // little-endian representation of 2
            let mut result_mul = xs233_sys::xsk233_neutral;
            xs233_sys::xsk233_mul(
                &mut result_mul,
                &genr,
                scalar.as_ptr() as *const _,
                scalar.len(),
            );

            // Instead of comparing raw bytes, verify points are equivalent
            // by checking if result_add - result_mul = neutral point
            let mut neg_result_mul = result_mul;
            xs233_sys::xsk233_neg(&mut neg_result_mul, &result_mul);

            let mut difference = xs233_sys::xsk233_neutral;
            xs233_sys::xsk233_add(&mut difference, &result_add, &neg_result_mul);

            // Check if difference is the neutral point
            let is_neutral = xs233_sys::xsk233_is_neutral(&difference);
            assert!(is_neutral != 0);
        }
    }

    #[test]
    fn test_point_scalar_mul3() {
        unsafe {
            let pt = CurvePointRef {
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

            let mut scalar = [0u8; 30];
            scalar[0] = 2;
            scalar[1] = 1; // little-endian 2

            // let result = &mut InnerPoint::identity();
            // simple_scalar_mul_koblitz_frob(result, &pt, &scalar);
            // let result = xs233_sys::xsk233_point { opaque: encode_inner_point_to_xs_opq(&result)};

            let result2 = point_scalar_multiplication(&BigUint::from_u64(258u64).unwrap(), &pt);
            let result2 = result2.to_xsk233_point();

            let npt = pt.to_xsk233_point();

            let mut by_mul = xs233_sys::xsk233_neutral;
            xs233_sys::xsk233_mul(&mut by_mul, &npt, scalar.as_ptr() as *const _, scalar.len());

            let res = xs233_sys::xsk233_equals(&by_mul, &result2);
            assert!(res != 0);
        }
    }

    #[test]
    fn test_random_point() {
        let _rng = rand::thread_rng();
        //let x: BigUint = rng.sample(RandomBits::new(232));
        let scalar: u8 = 4; //rng.gen();
        let _x = BigUint::from_u8(scalar).unwrap();
        let pt = CurvePointRef::identity();

        // // // point double and add
        // let mut yd =  InnerPoint::identity();
        // let xb = x.to_bytes_be();
        // simple_scalar_mul_koblitz_frob(&mut yd, &pt, &xb);

        // // repeated addition
        // let mut ydd = pt.clone();
        // for _ in 0..scalar-1 {
        //     println!("ydd {:?}", ydd);
        //     ydd = point_add(&ydd, &pt);
        // }
        let ref_pt = pt.clone();
        let ref_pt = point_add(&ref_pt, &pt);
        let ref_pt = point_add(&ref_pt, &pt);
        let _ref_pt = point_add(&ref_pt, &pt);

        let _ref_pt2 = point_add(&point_add(&pt, &pt), &point_add(&pt, &pt));
        // let matches = point_sub(&ref_pt, &ref_pt2);
        // assert_eq!(matches, ref_pt);
        // println!("ydd {:?}", ydd);
        // println!("ref {:?}", ref_pt);

        unsafe {
            let c_pt = xs233_sys::xsk233_generator;
            let mut ref_cpt = xs233_sys::xsk233_neutral;

            xs233_sys::xsk233_add(&mut ref_cpt, &ref_cpt, &c_pt); // 0 + p
            xs233_sys::xsk233_add(&mut ref_cpt, &ref_cpt, &c_pt); // p + p
            xs233_sys::xsk233_add(&mut ref_cpt, &ref_cpt, &c_pt); // 2p + p
            xs233_sys::xsk233_add(&mut ref_cpt, &ref_cpt, &c_pt); // 3p + p

            let mut tr1 = xs233_sys::xsk233_neutral;
            let mut tr2 = xs233_sys::xsk233_neutral;
            let mut ref_cpt2 = xs233_sys::xsk233_neutral;
            xs233_sys::xsk233_add(&mut tr1, &c_pt, &c_pt); // p + p
            xs233_sys::xsk233_add(&mut tr2, &c_pt, &c_pt); // p + p
            xs233_sys::xsk233_add(&mut ref_cpt2, &tr1, &tr2); // 2p + 2p

            assert_ne!(xsk233_equals(&ref_cpt2, &ref_cpt), 0);
        }
    }

    #[test]
    fn test_point_gen() {
        unsafe {
            let c_pt = xs233_sys::xsk233_generator;

            let mut ref_cpt = xs233_sys::xsk233_neutral;

            xs233_sys::xsk233_add(&mut ref_cpt, &ref_cpt, &c_pt); // 0 + p
            xs233_sys::xsk233_add(&mut ref_cpt, &ref_cpt, &c_pt); // p + p
            xs233_sys::xsk233_add(&mut ref_cpt, &ref_cpt, &c_pt); // 2p + p
            xs233_sys::xsk233_add(&mut ref_cpt, &ref_cpt, &c_pt); // 3p + p

            let mut tr1 = xs233_sys::xsk233_neutral;
            let mut tr2 = xs233_sys::xsk233_neutral;
            let mut ref_cpt2 = xs233_sys::xsk233_neutral;
            xs233_sys::xsk233_add(&mut tr1, &c_pt, &c_pt); // p + p
            xs233_sys::xsk233_add(&mut tr2, &c_pt, &c_pt); // p + p
            xs233_sys::xsk233_add(&mut ref_cpt2, &tr1, &tr2); // 2p + 2p

            assert!(xsk233_equals(&ref_cpt2, &ref_cpt) == 0xffffffff);
        }

        unsafe {
            let genr = CurvePointRef::generator();
            let genr = genr.to_xsk233_point();

            let gen2 = xs233_sys::xsk233_generator;
            assert!(xsk233_equals(&genr, &gen2) == 0xffffffff);
        }
    }
}
