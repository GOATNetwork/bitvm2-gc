use crate::{
    dv_bn254::{fp254impl::Fp254Impl},
    circuits::bn254::utils::create_rng
};
use ark_ff::{AdditiveGroup, UniformRand};
use num_bigint::BigUint;
use crate::circuits::sect233k1::builder::CircuitTrait;
use crate::dv_bn254::basic::not;
use crate::dv_bn254::bigint::U254;

pub const FR_LEN: usize = 254;
#[derive(Debug, Clone)]
pub struct Fr(pub [usize; FR_LEN]);

impl Fp254Impl for Fr {
    const MODULUS: &'static str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";
    const MONTGOMERY_M_INVERSE: &'static str =
        "5441563794177615591428663161977496376097281981129373443346157590346630955009";
    const MONTGOMERY_R_INVERSE: &'static str =
        "17773755579518009376303681366703133516854333631346829854655645366227550102839";
    const N_BITS: usize = 254;

    fn half_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fr::from(1) / ark_bn254::Fr::from(2))
    }

    fn one_third_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fr::from(1) / ark_bn254::Fr::from(3))
    }
    fn two_third_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fr::from(2) / ark_bn254::Fr::from(3))
    }

    fn neg<T: CircuitTrait>(bld: &mut T, a: &[usize]) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);
        let mut not_a =  Vec::new();
        for i in 0..Self::N_BITS {
            not_a.push(not(bld, a[i]));
        }

        let wires = Self::add_constant(
            bld,
            &not_a,
            ark_bn254::Fr::from(1) - ark_bn254::Fr::from(Self::not_modulus_as_biguint()),
        );
        wires
    }
}

impl Fr {
    pub fn as_montgomery(a: ark_bn254::Fr) -> ark_bn254::Fr {
        a * ark_bn254::Fr::from(Self::montgomery_r_as_biguint())
    }

    pub fn from_montgomery(a: ark_bn254::Fr) -> ark_bn254::Fr {
        a / ark_bn254::Fr::from(Self::montgomery_r_as_biguint())
    }

    pub fn random() -> ark_bn254::Fr {
        let mut prng = create_rng();
        ark_bn254::Fr::rand(&mut prng)
    }

    pub fn to_bits(u: ark_bn254::Fr) -> Vec<bool> {
        let mut bytes = BigUint::from(u).to_bytes_le();
        bytes.extend(vec![0_u8; 32 - bytes.len()]);
        let mut bits = Vec::new();
        for byte in bytes {
            for i in 0..8 {
                bits.push(((byte >> i) & 1) == 1)
            }
        }
        bits.pop();
        bits.pop();
        bits
    }

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::Fr {
        let zero = BigUint::ZERO;
        let one = BigUint::from(1_u8);
        let mut u = zero.clone();
        for bit in bits.iter().rev() {
            u = u.clone() + u.clone() + if *bit { one.clone() } else { zero.clone() };
        }
        ark_bn254::Fr::from(u)
    }

    pub fn wires<T: CircuitTrait>(bld: &mut T) -> Self {
        let inner: [usize; FR_LEN] = bld.fresh();
        Self(inner)
    }

    pub fn wires_set<T: CircuitTrait>(bld: &mut T, u: ark_bn254::Fr) -> Self {
        let inner = Self::to_bits(u)[0..Self::N_BITS]
            .iter()
            .map(|bit| {
                if *bit {
                    bld.one()
                } else {
                    bld.zero()
                }
            })
            .collect::<Vec<usize>>();
        Self(inner.try_into().unwrap())
    }
    pub fn wires_set_montgomery<T: CircuitTrait>(bld: &mut T, u: ark_bn254::Fr) -> Self {
        Self::wires_set(bld, Self::as_montgomery(u))
    }

    pub fn from_wires<T: CircuitTrait>(bld: &mut T, fr: Fr) -> ark_bn254::Fr {
        Self::from_bits(fr.0.iter().map(|wire| {
            if *wire != bld.one() || *wire != bld.zero() {
                panic!("wire value is not set properly");
            }
            *wire == bld.one()
        }).collect())
    }

    pub fn from_montgomery_wires<T: CircuitTrait>(bld: &mut T, fr: Fr) -> ark_bn254::Fr {
        Self::from_montgomery(Self::from_wires(bld, fr))
    }

    // ───────────────────  a ≥ c   (one wire, MSB first)  ─────────────────────
    //  Gate cost: 4·W XOR + 3·W AND
    pub(crate) fn ge_unsigned<T: CircuitTrait>(bld: &mut T, a: &[usize], c: &[usize]) -> usize {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(c.len(), Self::N_BITS);
        let w = a.len();
        let mut gt = bld.zero();
        let mut eq = bld.one();
        for i in (0..w).rev() {
            let ai = a[i];
            let bi = c[i];
            let m0 = not(bld, bi);
            let ai_gt_bi = bld.and_wire(ai, m0);
            //let _m1 = not(b, ai);
            //let ai_lt_bi = b.and_wire(m1, bi);
            let m2 = bld.and_wire(eq, ai_gt_bi);
            gt = bld.or_wire(gt, m2);
            let m3 = bld.xor_wire(ai, bi);
            let m4 = not(bld, m3);
            eq = bld.and_wire(eq, m4); // keep eq flag
        }
        bld.or_wire(gt, eq) // ge = gt ∨ eq
    }

    fn add_constant<T: CircuitTrait>(bld: &mut T, a: &[usize], b: ark_bn254::Fr) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);
        if b == ark_bn254::Fr::ZERO {
            return a.to_vec();
        }

        let mut wires_1 = U254::add_constant(bld, a, &BigUint::from(b));
        let u = wires_1.pop().unwrap();
        let c = Self::not_modulus_as_biguint();
        let mut wires_2 = U254::add_constant(bld, &wires_1, &c);
        wires_2.pop();
        let v = U254::less_than_constant(bld, &wires_1, &Self::modulus_as_biguint());

        // Ncimp
        let not_a = not(bld, u);
        let s = bld.and_wire(not_a, v);
        U254::select(bld, &wires_1, &wires_2, s)
    }

}

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn test_fr_random() {
//         let u = Fr::random();
//         println!("u: {:?}", u);
//         let b = Fr::to_bits(u);
//         let v = Fr::from_bits(b);
//         println!("v: {:?}", v);
//         assert_eq!(u, v);
//     }
// }
