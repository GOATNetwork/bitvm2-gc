use crate::dv_bn254::bigint::U254;
use crate::circuits::bn254::utils::create_rng;
use crate::{dv_bn254::fp254impl::Fp254Impl};
use ark_ff::{AdditiveGroup, UniformRand};
use core::str::FromStr;
use num_bigint::BigUint;
use crate::circuits::sect233k1::builder::CircuitTrait;
use crate::dv_bn254::basic::not;

pub const FQ_LEN: usize = 254;
#[derive(Debug, Clone)]
pub struct Fq(pub [usize; FQ_LEN]);

impl Fp254Impl for Fq {
    const MODULUS: &'static str =
        "21888242871839275222246405745257275088696311157297823662689037894645226208583";
    const MONTGOMERY_M_INVERSE: &'static str =
        "4759646384140481320982610724935209484903937857060724391493050186936685796471";
    const MONTGOMERY_R_INVERSE: &'static str =
        "18289368484950178621272022062020525048389989670507786348948026221581485535495";
    const N_BITS: usize = 254;

    fn half_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fq::from(1) / ark_bn254::Fq::from(2))
    }

    fn one_third_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fq::from(1) / ark_bn254::Fq::from(3))
    }

    fn two_third_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fq::from(2) / ark_bn254::Fq::from(3))
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
            ark_bn254::Fq::from(1) - ark_bn254::Fq::from(Self::not_modulus_as_biguint()),
        );
        wires
    }
}

impl Fq {
    const B_MUL: &'static str =
        "11601089733084985762858650344571909944996040564978406380258545510642996494113";

    pub fn b_mul_as_biguint() -> BigUint {
        BigUint::from_str(Self::B_MUL).unwrap()
    }

    pub fn as_montgomery(a: ark_bn254::Fq) -> ark_bn254::Fq {
        a * ark_bn254::Fq::from(Self::montgomery_r_as_biguint())
    }

    pub fn from_montgomery(a: ark_bn254::Fq) -> ark_bn254::Fq {
        a / ark_bn254::Fq::from(Self::montgomery_r_as_biguint())
    }

    pub fn random() -> ark_bn254::Fq {
        let mut prng = create_rng();
        ark_bn254::Fq::rand(&mut prng)
    }

    pub fn to_bits(u: ark_bn254::Fq) -> Vec<bool> {
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

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::Fq {
        let zero = BigUint::ZERO;
        let one = BigUint::from(1_u8);
        let mut u = zero.clone();
        for bit in bits.iter().rev() {
            u = u.clone() + u.clone() + if *bit { one.clone() } else { zero.clone() };
        }
        ark_bn254::Fq::from(u)
    }

    pub fn wires<T: CircuitTrait> (bld: &mut T) -> Self {
        let inner: [usize; FQ_LEN] = bld.fresh();
        Self(inner)
    }

    pub fn wires_set<T: CircuitTrait>(bld: &mut T, u: ark_bn254::Fq) -> Self {
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

    pub fn wires_set_montgomery<T: CircuitTrait>(bld: &mut T, u: ark_bn254::Fq) -> Self {
        Self::wires_set(bld, Self::as_montgomery(u))
    }

    pub fn from_wires<T: CircuitTrait>(bld: &mut T, fq: Fq) -> ark_bn254::Fq {
        Self::from_bits(fq.0.iter().map(|wire| {
            if *wire != bld.one() || *wire != bld.zero() {
                panic!("wire value is not set properly");
            }
            *wire == bld.one()
        }).collect())
    }

    pub fn from_montgomery_wires<T: CircuitTrait>(bld: &mut T, fq: Fq) -> ark_bn254::Fq {
        Self::from_montgomery(Self::from_wires(bld, fq))
    }

    pub fn add_constant<T: CircuitTrait>(bld: &mut T, a: &[usize], b: ark_bn254::Fq) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);
        if b == ark_bn254::Fq::ZERO {
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


#[cfg(test)]
mod tests {
    use ark_ff::Field;
    use crate::circuits::sect233k1::builder::CircuitAdapter;
    use crate::dv_bn254::fp254impl::Fp254Impl;
    use crate::dv_bn254::fq::Fq;

    #[test]
    fn test_fq_mul_montgomery_dvbn254() {
        let a = Fq::random();
        let b = Fq::random();

        let mut bld = CircuitAdapter::default();
        let a_mont = Fq::as_montgomery(a);
        let b_mont = Fq::as_montgomery(b);

        let a_wires = Fq::wires(&mut bld);
        let b_wires = Fq::wires(&mut bld);

        let a_witness = Fq::to_bits(a_mont);
        let b_witness = Fq::to_bits(b_mont);
        let witness = a_witness.iter().chain(b_witness.iter()).cloned().collect::<Vec<bool>>();

        let out_wires = Fq::mul_montgomery(&mut bld, &a_wires.0, &b_wires.0);
        let wires = bld.eval_gates(&witness);
        let output_bits = out_wires.iter().map(|w| wires[*w]).collect::<Vec<bool>>();
        let c = Fq::from_bits(output_bits);
        assert_eq!(c, Fq::as_montgomery(a * b));
    }

    #[test]
    fn test_fq_inverse_montgomery_dvbn254() {
        let a = ark_bn254::Fq::from(10);

        let mut bld = CircuitAdapter::default();
        let mont_a = Fq::as_montgomery(a);

        let a_ref = Fq::wires(&mut bld);

        let out = Fq::inverse_montgomery(&mut bld, &a_ref.0);
        let witness = Fq::to_bits(mont_a);
        let wires = bld.eval_gates(&witness);

        let inv_a_bits: Vec<bool> = out.iter().map(|id| wires[*id]).collect();
        let c = Fq::from_bits(inv_a_bits);
        assert_eq!(c, Fq::as_montgomery(a.inverse().unwrap()));
    }
}
