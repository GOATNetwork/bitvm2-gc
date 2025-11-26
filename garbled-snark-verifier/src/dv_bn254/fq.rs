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

    // // check if x is a quadratic non-residue (QNR) in Fq
    // pub fn is_qnr_montgomery(x: Wires) -> Circuit {
    //     let mut circuit = Circuit::empty();
    //     // y = x^((p - 1)/2)
    //     let exp = BigUint::from(ark_bn254::Fq::MODULUS_MINUS_ONE_DIV_TWO);
    //     let y = circuit.extend(Fq::exp_by_constant_montgomery(x.clone(), exp));
    //
    //     let neg_one = -ark_bn254::Fq::ONE;
    //     let neg_one_mont = Fq::wires_set_montgomery(neg_one);
    //
    //     let is_qnr = circuit.extend(U254::equal(y, neg_one_mont));
    //
    //     circuit.add_wires(is_qnr);
    //     circuit
    // }
    //
    // pub fn is_qnr_montgomery_evaluate(x: Wires) -> (Wires, GateCount) {
    //     let mut gc = GateCount::zero();
    //     let exp = BigUint::from(ark_bn254::Fq::MODULUS_MINUS_ONE_DIV_TWO);
    //     let (y, add_gc) = Fq::exp_by_constant_montgomery_evaluate(x.clone(), exp);
    //     gc += add_gc;
    //
    //     let neg_one = -ark_bn254::Fq::ONE;
    //     let neg_one_mont = Fq::wires_set_montgomery(neg_one);
    //
    //     let (is_qnr, add_gc) = U254::equal_evaluate(y, neg_one_mont);
    //     gc += add_gc;
    //
    //     (is_qnr, gc)
    // }

    // pub fn sqrt_montgomery(a: Wires) -> Circuit {
    //     assert_eq!(a.len(), Self::N_BITS);
    //     let mut circuit = Circuit::empty();
    //     let b = circuit.extend(Self::exp_by_constant_montgomery(
    //         a,
    //         BigUint::from_str(Self::MODULUS_ADD_1_DIV_4).unwrap(),
    //     ));
    //     circuit.add_wires(b);
    //     circuit
    // }
    //
    // pub fn sqrt_montgomery_evaluate(a: Wires) -> (Wires, GateCount) {
    //     assert_eq!(a.len(), Self::N_BITS);
    //     let mut gc = GateCount::zero();
    //     let (b, add_gc) = Self::exp_by_constant_montgomery_evaluate(
    //         a,
    //         BigUint::from_str(Self::MODULUS_ADD_1_DIV_4).unwrap(),
    //     );
    //     gc += add_gc;
    //     (b, gc)
    // }
}


#[cfg(test)]
mod tests {
    use crate::circuits::sect233k1::builder::CircuitAdapter;
    use crate::dv_bn254::fp254impl::Fp254Impl;
    use crate::dv_bn254::fq::Fq;

    #[test]
    fn test_fq_mul_montgomery_vjp() {
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
}
//     use super::*;
//     use ark_ff::AdditiveGroup;
//     use ark_std::test_rng;
//     use serial_test::serial;
// 
//     #[test]
//     fn test_fq_random() {
//         let u = Fq::random();
//         println!("u: {:?}", u);
//         let b = Fq::to_bits(u);
//         let v = Fq::from_bits(b);
//         println!("v: {:?}", v);
//         assert_eq!(u, v);
//     }
// 
//     #[test]
//     fn test_fq_add() {
//         let a = Fq::random();
//         let b = Fq::random();
//         let circuit = Fq::add(Fq::wires_set(a), Fq::wires_set(b));
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let c = Fq::from_wires(circuit.0);
//         assert_eq!(c, a + b);
//     }
// 
//     #[test]
//     fn test_fq_add_constant() {
//         let a = Fq::random();
//         let b = Fq::random();
//         let circuit = Fq::add_constant(Fq::wires_set(a), b);
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let c = Fq::from_wires(circuit.0);
//         assert_eq!(c, a + b);
//     }
// 
//     #[test]
//     fn test_fq_neg() {
//         let a = Fq::random();
//         let circuit = Fq::neg(Fq::wires_set(a));
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let c = Fq::from_wires(circuit.0);
//         assert_eq!(c, -a);
//     }
// 
//     #[test]
//     fn test_fq_sub() {
//         let a = Fq::random();
//         let b = Fq::random();
//         let circuit = Fq::sub(Fq::wires_set(a), Fq::wires_set(b));
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let c = Fq::from_wires(circuit.0);
//         assert_eq!(c, a - b);
//     }
// 
//     #[test]
//     fn test_fq_double() {
//         let a = Fq::random();
//         let circuit = Fq::double(Fq::wires_set(a));
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let c = Fq::from_wires(circuit.0);
//         assert_eq!(c, a + a);
//     }
// 
//     #[test]
//     fn test_fq_half() {
//         let a = Fq::random();
//         let circuit = Fq::half(Fq::wires_set(a));
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let c = Fq::from_wires(circuit.0);
//         assert_eq!(c + c, a);
//     }
// 
//     #[test]
//     fn test_fq_triple() {
//         let a = Fq::random();
//         let circuit = Fq::triple(Fq::wires_set(a));
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let c = Fq::from_wires(circuit.0);
//         assert_eq!(c, a + a + a);
//     }
// 
//     #[test]
//     fn test_fq_mul_montgomery() {
//         let a = Fq::random();
//         let b = Fq::random();
//         let circuit = Fq::mul_montgomery(
//             Fq::wires_set(Fq::as_montgomery(a)),
//             Fq::wires_set(Fq::as_montgomery(b)),
//         );
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let c = Fq::from_wires(circuit.0);
//         assert_eq!(c, Fq::as_montgomery(a * b));
//     }
// 
//     #[test]
//     fn test_fq_mul_by_constant_montgomery() {
//         let a = Fq::random();
//         let b = Fq::random();
//         let c = ark_bn254::Fq::ONE;
//         let d = ark_bn254::Fq::ZERO;
// 
//         let circuit =
//             Fq::mul_by_constant_montgomery(Fq::wires_set_montgomery(a), Fq::as_montgomery(b));
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let e = Fq::from_wires(circuit.0);
//         assert_eq!(e, Fq::as_montgomery(a * b));
// 
//         let circuit =
//             Fq::mul_by_constant_montgomery(Fq::wires_set_montgomery(a), Fq::as_montgomery(c));
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let e = Fq::from_wires(circuit.0);
//         assert_eq!(e, Fq::as_montgomery(a * c));
// 
//         let circuit =
//             Fq::mul_by_constant_montgomery(Fq::wires_set_montgomery(a), Fq::as_montgomery(d));
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let e = Fq::from_wires(circuit.0);
//         assert_eq!(e, Fq::as_montgomery(a * d));
//     }
// 
//     #[test]
//     fn test_fq_square_montgomery() {
//         let a = Fq::random();
//         let circuit = Fq::square_montgomery(Fq::wires_set_montgomery(a));
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let c = Fq::from_wires(circuit.0);
//         assert_eq!(c, Fq::as_montgomery(a * a));
//     }
// 
//     #[test]
//     fn test_fq_inverse_montgomery() {
//         let a = Fq::random();
//         let circuit = Fq::inverse_montgomery(Fq::wires_set_montgomery(a));
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let c = Fq::from_wires(circuit.0);
//         assert_eq!(c, Fq::as_montgomery(a.inverse().unwrap()));
//     }
// 
//     #[test]
//     fn test_fq_div6() {
//         let a = Fq::random();
//         let circuit = Fq::div6(Fq::wires_set(a));
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
// 
//         let c = Fq::from_wires(circuit.0);
//         assert_eq!(c + c + c + c + c + c, a);
//     }
// 
//     #[test]
//     #[serial]
//     #[ignore]
//     fn test_fq_exp_by_constant_montgomery() {
//         use ark_ff::PrimeField;
//         let ut = |b: BigUint| {
//             let a = Fq::random();
//             let b = ark_bn254::Fq::from(b);
//             let expect_a_to_power_of_b = a.pow(b.into_bigint());
// 
//             let circuit =
//                 Fq::exp_by_constant_montgomery(Fq::wires_set_montgomery(a), BigUint::from(b));
//             circuit.gate_counts().print();
//             for mut gate in circuit.1 {
//                 gate.evaluate();
//             }
//             let c = Fq::from_montgomery_wires(circuit.0);
//             assert_eq!(expect_a_to_power_of_b, c);
//         };
//         ut(BigUint::from(0u8));
//         ut(BigUint::from(1u8));
//         ut(BigUint::from(u32::rand(&mut test_rng())));
//         ut(BigUint::from_str(Fq::MODULUS_ADD_1_DIV_4).unwrap());
//         ut(BigUint::from(ark_bn254::Fq::MODULUS_MINUS_ONE_DIV_TWO));
//     }
// 
//     #[test]
//     #[serial]
//     fn test_fq_exp_by_constant_montgomery_evaluate() {
//         use ark_ff::PrimeField;
//         let ut = |b: BigUint| {
//             let a = Fq::random();
//             let b = ark_bn254::Fq::from(b);
//             let expect_a_to_power_of_b = a.pow(b.into_bigint());
// 
//             let (c, gc) = Fq::exp_by_constant_montgomery_evaluate(
//                 Fq::wires_set_montgomery(a),
//                 BigUint::from(b),
//             );
//             gc.print();
//             assert_eq!(expect_a_to_power_of_b, Fq::from_montgomery_wires(c));
//         };
//         ut(BigUint::from(0u8));
//         ut(BigUint::from(1u8));
//         ut(BigUint::from(u32::rand(&mut test_rng())));
//         ut(BigUint::from_str(Fq::MODULUS_ADD_1_DIV_4).unwrap());
//         ut(BigUint::from(ark_bn254::Fq::MODULUS_MINUS_ONE_DIV_TWO));
//     }
// 
//     #[test]
//     fn test_fq_sqrt_montgomery() {
//         let a = Fq::random();
//         let aa = a * a;
//         let circuit = Fq::sqrt_montgomery(Fq::wires_set_montgomery(aa));
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let c = Fq::from_montgomery_wires(circuit.0);
//         let la = match a.legendre().is_qnr() {
//             true => -a,
//             false => a,
//         };
//         assert_eq!(c, la);
//     }
// 
//     #[test]
//     fn test_fq_is_qnr_montgomery() {
//         use num_traits::One;
//         let a = Fq::random();
//         println!("{}", a.legendre().is_qnr());
//         let circuit = Fq::is_qnr_montgomery(Fq::wires_set_montgomery(a));
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let is_qnr = Fq::from_montgomery_wires(circuit.0);
//         assert_eq!(is_qnr.is_one(), a.legendre().is_qnr());
//     }
// }
