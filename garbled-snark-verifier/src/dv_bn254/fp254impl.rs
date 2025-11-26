use crate::{
    dv_bn254::{
        bigint::U254,
        fq::Fq,
    },
};
use ark_ff::{AdditiveGroup, Field};
use core::str::FromStr;
use num_bigint::BigUint;
use crate::circuits::sect233k1::builder::CircuitTrait;
use crate::dv_bn254::basic::not;
use crate::dv_bn254::fr::Fr;

pub trait Fp254Impl: Sized {
    const MODULUS: &'static str;
    const MONTGOMERY_R: &'static str =
        "28948022309329048855892746252171976963317496166410141009864396001978282409984"; //2^254
    
    const MONTGOMERY_M_INVERSE: &'static str; // MODULUS^-1 modulo R
    const MONTGOMERY_R_INVERSE: &'static str; // R^-1 modulo MODULUS
    const N_BITS: usize;
    const MODULUS_ADD_1_DIV_4: &'static str =
        "5472060717959818805561601436314318772174077789324455915672259473661306552146"; // (MODULUS+1)/4 

    fn modulus_as_biguint() -> BigUint {
        BigUint::from_str(Self::MODULUS).unwrap()
    }

    fn montgomery_r_as_biguint() -> BigUint {
        BigUint::from_str(Self::MONTGOMERY_R).unwrap()
    }

    fn montgomery_m_inverse_as_biguint() -> BigUint {
        BigUint::from_str(Self::MONTGOMERY_M_INVERSE).unwrap()
    }

    fn montgomery_r_inverse_as_biguint() -> BigUint {
        BigUint::from_str(Self::MONTGOMERY_R_INVERSE).unwrap()
    }

    fn not_modulus_as_biguint() -> BigUint {
        let p = Self::modulus_as_biguint();
        let a = BigUint::from_str("2").unwrap().pow(Self::N_BITS.try_into().unwrap());
        a - p
    }

    fn half_modulus() -> BigUint;

    fn one_third_modulus() -> BigUint;

    fn two_third_modulus() -> BigUint;

    fn multiplexer<T: CircuitTrait> (bld: &mut T, a: &Vec<Vec<usize>>, s: &[usize], w: usize) -> Vec<usize> {
        U254::multiplexer(bld, a, s, w)
    }

    fn equal<T: CircuitTrait> (bld: &mut T, a: &[usize], b: &[usize]) -> usize {
        U254::equal(bld, a, b)
    }

    fn equal_constant<T: CircuitTrait> (bld: &mut T, a: &[usize], b: ark_bn254::Fq) -> usize {
        U254::equal_constant(bld, a, &BigUint::from(b))
    }

    fn equal_zero<T: CircuitTrait> (bld: &mut T, a: &[usize]) -> usize {
        U254::equal_constant(bld, a, &BigUint::ZERO)
    }

    fn add<T: CircuitTrait> (bld: &mut T, a: &[usize], b: &[usize]) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);

        let mut wires_1 = U254::add(bld, a, b);
        let u = wires_1.pop().unwrap();
        let c = Self::not_modulus_as_biguint();
        let mut wires_2 = U254::add_constant(bld, &wires_1, &c);
        wires_2.pop();
        let v = U254::less_than_constant(bld, &wires_1, &Self::modulus_as_biguint());
        let not_u = not(bld, u);
        let s = bld.and_wire(not_u, v);
        
        let wires_3 = U254::select(bld, &wires_1, &wires_2, s);
        wires_3
    }
    
    fn neg<T: CircuitTrait>(bld: &mut T, a: &[usize]) -> Vec<usize>;

    fn sub<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &[usize]) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);


        let neg_b = Self::neg(bld, b);
        let result = Self::add(bld, a, &neg_b);
        result
    }

    fn double<T: CircuitTrait>(bld: &mut T, a: &[usize]) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);
    
        let mut aa = a.to_vec();
        let u = aa.pop().unwrap();
        let mut shifted_wires = vec![bld.zero()];
        shifted_wires.extend(aa);
        let c = Self::not_modulus_as_biguint();
        let mut wires_2 = U254::add_constant(bld, &shifted_wires, &c);
        wires_2.pop();
        let v = U254::less_than_constant(bld, &shifted_wires, &Self::modulus_as_biguint());
    
        // Ncimp
        let not_a = not(bld, u);
        let s = bld.and_wire(not_a, v);
        let result = U254::select(bld, &shifted_wires, &wires_2, s);
        result
    }

    fn half<T: CircuitTrait>(bld: &mut T, a: &[usize]) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);
        let selector = a[0];
        let wires_1 = U254::half(bld, a);
        let wires_2 = U254::add_constant_without_carry(bld, &wires_1, &Self::half_modulus());
        let result = U254::select(bld, &wires_2, &wires_1, selector);
        result
    }

    fn triple<T: CircuitTrait>(bld: &mut T, a: &[usize]) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);
        let a_2 = Self::double(bld, a);
        let a_3 = Self::add(bld, &a_2, a);
        a_3
    }

    // fn exp_by_constant_montgomery(a: Wires, b: BigUint) -> Circuit {
    //     assert_eq!(a.len(), Self::N_BITS);
    //     let mut circuit = Circuit::empty();
    //
    //     if b.is_zero() {
    //         circuit.add_wires(Fq::wires_set_montgomery(ark_bn254::Fq::ONE));
    //         return circuit;
    //     }
    //
    //     if b.is_one() {
    //         circuit.add_wires(a);
    //         return circuit;
    //     }
    //
    //     let b_bits = bits_from_biguint(&b);
    //
    //     let len = b_bits.len();
    //     let mut i = len - 1;
    //     while !b_bits[i] {
    //         i -= 1;
    //     }
    //     let mut result = a.clone();
    //     for b_bit in b_bits.iter().rev().skip(len - i) {
    //         let result_square = circuit.extend(Self::square_montgomery(result.clone()));
    //         if *b_bit {
    //             result = circuit.extend(Self::mul_montgomery(a.clone(), result_square));
    //         } else {
    //             result = result_square;
    //         }
    //     }
    //     circuit.add_wires(result);
    //     circuit
    // }

    fn montgomery_reduce<T: CircuitTrait>(bld: &mut T, x: &[usize]) -> Vec<usize> {
        let x_low = x[..254].to_vec();
        let x_high = x[254..].to_vec();
        let q = U254::mul_by_constant_modulo_power_two(
            bld,
            &x_low,
            Self::montgomery_m_inverse_as_biguint(),
            254,
        );
        let sub = U254::mul_by_constant(bld, &q, Self::modulus_as_biguint())[254..508].to_vec();
        let bound_check = U254::greater_than(bld, &sub, &x_high);
        let subtract_if_too_much = U254::self_or_zero_constant(
            bld,
            &Self::modulus_as_biguint(),
            bound_check,
        );
        let new_sub = U254::sub_without_borrow(bld, &sub, &subtract_if_too_much);
        let result = U254::sub_without_borrow(bld, &x_high, &new_sub);
        result
    }

    fn mul_montgomery<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &[usize]) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mul_circuit = U254::mul_karatsuba(bld, a, b);
        let reduction_circuit = Self::montgomery_reduce(bld, &mul_circuit);
        reduction_circuit
    }

    fn mul_by_fq_constant_montgomery<T: CircuitTrait>(bld: &mut T, a: &[usize], b: ark_bn254::Fq) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);

        if b == ark_bn254::Fq::ZERO {
            return Fq::wires_set(bld, ark_bn254::Fq::ZERO).0.to_vec();
        }

        if b == Fq::as_montgomery(ark_bn254::Fq::ONE) {
            return a.to_vec();
        }

        let mul_circuit = U254::mul_by_constant(bld, a, b.into());
        let reduction_circuit = Self::montgomery_reduce(bld, &mul_circuit);
        reduction_circuit
    }

    fn mul_by_fr_constant_montgomery<T: CircuitTrait>(bld: &mut T, a: &[usize], b: ark_bn254::Fr) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);

        if b == ark_bn254::Fr::ZERO {
            return Fr::wires_set(bld, ark_bn254::Fr::ZERO).0.to_vec();
        }

        if b == Fr::as_montgomery(ark_bn254::Fr::ONE) {
            return a.to_vec();
        }

        let mul_circuit = U254::mul_by_constant(bld, a, b.into());
        let reduction_circuit = Self::montgomery_reduce(bld, &mul_circuit);
        reduction_circuit
    }

    fn square_montgomery<T: CircuitTrait>(bld: &mut T, a: &[usize]) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);

        Self::mul_montgomery(bld, a, a)
    }

    fn inverse<T: CircuitTrait>(bld: &mut T, a: &[usize]) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);
        let wires_1 = U254::odd_part(bld, a);
        let odd_part = wires_1.0;
        let mut even_part = wires_1.1;

        // initialize value for wires
        let neg_odd_part = Self::neg(bld, &odd_part);
        let mut u = U254::half(bld, &neg_odd_part);
        let mut v = odd_part;
        let mut k = Fq::wires_set(bld, ark_bn254::Fq::ONE).0.to_vec();
        let mut r = Fq::wires_set(bld, ark_bn254::Fq::ONE).0.to_vec();
        let mut s = Fq::wires_set(bld, ark_bn254::Fq::from(2)).0.to_vec();

        for _ in 0..2 * Self::N_BITS {
            let not_x1 = u[0];
            let not_x2 = v[0];
            let x3 = U254::greater_than(bld, &u, &v);

            // Nimp
            let not_b = not(bld, not_x2);
            let p2 = bld.and_wire(not_x1, not_b);
            let wires_2 = bld.and_wire(not_x1, not_x2);
            let p3 = bld.and_wire(wires_2, x3);
            let not_x3 = not(bld, x3);
            let p4 = bld.and_wire(wires_2, not_x3);

            //part1
            let u1 = U254::half(bld, &u);
            let v1 = v.clone();
            let r1 = r.clone();
            let s1 = U254::double_without_overflow(bld, &s);
            let k1 = U254::add_constant_without_carry(
                bld,
                &k,
                &BigUint::from_str("1").unwrap(),
            );

            // part2
            let u2 = u.clone();
            let v2 = U254::half(bld, &v);
            let r2 = U254::double_without_overflow(bld, &r);
            let s2 = s.clone();
            let k2 = U254::add_constant_without_carry(
                bld,
                &k,
                &BigUint::from_str("1").unwrap(),
            );

            // part3
            let u3 = U254::sub_without_borrow(bld, &u1, &v2);
            let v3 = v.clone();
            let r3 = U254::add_without_carry(bld, &r, &s);
            let s3 = U254::double_without_overflow(bld, &s);
            let k3 = U254::add_constant_without_carry(
                bld,
                &k,
                &BigUint::from_str("1").unwrap(),
            );

            // part4
            let u4 = u.clone();
            let v4 = U254::sub_without_borrow(bld, &v2, &u1);
            let r4 = U254::double_without_overflow(bld, &r);
            let s4 = U254::add_without_carry(bld, &r, &s);
            let k4 = U254::add_constant_without_carry(
                bld,
                &k,
                &BigUint::from_str("1").unwrap(),
            );

            // calculate new u
            let wire_u_1 = U254::self_or_zero_inv(bld, &u1, not_x1);
            let wire_u_2 = U254::self_or_zero(bld, &u2, p2);
            let wire_u_3 = U254::self_or_zero(bld, &u3, p3);
            let wire_u_4 = U254::self_or_zero(bld, &u4, p4);

            let add_u_1 = U254::add_without_carry(bld, &wire_u_1, &wire_u_2);
            let add_u_2 = U254::add_without_carry(bld, &add_u_1, &wire_u_3);
            let new_u = U254::add_without_carry(bld, &add_u_2, &wire_u_4);

            // calculate new v
            let wire_v_1 = U254::self_or_zero_inv(bld, &v1, not_x1);
            let wire_v_2 = U254::self_or_zero(bld, &v2, p2);
            let wire_v_3 = U254::self_or_zero(bld, &v3, p3);
            let wire_v_4 = U254::self_or_zero(bld, &v4, p4);

            let add_v_1 = U254::add_without_carry(bld, &wire_v_1, &wire_v_2);
            let add_v_2 = U254::add_without_carry(bld, &add_v_1, &wire_v_3);
            let new_v = U254::add_without_carry(bld, &add_v_2, &wire_v_4);

            // calculate new r
            let wire_r_1 = U254::self_or_zero_inv(bld, &r1, not_x1);
            let wire_r_2 = U254::self_or_zero(bld, &r2, p2);
            let wire_r_3 = U254::self_or_zero(bld, &r3, p3);
            let wire_r_4 = U254::self_or_zero(bld, &r4, p4);

            let add_r_1 = U254::add_without_carry(bld, &wire_r_1, &wire_r_2);
            let add_r_2 = U254::add_without_carry(bld, &add_r_1, &wire_r_3);
            let new_r = U254::add_without_carry(bld, &add_r_2, &wire_r_4);

            // calculate new s
            let wire_s_1 = U254::self_or_zero_inv(bld, &s1, not_x1);
            let wire_s_2 = U254::self_or_zero(bld, &s2, p2);
            let wire_s_3 = U254::self_or_zero(bld, &s3, p3);
            let wire_s_4 = U254::self_or_zero(bld, &s4, p4);

            let add_s_1 = U254::add_without_carry(bld, &wire_s_1, &wire_s_2);
            let add_s_2 = U254::add_without_carry(bld, &add_s_1, &wire_s_3);
            let new_s = U254::add_without_carry(bld, &add_s_2, &wire_s_4);

            // calculate new k
            let wire_k_1 = U254::self_or_zero_inv(bld, &k1, not_x1);
            let wire_k_2 = U254::self_or_zero(bld, &k2, p2);
            let wire_k_3 = U254::self_or_zero(bld, &k3, p3);
            let wire_k_4 = U254::self_or_zero(bld, &k4, p4);

            let add_k_1 = U254::add_without_carry(bld, &wire_k_1,& wire_k_2);
            let add_k_2 = U254::add_without_carry(bld, &add_k_1, &wire_k_3);
            let new_k = U254::add_without_carry(bld, &add_k_2, &wire_k_4);

            // set new values

            let v_equals_one = U254::equal_constant(
                bld,
                &v,
                &BigUint::from_str("1").unwrap()
            );
            u = U254::select(bld, &u, &new_u, v_equals_one);
            v = U254::select(bld, &v, &new_v, v_equals_one);
            r = U254::select(bld, &r, &new_r, v_equals_one);
            s = U254::select(bld, &s, &new_s, v_equals_one);
            k = U254::select(bld, &k, &new_k, v_equals_one);
        }

        // divide result by even part
        for _ in 0..Self::N_BITS {
            let updated_s = Self::half(bld, &s);
            let updated_even_part = Self::half(bld, &even_part);
            let selector = Self::equal_constant(bld, &even_part, ark_bn254::Fq::ONE);
            s = U254::select(bld, &s, &updated_s, selector);
            even_part = U254::select(bld, &even_part, &updated_even_part, selector);
        }

        // divide result by 2^k
        for _ in 0..2 * Self::N_BITS {
            let updated_s = Self::half(bld, &s);
            let updated_k = Fq::add_constant(bld, &k, ark_bn254::Fq::from(-1));
            let selector = Self::equal_constant(bld, &k, ark_bn254::Fq::ZERO);
            s = U254::select(bld, &s, &updated_s, selector);
            k = U254::select(bld, &k, &updated_k, selector);
        }
        s
    }

    fn inverse_montgomery<T: CircuitTrait>(bld: &mut T, a: &[usize]) -> Vec<usize> {

        let b = Fq::inverse(bld, a);
        let result = Fq::mul_by_fq_constant_montgomery(
            bld,
            &b,
            ark_bn254::Fq::from(Fq::montgomery_r_as_biguint()).square()
                * ark_bn254::Fq::from(Fq::montgomery_r_as_biguint()),
        );

        result
    }

    // fn div6(a: Wires) -> Circuit {
    //     assert_eq!(a.len(), Self::N_BITS);
    //     let mut circuit = Circuit::empty();
    //
    //     let half = circuit.extend(Self::half(a.clone()));
    //     let mut result = Fq::wires();
    //     let mut r1 = new_wirex();
    //     let mut r2 = new_wirex();
    //     r1.borrow_mut().set(false);
    //     r2.borrow_mut().set(false);
    //     for i in 0..U254::N_BITS {
    //         // msb to lsb
    //         let j = U254::N_BITS - 1 - i;
    //
    //         // result wire
    //         let r2_and_hj = new_wirex();
    //         circuit.add(Gate::and(r2.clone(), half[j].clone(), r2_and_hj.clone()));
    //         let result_wire = new_wirex();
    //         circuit.add(Gate::or(r1.clone(), r2_and_hj.clone(), result_wire.clone()));
    //         result[j] = result_wire.clone();
    //         // update r1 r2 values
    //         let not_hj = new_wirex();
    //         let not_r2 = new_wirex();
    //         circuit.add(Gate::not(half[j].clone(), not_hj.clone()));
    //         circuit.add(Gate::not(r2.clone(), not_r2.clone()));
    //         r1 = circuit.extend(selector(not_r2.clone(), r2.clone(), result_wire.clone()))[0]
    //             .clone();
    //         r2 = circuit.extend(selector(not_hj.clone(), half[j].clone(), result_wire.clone()))[0]
    //             .clone();
    //
    //         // special case if 1 0 0 then 0 1 instead of 1 1 so we need to not r1 if 1 0 0 is the case
    //         let not_r1 = new_wirex();
    //         circuit.add(Gate::not(r1.clone(), not_r1.clone()));
    //         let edge_case = new_wirex();
    //         circuit.add(Gate::and(result_wire.clone(), not_hj, edge_case.clone()));
    //         r1 = circuit.extend(selector(not_r1.clone(), r1.clone(), edge_case))[0].clone();
    //     }
    //     // residue for r2
    //     let result_plus_one_third = circuit
    //         .extend(U254::add_constant_without_carry(result.clone(), &Self::one_third_modulus()));
    //     result = U254::select(bld, result_plus_one_third, result.clone(), r2.clone()));
    //     // residue for r1
    //     let result_plus_two_third = circuit
    //         .extend(U254::add_constant_without_carry(result.clone(), &Self::two_third_modulus()));
    //     result = U254::select(bld, result_plus_two_third, result.clone(), r1.clone()));
    //     circuit.add_wires(result.clone());
    //     circuit
    // }
}
