use super::U254;
use crate::dv_bn254::basic::{multiplexer, not};
use crate::dv_bn254::bigint::utils::bits_from_biguint;
use crate::{dv_bn254::basic::selector};
use ark_ff::Zero;
use num_bigint::BigUint;
use crate::circuits::sect233k1::builder::CircuitTrait;

pub fn self_or_zero_generic<T: CircuitTrait>(bld: &mut T, a: &[usize], s: usize, len: usize) -> Vec<usize> {
    assert_eq!(a.len(), len);
    let mut result = vec![0; len];
    for i in 0..len {
        result[i] = bld.and_wire(a[i], s);
    }
    result
}

//s is inverted
pub fn self_or_zero_inv_generic<T: CircuitTrait>(bld: &mut T, a: &[usize], s: usize, len: usize) -> Vec<usize> {
    assert_eq!(a.len(), len);
    let mut result = vec![0; len];
    for i in 0..len {
        // Nimp
        let not_b = not(bld, s);
        result[i] = bld.and_wire(a[i], not_b);
    }
    result
}

impl U254 {
    pub fn equal<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &[usize]) -> usize {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);

        let mut c= vec![0; Self::N_BITS];
        for i in 0..Self::N_BITS {
            c[i] = bld.xor_wire(a[i], b[i]);
        }
        Self::equal_constant(bld, &c, &BigUint::ZERO)
    }

    pub fn equal_constant<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &BigUint) -> usize {
        assert_eq!(a.len(), Self::N_BITS);
        let mut result = 0;
        if b == &BigUint::zero() {
            if Self::N_BITS == 1 {
                let not_a0 = not(bld, a[0]);
                result = not_a0;
            } else {
                // xnor
                let axor = bld.xor_wire(a[0], a[1]);
                let mut res = not(bld, axor);
                for x in &a[1..Self::N_BITS] {
                    // Ncimp
                    let not_a = not(bld, *x);
                    let new_res = bld.and_wire(not_a, res);
                    res = new_res;
                }
                result = res;
            }
        } else {
            let mut one_ind = 0;
            let b_bits = bits_from_biguint(b);
            while !b_bits[one_ind] {
                one_ind += 1;
            }
            let mut res = a[one_ind].clone();
            for i in 0..Self::N_BITS {
                if i == one_ind {
                    continue;
                }

                if !b_bits[i] {
                    // Ncimp
                    let not_a = not(bld, a[i]);
                    res = bld.and_wire(not_a, res);
                } else {
                    // And
                    res = bld.and_wire(a[i], res);
                }
            }
            result = res;
        }
        result
    }

    pub fn greater_than<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &[usize]) -> usize {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut not_b = vec![0; Self::N_BITS];

        for i in 0..Self::N_BITS {
            not_b[i] = not(bld, b[i]);
        }

        let wires = Self::add(bld, a, &not_b);
        wires[Self::N_BITS]
    }

    pub fn less_than_constant<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &BigUint) -> usize {
        assert_eq!(a.len(), Self::N_BITS);
        let mut not_a = [0; Self::N_BITS];
        for i in 0..Self::N_BITS {
            not_a[i] = not(bld, a[i]);
        }

        let wires = Self::add_constant(bld, &not_a, b);
        wires[Self::N_BITS]
    }

    pub fn select<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &[usize], s: usize) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut res = [0_usize; Self::N_BITS];
        for i in 0..Self::N_BITS {
            let wires = selector(bld, a[i], b[i], s);
            res[i] = wires;
        }
        res.to_vec()
    }

    pub fn self_or_zero<T: CircuitTrait>(bld: &mut T, a: &[usize], s: usize) -> Vec<usize> {
        self_or_zero_generic(bld, a, s, Self::N_BITS)
    }

    //s is inverted
    pub fn self_or_zero_inv<T: CircuitTrait>(bld: &mut T, a: &[usize], s: usize) -> Vec<usize> {
        self_or_zero_inv_generic(bld, a, s, Self::N_BITS)
    }

    pub fn self_or_zero_constant<T: CircuitTrait>(bld: &mut T, a: &BigUint, s: usize) -> Vec<usize> {
        let mut bit_wires = vec![];
        let mut bits = bits_from_biguint(a);
        bits.resize(Self::N_BITS, false);
        for i in 0..Self::N_BITS {
            if bits[i] {
                bit_wires.push(bld.one());
            } else {
                bit_wires.push(bld.zero());
            }
        }
        Self::self_or_zero(bld, &bit_wires, s)
    }

    pub fn multiplexer<T: CircuitTrait>(bld: &mut T, a: &Vec<Vec<usize>>, s: &[usize], w: usize) -> Vec<usize> {
        let n = 2_usize.pow(w.try_into().unwrap());
        assert_eq!(a.len(), n);
        for x in a.iter() {
            assert_eq!(x.len(), Self::N_BITS);
        }
        assert_eq!(s.len(), w);

        let mut res = vec![];
        for i in 0..Self::N_BITS {
            let ith_wires: Vec<usize> = a.iter().map(|x| x[i].clone()).collect();
            let ith_result = multiplexer(bld, &ith_wires, &s, w);
            res.push(ith_result);
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use crate::circuits::sect233k1::builder::CircuitAdapter;
    use super::*;
    use crate::dv_bn254::{
        bigint::{
            U254,
            utils::{random_biguint_n_bits},
        },
    };

    #[test]
    fn test_less_than_constant_dvbn254() {
        let mut bld = CircuitAdapter::default();
        let a = random_biguint_n_bits(254);
        let b = random_biguint_n_bits(254);
        let vec_a = U254::wires_set_from_number(&mut bld, &a);
        let circuit = U254::less_than_constant(&mut bld, &vec_a, &b);
        // circuit.gate_counts().print();
        // for mut gate in circuit.1 {
        //     gate.evaluate();
        // }
        let wires = bld.eval_gates(&vec![]);
        let output = wires[circuit];
        assert_eq!(a < b, output);
    }
}
