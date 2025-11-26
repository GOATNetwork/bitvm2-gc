use crate::{
    dv_bn254::{
        basic::{full_adder, full_subtracter, half_adder, half_subtracter},
        bigint::utils::bits_from_biguint,
    },
};
use num_bigint::BigUint;
use crate::dv_bn254::bigint::U254;
use crate::circuits::sect233k1::builder::CircuitTrait;
use crate::dv_bn254::basic::not;

pub fn add_generic<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &[usize], len: usize) -> Vec<usize> {
    assert_eq!(a.len(), len);
    assert_eq!(b.len(), len);
    let mut res = Vec::new();
    let wires = half_adder(bld, a[0], b[0]);
    res.push(wires[0]);
    let mut carry = wires[1];
    for i in 1..len {
        let wires = full_adder(bld, a[i], b[i], carry);
        res.push(wires[0]);
        carry = wires[1];
    }
    res.push(carry);
    res
}

pub fn add_constant_generic<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &BigUint, len: usize) -> Vec<usize> {
    assert_eq!(a.len(), len);
    assert_ne!(b, &BigUint::ZERO);
    
    let b_bits = bits_from_biguint(b);
    
    let mut first_one = 0;
    while !b_bits[first_one] {
        first_one += 1;
    }
    
    // let mut carry = bld.fresh_one();
    let mut carry = 0;
    let mut res = Vec::new();
    for i in 0..len {
        if i < first_one {
            res.push(a[i]);
        } else if i == first_one {
            let not_a = not(bld, a[i]);
            res.push(not_a);
            carry = a[i];
        } else if b_bits[i] {
            // xnor
            let axb = bld.xor_wire(a[i], carry);
            let wire1 = not(bld, axb);
            res.push(wire1);
            let wire2 = bld.or_wire(a[i], carry);
            carry = wire2;
        } else {
            let wire1 = bld.xor_wire(a[i], carry);
            let wire2 = bld.and_wire(a[i], carry);
            res.push(wire1);
            carry = wire2;
        }
    }
    res.push(carry);
    res
}

pub fn sub_generic<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &[usize], len: usize) -> Vec<usize> {
    assert_eq!(a.len(), len);
    assert_eq!(b.len(), len);

    let mut res = Vec::new();
    let wires = half_subtracter(bld, a[0], b[0]);
    res.push(wires[0]);
    let mut borrow = wires[1];
    for i in 1..len {
        let wires= full_subtracter(bld, a[i], b[i], borrow);
        res.push(wires[0]);
        borrow = wires[1].clone();
    }
    res.push(borrow);
    res
}

pub fn sub_generic_without_borrow<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &[usize], len: usize) -> Vec<usize> {
    let mut c = sub_generic(bld, a, b, len);
    c.pop();
    c
}

impl U254{
    pub fn add<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &[usize]) -> Vec<usize> {
        add_generic(bld, a, b, Self::N_BITS)
    }

    pub fn add_without_carry<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &[usize]) -> Vec<usize> {
        let mut c = add_generic(bld, a, b, Self::N_BITS);
        c.pop();
        c
    }

    pub fn add_constant<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &BigUint) -> Vec<usize> {
        add_constant_generic(bld, a, b, Self::N_BITS)
    }

    pub fn add_constant_without_carry<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &BigUint) -> Vec<usize> {
        let mut c = add_constant_generic(bld, a, b, Self::N_BITS);
        c.pop();
        c
    }

    /*
    pub fn sub(a: Wires, b: Wires) -> Circuit {
        sub_generic(a, b, N_BITS)
    }
    */

    pub fn sub_without_borrow<T: CircuitTrait>(bld: &mut T, a: &[usize], b: &[usize]) -> Vec<usize> {
        sub_generic_without_borrow(bld, a, b, Self::N_BITS)
    }

    // pub fn double(a: Wires) -> Circuit {
    //     assert_eq!(a.len(), N_BITS);
    //     let mut circuit = Circuit::empty();
    //     let not_a = new_wirex();
    //     let zero_wire = new_wirex();
    //     circuit.add(Gate::not(a[0].clone(), not_a.clone()));
    //     circuit.add(Gate::and(a[0].clone(), not_a.clone(), zero_wire.clone()));
    //     circuit.add_wire(zero_wire);
    //     circuit.add_wires(a[0..N_BITS].to_vec());
    //     circuit
    // }

    pub fn double_without_overflow<T: CircuitTrait>(bld: &mut T, a: &[usize]) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);
        let zero_wire = bld.zero();
        let mut res = Vec::new();
        res.push(zero_wire);
        res.extend(&a[0..Self::N_BITS - 1]);
        res
    }

    pub fn half<T: CircuitTrait>(bld: &mut T, a: &[usize]) -> Vec<usize> {
        assert_eq!(a.len(), Self::N_BITS);
        let mut res: [usize; Self::N_BITS] = [bld.zero(); Self::N_BITS];
        res[0..Self::N_BITS - 1].copy_from_slice(&a[1..Self::N_BITS]);
        res.to_vec()
    }

    pub fn odd_part<T: CircuitTrait>(bld: &mut T, a: &[usize]) -> (Vec<usize>, Vec<usize>) {
        assert_eq!(a.len(), Self::N_BITS);
        let mut select: [usize; Self::N_BITS] = [bld.zero(); Self::N_BITS];
        select[0] = a[0];
        for i in 1..Self::N_BITS {
            select[i] = bld.or_wire(select[i - 1], a[i]);
        }

        let mut k: [usize; Self::N_BITS] = [bld.zero(); Self::N_BITS];
        k[0] = a[0];
        for i in 1..Self::N_BITS {
            // do the ncimp: !a & b
            let not_a = not(bld, select[i - 1]);
            k[i] = bld.and_wire(not_a, a[i]);
        }

        let mut result = a.to_vec();
        for i in 0..Self::N_BITS {
            let half_result = Self::half(bld, &result);
            result = Self::select(bld, &result, &half_result, select[i]);
        }
        (result, k.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use crate::dv_bn254::bigint::U254;
    use num_bigint::BigUint;
    use crate::circuits::sect233k1::builder::CircuitAdapter;
    use crate::dv_bn254::bigint::utils::{biguint_from_bits, bits_from_biguint};

    #[test]
    fn test_odd_part_vjp() {
        let a = BigUint::from(10_u8);
        let mut bld = CircuitAdapter::default();
        let a_wires = U254::wires(&mut bld);
        let output = U254::odd_part(&mut bld, &a_wires);

        let witness = bits_from_biguint(&a);
        let wires = bld.eval_gates(&witness[0..254]);
        let output_0bits: Vec<bool> = output.0.iter().map(|id| wires[*id]).collect();
        let output_1bits: Vec<bool> = output.1.iter().map(|id| wires[*id]).collect();

        let c = biguint_from_bits(output_0bits);
        let d = biguint_from_bits(output_1bits);
        assert_eq!(a, c * d);
    }


    //
    // #[test]
    // fn test_add_constant() {
    //     let a = random_biguint_n_bits(254);
    //     let b = random_biguint_n_bits(254);
    //     let circuit = U254::add_constant(U254::wires_set_from_number(&a), &b);
    //     circuit.gate_counts().print();
    //     for mut gate in circuit.1 {
    //         gate.evaluate();
    //     }
    //     let c = biguint_from_wires(circuit.0);
    //     assert_eq!(c, a + b);
    // }
    //
    // #[test]
    // fn test_add_without_carry() {
    //     let a = random_biguint_n_bits(254);
    //     let b = random_biguint_n_bits(254);
    //     let circuit = U254::add_without_carry(
    //         U254::wires_set_from_number(&a),
    //         U254::wires_set_from_number(&b),
    //     );
    //     circuit.gate_counts().print();
    //     for mut gate in circuit.1 {
    //         gate.evaluate();
    //     }
    //     let c = biguint_from_wires(circuit.0);
    //     assert_eq!(c, (a + b) % biguint_two_pow_254());
    // }
    //
    // #[test]
    // fn test_sub() {
    //     let mut a = random_biguint_n_bits(254);
    //     let mut b = random_biguint_n_bits(254);
    //     if a < b {
    //         (a, b) = (b, a);
    //     }
    //     let circuit = U254::sub_without_borrow(
    //         U254::wires_set_from_number(&a),
    //         U254::wires_set_from_number(&b),
    //     );
    //     circuit.gate_counts().print();
    //     for mut gate in circuit.1 {
    //         gate.evaluate();
    //     }
    //     let c = biguint_from_wires(circuit.0);
    //     assert_eq!(c, a - b);
    // }
    //
    // #[test]
    // fn test_sub_without_borrow() {
    //     let mut a = random_biguint_n_bits(254);
    //     let mut b = random_biguint_n_bits(254);
    //     if a < b {
    //         (a, b) = (b, a);
    //     }
    //     let circuit = U254::sub_without_borrow(
    //         U254::wires_set_from_number(&a),
    //         U254::wires_set_from_number(&b),
    //     );
    //     circuit.gate_counts().print();
    //     for mut gate in circuit.1 {
    //         gate.evaluate();
    //     }
    //     let c = biguint_from_wires(circuit.0);
    //     assert_eq!(c, (a - b) % biguint_two_pow_254());
    // }
    //
    // #[test]
    // fn test_double() {
    //     let a = random_biguint_n_bits(254);
    //     let circuit = U254::double(U254::wires_set_from_number(&a));
    //     circuit.gate_counts().print();
    //     for mut gate in circuit.1 {
    //         gate.evaluate();
    //     }
    //     let c = biguint_from_wires(circuit.0);
    //     assert_eq!(c, a.clone() + a);
    // }
    //
    // #[test]
    // fn test_double_without_overflow() {
    //     let a = random_biguint_n_bits(254);
    //     let circuit = U254::double_without_overflow(U254::wires_set_from_number(&a));
    //     circuit.gate_counts().print();
    //     for mut gate in circuit.1 {
    //         gate.evaluate();
    //     }
    //     let c = biguint_from_wires(circuit.0);
    //     assert_eq!(c, (a.clone() + a) % biguint_two_pow_254());
    // }
    //
    // #[test]
    // fn test_half() {
    //     let a = random_biguint_n_bits(254);
    //     let circuit = U254::half(U254::wires_set_from_number(&a));
    //     circuit.gate_counts().print();
    //     for mut gate in circuit.1 {
    //         gate.evaluate();
    //     }
    //     let c = biguint_from_wires(circuit.0);
    //     let d = a.clone() - c.clone() - c.clone();
    //     assert!(d == BigUint::ZERO || d == BigUint::from_str("1").unwrap());
    // }
    //
    // #[test]
    // fn test_odd_part() {
    //     let a = random_biguint_n_bits(254);
    //     let circuit = U254::odd_part(U254::wires_set_from_number(&a));
    //     circuit.gate_counts().print();
    //     for mut gate in circuit.1 {
    //         gate.evaluate();
    //     }
    //     let c = biguint_from_wires(circuit.0[0..U254::N_BITS].to_vec());
    //     let d = biguint_from_wires(circuit.0[U254::N_BITS..2 * U254::N_BITS].to_vec());
    //     assert_eq!(a, c * d);
    // }
}
