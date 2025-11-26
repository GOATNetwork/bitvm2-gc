use crate::circuits::sect233k1::builder::CircuitTrait;

#[inline]
pub fn not<T: CircuitTrait>(b: &mut T, x: usize) -> usize {
    let one_gate = b.one();
    b.xor_wire(x, one_gate)
}

pub fn half_adder<T: CircuitTrait>(bld: &mut T, a: usize, b: usize) -> Vec<usize> {
    let result = bld.xor_wire(a, b);
    let carry = bld.and_wire(a, b);
    vec![result, carry]
}

pub fn full_adder<T: CircuitTrait>(bld: &mut T, a: usize, b: usize, c: usize) -> Vec<usize> {
    let axc = bld.xor_wire(a, c);
    let bxc = bld.xor_wire(b, c);
    let result = bld.xor_wire(a, bxc);
    let t = bld.and_wire(axc, bxc);
    let carry = bld.xor_wire(c, t);
    vec![result, carry]
}

pub fn half_subtracter<T: CircuitTrait>(bld: &mut T, a: usize, b: usize) -> Vec<usize> {
    let result = bld.xor_wire(a, b);
    let not_a = not(bld, a);
    let borrow = bld.and_wire(not_a, b);
    vec![result, borrow]
}

pub fn full_subtracter<T: CircuitTrait>(bld: &mut T, a: usize, b: usize, c: usize) -> Vec<usize> {
    let bxa = bld.xor_wire(a, b);
    let bxc = bld.xor_wire(b, c);
    let result = bld.xor_wire(bxa, c);
    let t = bld.and_wire(bxa, bxc);
    let carry = bld.xor_wire(c, t);
    vec![result, carry]

}

pub fn selector<T: CircuitTrait>(bld: &mut T, a: usize, b: usize, c: usize) -> usize {
    let not_c = not(bld, c);
    let a_and_c = bld.and_wire(a, c);
    let b_and_not_c = bld.and_wire(b, not_c);
    bld.or_wire(a_and_c, b_and_not_c)
}

pub fn multiplexer<T: CircuitTrait>(bld: &mut T, a: &[usize], s: &[usize], w: usize) -> usize {
    let n = 2_usize.pow(w.try_into().unwrap());
    assert_eq!(a.len(), n);
    assert_eq!(s.len(), w);
    
    if w == 1 {
        return selector(bld, a[1], a[0], s[0]);
    }
    
    let a1 = a[0..(n / 2)].to_vec();
    let a2 = a[(n / 2)..n].to_vec();
    let su = s[0..w - 1].to_vec();
    let sv = s[w - 1].clone();
    
    let b1 = multiplexer(bld, &a1, &su, w - 1);
    let b2 = multiplexer(bld, &a2, &su, w - 1);
    
    selector(bld, b2, b1, sv)
}

// #[cfg(test)]
// mod tests {
//     use rand::Rng;
//
//     use crate::{
//         bag::*,
//         circuits::{
//             basic::{
//                 full_adder, full_subtracter, half_adder, half_subtracter, multiplexer, selector,
//             },
//             bn254::utils::create_rng,
//         },
//     };
//
//     #[test]
//     fn test_half_adder() {
//         let result = [
//             ((false, false), (false, false)),
//             ((false, true), (true, false)),
//             ((true, false), (true, false)),
//             ((true, true), (false, true)),
//         ];
//
//         for ((a, b), (c, d)) in result {
//             let a_wire = new_wirex();
//             a_wire.borrow_mut().set(a);
//
//             let b_wire = new_wirex();
//             b_wire.borrow_mut().set(b);
//
//             let circuit = half_adder(a_wire, b_wire);
//
//             for mut gate in circuit.1 {
//                 gate.evaluate();
//             }
//
//             let (c_wire, d_wire) = (circuit.0[0].clone(), circuit.0[1].clone());
//
//             assert_eq!(c_wire.borrow().get_value(), c);
//             assert_eq!(d_wire.borrow().get_value(), d);
//         }
//     }
//
//     #[test]
//     fn test_full_adder() {
//         let result = [
//             ((false, false, false), (false, false)),
//             ((false, false, true), (true, false)),
//             ((false, true, false), (true, false)),
//             ((false, true, true), (false, true)),
//             ((true, false, false), (true, false)),
//             ((true, false, true), (false, true)),
//             ((true, true, false), (false, true)),
//             ((true, true, true), (true, true)),
//         ];
//
//         for ((a, b, c), (d, e)) in result {
//             let a_wire = new_wirex();
//             a_wire.borrow_mut().set(a);
//
//             let b_wire = new_wirex();
//             b_wire.borrow_mut().set(b);
//
//             let c_wire = new_wirex();
//             c_wire.borrow_mut().set(c);
//
//             let circuit = full_adder(a_wire, b_wire, c_wire);
//
//             for mut gate in circuit.1 {
//                 gate.evaluate();
//             }
//
//             let (d_wire, e_wire) = (circuit.0[0].clone(), circuit.0[1].clone());
//
//             assert_eq!(d_wire.borrow().get_value(), d);
//             assert_eq!(e_wire.borrow().get_value(), e);
//         }
//     }
//
//     #[test]
//     fn test_half_subtracter() {
//         let result = [
//             ((false, false), (false, false)),
//             ((false, true), (true, true)),
//             ((true, false), (true, false)),
//             ((true, true), (false, false)),
//         ];
//
//         for ((a, b), (c, d)) in result {
//             let a_wire = new_wirex();
//             a_wire.borrow_mut().set(a);
//
//             let b_wire = new_wirex();
//             b_wire.borrow_mut().set(b);
//
//             let circuit = half_subtracter(a_wire, b_wire);
//
//             for mut gate in circuit.1 {
//                 gate.evaluate();
//             }
//
//             let (c_wire, d_wire) = (circuit.0[0].clone(), circuit.0[1].clone());
//
//             assert_eq!(c_wire.borrow().get_value(), c);
//             assert_eq!(d_wire.borrow().get_value(), d);
//         }
//     }
//
//     #[test]
//     fn test_full_subtracter() {
//         let result = [
//             ((false, false, false), (false, false)),
//             ((false, false, true), (true, true)),
//             ((false, true, false), (true, true)),
//             ((false, true, true), (false, true)),
//             ((true, false, false), (true, false)),
//             ((true, false, true), (false, false)),
//             ((true, true, false), (false, false)),
//             ((true, true, true), (true, true)),
//         ];
//
//         for ((a, b, c), (d, e)) in result {
//             let a_wire = new_wirex();
//             a_wire.borrow_mut().set(a);
//
//             let b_wire = new_wirex();
//             b_wire.borrow_mut().set(b);
//
//             let c_wire = new_wirex();
//             c_wire.borrow_mut().set(c);
//
//             let circuit = full_subtracter(a_wire, b_wire, c_wire);
//
//             for mut gate in circuit.1 {
//                 gate.evaluate();
//             }
//
//             let (d_wire, e_wire) = (circuit.0[0].clone(), circuit.0[1].clone());
//
//             assert_eq!(d_wire.borrow().get_value(), d);
//             assert_eq!(e_wire.borrow().get_value(), e);
//         }
//     }
//
//     #[test]
//     fn test_selector() {
//         let result = [
//             ((false, false, false), false),
//             ((false, false, true), false),
//             ((false, true, false), true),
//             ((false, true, true), false),
//             ((true, false, false), false),
//             ((true, false, true), true),
//             ((true, true, false), true),
//             ((true, true, true), true),
//         ];
//
//         for ((a, b, c), d) in result {
//             let a_wire = new_wirex();
//             a_wire.borrow_mut().set(a);
//
//             let b_wire = new_wirex();
//             b_wire.borrow_mut().set(b);
//
//             let c_wire = new_wirex();
//             c_wire.borrow_mut().set(c);
//
//             let circuit = selector(a_wire, b_wire, c_wire);
//
//             for mut gate in circuit.1 {
//                 gate.evaluate();
//             }
//
//             let d_wire = circuit.0[0].clone();
//
//             assert_eq!(d_wire.borrow().get_value(), d);
//         }
//     }
//
//     #[test]
//     fn test_multiplexer() {
//         let w = 5;
//         let n = 2_usize.pow(w as u32);
//         let a: Wires = (0..n).map(|_| new_wirex()).collect();
//         let s: Wires = (0..w).map(|_| new_wirex()).collect();
//
//         let mut rng = create_rng();
//         for wire in a.iter() {
//             wire.borrow_mut().set(rng.r#gen());
//         }
//
//         let mut u = 0;
//         for wire in s.iter().rev() {
//             let x = rng.r#gen();
//             u = u + u + if x { 1 } else { 0 };
//             wire.borrow_mut().set(x);
//         }
//
//         let circuit = multiplexer(a.clone(), s.clone(), w);
//         circuit.gate_counts().print();
//
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//
//         let result = circuit.0[0].clone().borrow().get_value();
//         let expected = a[u].clone().borrow().get_value();
//
//         assert_eq!(result, expected);
//     }
// }
