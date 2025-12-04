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
