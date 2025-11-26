use crate::{
    dv_bn254::{
        fp254impl::Fp254Impl, fq::Fq, fr::Fr,
    },
};
use crate::circuits::bn254::utils::create_rng;
use ark_ff::{AdditiveGroup, UniformRand};
use ark_ec::PrimeGroup;
use ark_ec::short_weierstrass::SWCurveConfig;
use crate::circuits::sect233k1::builder::CircuitTrait;
use crate::dv_bn254::basic::selector;
use crate::dv_bn254::fq::FQ_LEN;

#[derive(Debug, Clone)]
pub struct G1Projective {
    pub x: Fq,
    pub y: Fq,
    pub z: Fq,
}
pub const G1_PROJECTIVE_LEN: usize = 3 * FQ_LEN;
impl G1Projective {
    pub fn as_montgomery(p: ark_bn254::G1Projective) -> ark_bn254::G1Projective {
        ark_bn254::G1Projective {
            x: Fq::as_montgomery(p.x),
            y: Fq::as_montgomery(p.y),
            z: Fq::as_montgomery(p.z),
        }
    }

    pub fn from_montgomery(p: ark_bn254::G1Projective) -> ark_bn254::G1Projective {
        ark_bn254::G1Projective {
            x: Fq::from_montgomery(p.x),
            y: Fq::from_montgomery(p.y),
            z: Fq::from_montgomery(p.z),
        }
    }

    pub fn random() -> ark_bn254::G1Projective {
        let mut prng = create_rng();
        ark_bn254::G1Projective::rand(&mut prng)
    }

    pub fn to_bits(u: ark_bn254::G1Projective) -> Vec<bool> {
        let mut bits = Vec::new();
        bits.extend(Fq::to_bits(u.x));
        bits.extend(Fq::to_bits(u.y));
        bits.extend(Fq::to_bits(u.z));
        bits
    }

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::G1Projective {
        let bits1 = &bits[0..Fq::N_BITS].to_vec();
        let bits2 = &bits[Fq::N_BITS..Fq::N_BITS * 2].to_vec();
        let bits3 = &bits[Fq::N_BITS * 2..Fq::N_BITS * 3].to_vec();
        ark_bn254::G1Projective::new(
            Fq::from_bits(bits1.clone()),
            Fq::from_bits(bits2.clone()),
            Fq::from_bits(bits3.clone()),
        )
    }

    pub fn from_bits_unchecked(bits: Vec<bool>) -> ark_bn254::G1Projective {
        let bits1 = &bits[0..Fq::N_BITS].to_vec();
        let bits2 = &bits[Fq::N_BITS..Fq::N_BITS * 2].to_vec();
        let bits3 = &bits[Fq::N_BITS * 2..Fq::N_BITS * 3].to_vec();
        ark_bn254::G1Projective {
            x: Fq::from_bits(bits1.clone()),
            y: Fq::from_bits(bits2.clone()),
            z: Fq::from_bits(bits3.clone()),
        }
    }

    pub fn wires<T: CircuitTrait>(bld: &mut T) -> Self {
        Self {
            x: Fq::wires(bld),
            y: Fq::wires(bld),
            z: Fq::wires(bld),
        }
    }

    pub fn wires_set<T: CircuitTrait>(bld: &mut T, u: ark_bn254::G1Projective) -> Self {
        Self {
            x: Fq::wires_set(bld, u.x),
            y: Fq::wires_set(bld, u.y),
            z: Fq::wires_set(bld, u.z),
        }
    }

    pub fn wires_set_montgomery<T: CircuitTrait>(bld: &mut T, u: ark_bn254::G1Projective) -> Self {
        Self::wires_set(bld, Self::as_montgomery(u))
    }

    pub fn from_wires<T: CircuitTrait>(bld: &mut T, point: G1Projective) -> ark_bn254::G1Projective {
        let bits = point.x.0.iter()
            .chain(point.y.0.iter()).chain(point.z.0.iter())
            .map(|wire| {
                if *wire != bld.one() && *wire != bld.zero() {
                    panic!("wire value is not set properly");
                }
                *wire == bld.one()
            })
            .collect::<Vec<bool>>();
        Self::from_bits(bits)
    }

    pub fn from_wires_unchecked<T: CircuitTrait>(bld: &mut T, point: G1Projective) -> ark_bn254::G1Projective {
        let bits = point.x.0.iter()
            .chain(point.y.0.iter()).chain(point.z.0.iter())
            .map(|wire| {
                if *wire != bld.one() && *wire != bld.zero() {
                    panic!("wire value is not set properly");
                }
                *wire == bld.one()
            })
            .collect::<Vec<bool>>();
        Self::from_bits_unchecked(bits)
    }

    pub fn from_montgomery_wires_unchecked<T: CircuitTrait>(bld: &mut T, point: G1Projective) -> ark_bn254::G1Projective {
        Self::from_montgomery(Self::from_wires_unchecked(bld, point))
    }

    pub fn to_vec_wires(&self) -> Vec<usize> {
        let mut res = Vec::new();
        res.extend(self.x.0);
        res.extend(self.y.0);
        res.extend(self.z.0);
        res
    }

    pub fn equal<T: CircuitTrait>(bld: &mut T, p_a: &[usize], p_b: &[usize]) -> usize {
        assert_eq!(p_a.len(), G1_PROJECTIVE_LEN);
        assert_eq!(p_b.len(), G1_PROJECTIVE_LEN);

        // The points (X, Y, Z) and (X', Y', Z')
        // are equal when (X * Z^2) = (X' * Z'^2)
        // and (Y * Z^3) = (Y' * Z'^3).
        let x = p_a[0..Fq::N_BITS].to_vec();
        let y = p_a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let z = p_a[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();
        let x_prime = p_b[0..Fq::N_BITS].to_vec();
        let y_prime = p_b[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let z_prime = p_b[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();

        let z2 = Fq::square_montgomery(bld, &z);
        let z3 = Fq::mul_montgomery(bld, &z, &z2);
        let z_prime2 = Fq::square_montgomery(bld, &z_prime);
        let z_prime3 = Fq::mul_montgomery(bld, &z_prime, &z_prime2);

        let lhs_x = Fq::mul_montgomery(bld, &x, &z_prime2);
        let rhs_x = Fq::mul_montgomery(bld, &x_prime, &z2);

        let lhs_y = Fq::mul_montgomery(bld, &y, &z_prime3);
        let rhs_y = Fq::mul_montgomery(bld, &y_prime, &z3);

        let eq_x = Fq::equal(bld, &lhs_x, &rhs_x);
        let eq_y = Fq::equal(bld, &lhs_y, &rhs_y);
        bld.and_wire(eq_x, eq_y)
    }
}

impl G1Projective {
    pub fn emit_projective_montgomery_point_is_on_curve<T: CircuitTrait>(
        bld: &mut T,
        p: &G1Projective,
    ) -> usize {
        // Y^2 = X^3 + b
        let affine_p = projective_to_affine_montgomery(bld, &p);

        let y2 = Fq::square_montgomery(bld, &affine_p.y.0);
        // let lhs = Fq::mul_by_constant_montgomery(bld, &y2, Fq::from_montgomery(ark_bn254::Fq::from(Fq::montgomery_r_as_biguint())));
        let x2 = Fq::square_montgomery(bld, &affine_p.x.0);
        let x3 = Fq::mul_montgomery(bld, &affine_p.x.0, &x2);
        let x3b = Fq::add_constant(bld, &x3, Fq::as_montgomery(ark_bn254::g1::Config::COEFF_B));
        // let rhs = Fq::add_constant(bld, &x3, ark_bn254::Fq::from(Fq::b_mul_as_biguint()));
        Fq::equal(bld, &y2, &x3b)
    }

    // http://koclab.cs.ucsb.edu/teaching/ccs130h/2018/09projective.pdf
    pub fn add_montgomery<T: CircuitTrait>(bld: &mut T, p: &[usize], q: &[usize]) -> Vec<usize> {
        assert_eq!(p.len(), G1_PROJECTIVE_LEN);
        assert_eq!(q.len(), G1_PROJECTIVE_LEN);
    
        let x1 = p[0..Fq::N_BITS].to_vec();
        let y1 = p[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let z1 = p[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();
        let x2 = q[0..Fq::N_BITS].to_vec();
        let y2 = q[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let z2 = q[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();
    
        let z1s = Fq::square_montgomery(bld, &z1);
        let z2s = Fq::square_montgomery(bld, &z2);
        let z1c = Fq::mul_montgomery(bld, &z1s, &z1);
        let z2c = Fq::mul_montgomery(bld, &z2s, &z2);
        let u1 = Fq::mul_montgomery(bld, &x1, &z2s);
        let u2 = Fq::mul_montgomery(bld, &x2, &z1s);
        let s1 = Fq::mul_montgomery(bld, &y1, &z2c);
        let s2 = Fq::mul_montgomery(bld, &y2, &z1c);
        let r = Fq::sub(bld, &s1, &s2);
        let h = Fq::sub(bld, &u1, &u2);
        let h2 = Fq::square_montgomery(bld, &h);
        let g = Fq::mul_montgomery(bld, &h, &h2);
        let v = Fq::mul_montgomery(bld, &u1, &h2);
        let r2 = Fq::square_montgomery(bld, &r);
        let r2g = Fq::add(bld, &r2, &g);
        let vd = Fq::double(bld, &v);
        let x3 = Fq::sub(bld, &r2g, &vd);
        let vx3 = Fq::sub(bld, &v, &x3);
        let w = Fq::mul_montgomery(bld, &r, &vx3);
        let s1g = Fq::mul_montgomery(bld, &s1, &g);
        let y3 = Fq::sub(bld, &w, &s1g);
        let z1z2 = Fq::mul_montgomery(bld, &z1, &z2);
        let z3 = Fq::mul_montgomery(bld, &z1z2, &h);
    
        let z1_0 = Fq::equal_zero(bld, &z1);
        let z2_0 = Fq::equal_zero(bld, &z2);
        let zero = Fq::wires_set(bld, ark_bn254::Fq::ZERO);
        let s = vec![z1_0, z2_0];
        let x = Fq::multiplexer(bld, &vec![x3, x2, x1, zero.0.to_vec()], &s, 2);
        let y = Fq::multiplexer(bld, &vec![y3, y2, y1, zero.0.to_vec()], &s, 2);
        let z = Fq::multiplexer(bld, &vec![z3, z2, z1, zero.0.to_vec()], &s, 2);
    
        let mut res = Vec::new();
        res.extend(x);
        res.extend(y);
        res.extend(z);
        res
    }
    
    pub fn double_montgomery<T: CircuitTrait>(bld: &mut T, p: &[usize]) -> Vec<usize> {
        assert_eq!(p.len(), G1_PROJECTIVE_LEN);

        let x = p[0..Fq::N_BITS].to_vec();
        let y = p[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let z = p[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();
    
        let x2 = Fq::square_montgomery(bld, &x);
        let y2 = Fq::square_montgomery(bld, &y);
        let m = Fq::triple(bld, &x2);
        let t = Fq::square_montgomery(bld, &y2);
        let xy2 = Fq::mul_montgomery(bld, &x, &y2);
        let xy2d = Fq::double(bld, &xy2);
        let s = Fq::double(bld, &xy2d);
        let m2 = Fq::square_montgomery(bld, &m);
        let sd = Fq::double(bld, &s);
        let xr = Fq::sub(bld, &m2, &sd);
        let sxr = Fq::sub(bld, &s, &xr);
        let msxr = Fq::mul_montgomery(bld, &m, &sxr);
        let td = Fq::double(bld, &t);
        let tdd = Fq::double(bld, &td);
        let tddd = Fq::double(bld, &tdd);
        let yr = Fq::sub(bld, &msxr, &tddd);
        let yz = Fq::mul_montgomery(bld, &y, &z);
        let zr = Fq::double(bld, &yz);
    
        let z_0 = Fq::equal_zero(bld, &z);
        let zero = Fq::wires_set(bld, ark_bn254::Fq::ZERO);
        let z = Fq::multiplexer(bld, &vec![zr, zero.0.to_vec()], &[z_0], 1);

        let mut res = Vec::new();
        res.extend(xr);
        res.extend(yr);
        res.extend(z);
    
        res
    }

    // pub fn scalar_mul<T: CircuitTrait>(bld: &mut T, p: &[usize], s: &[usize]) -> Vec<usize> {
    //
    // }

    // pub fn multiplexer<T: CircuitTrait>(bld: &mut T, a: &Vec<Vec<usize>>, s: &[usize], w: usize) -> Vec<usize> {
    //     let n = 2_usize.pow(w.try_into().unwrap());
    //     assert_eq!(a.len(), n);
    //     for x in a.iter() {
    //         assert_eq!(x.len(), G1_PROJECTIVE_LEN);
    //     }
    //     assert_eq!(s.len(), w);
    //     let mut res = Vec::new();
    //     for i in 0..G1_PROJECTIVE_LEN {
    //         let ith_wires: Vec<usize> = a.iter().map(|x| x[i].clone()).collect();
    //         let ith_result = multiplexer(bld, &ith_wires, s.clone(), w);
    //         res.push(ith_result);
    //     }
    //     res
    // }

    pub fn selector_projective_montgomery<T: CircuitTrait>(
        bld: &mut T,
        a: &[usize],
        b: &[usize],
        c: usize,
    ) -> Vec<usize> {
        assert_eq!(a.len(), G1_PROJECTIVE_LEN);
        assert_eq!(b.len(), G1_PROJECTIVE_LEN);
        let mut res = Vec::new();
        for i in 0..G1_PROJECTIVE_LEN {
            let selected_wire = selector(bld, a[i], b[i], c);
            res.push(selected_wire);
        }
        res
    }

    pub fn scalar_mul_montgomery_circuit(
        bld: &mut impl CircuitTrait,
        s: &[usize],
        point: &[usize],
    ) -> Vec<usize> {
        // use double and add
        assert_eq!(s.len(), Fr::N_BITS);
        assert_eq!(point.len(), G1_PROJECTIVE_LEN);

        // if s == 0 return point at infinity
        let inf_point = ark_bn254::G1Projective::default();
        let inf_point_wires = G1Projective::wires_set(bld, inf_point);
        let mut res = inf_point_wires.to_vec_wires();
        let mut point_pow = point.to_vec();
        let inf_wires = inf_point_wires.to_vec_wires();
        for index in 0..Fr::N_BITS {
            let selector = s[index];
            // if selector, res = res + pow_point
            // else: res = res + zero
            let added = Self::selector_projective_montgomery(
                bld,
                &point_pow,
                &inf_wires,
                selector,
            );
            res = Self::add_montgomery(bld, &res, &added);
            // double point_pow
            if index != Fr::N_BITS - 1 {
                point_pow = Self::double_montgomery(bld, &point_pow);
            }
        }
        res
    }

    pub fn msm_montgomery_circuit<T: CircuitTrait>(
        bld: &mut T,
        scalars: &[Vec<usize>],
        points: &[Vec<usize>],
    ) -> Vec<usize> {
        let n = scalars.len();
        assert_eq!(scalars.len(), points.len());
        for i in 0..n {
            assert_eq!(scalars[i].len(), Fr::N_BITS);
            assert_eq!(points[i].len(), G1_PROJECTIVE_LEN);
        }

        let inf_point = ark_bn254::G1Projective::default();
        let inf_point_wires = G1Projective::wires_set(bld, inf_point);
        let mut res = inf_point_wires.to_vec_wires();

        for i in 0..n {
            let sm = Self::scalar_mul_montgomery_circuit(bld, &scalars[i], &points[i]);
            res = Self::add_montgomery(bld, &res, &sm);
        }

        res
    }

    pub fn wires_set_montgomery_generator<T: CircuitTrait>(
        bld: &mut T,
    ) -> Vec<usize> {
        let gen_point = ark_bn254::G1Projective::generator();
        let mont_gen = G1Projective::as_montgomery(gen_point);
        let gen_wires = G1Projective::wires_set(bld, mont_gen);
        gen_wires.to_vec_wires()
    }
}

pub struct G1Affine {
    pub x: Fq,
    pub y: Fq,
}
pub const G1_AFFINE_LEN: usize = 2 * FQ_LEN;

pub fn projective_to_affine_montgomery<T: CircuitTrait>(bld: &mut T, p_point: &G1Projective) -> G1Affine {

    let z_inverse = Fq::inverse_montgomery(bld, &p_point.z.0);
    let z_inverse_square = Fq::square_montgomery(bld, &z_inverse);
    let z_inverse_cube = Fq::mul_montgomery(bld, &z_inverse, &z_inverse_square);
    let new_x = Fq::mul_montgomery(bld, &p_point.x.0, &z_inverse_square);
    let new_y = Fq::mul_montgomery(bld, &p_point.y.0, &z_inverse_cube);
    
    G1Affine {
        x: Fq(new_x.try_into().unwrap()),
        y: Fq(new_y.try_into().unwrap()),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use ark_ec::CurveGroup;
    use ark_ff::{AdditiveGroup, Field};
    use crate::circuits::sect233k1::builder::{CircuitAdapter, CircuitTrait};
    use crate::dv_bn254::fp254impl::Fp254Impl;
    use crate::dv_bn254::fq::Fq;
    use crate::dv_bn254::fr::Fr;
    use crate::dv_bn254::g1::{projective_to_affine_montgomery, G1Projective};

    #[test]
    fn sub_montgomery_test() {
        let t0 = ark_bn254::Fr::from_str("7732983886091688221498675126584431356840007664582939941724679283817292177916").unwrap();
        let i0 = ark_bn254::Fr::from_str("4309415654564185098055313613053571962808436852931865757620162477615162115501").unwrap();
        let r0 = t0 - i0;
        println!("{:?}", r0);
        let mut bld = CircuitAdapter::default();
        let t_wires = Fr::wires(&mut bld);
        let i_wires = Fr::wires(&mut bld);
        let r_wires = Fr::sub(&mut bld, &t_wires.0.to_vec(), &i_wires.0.to_vec());

        let witness = Fr::to_bits(Fr::as_montgomery(t0))
            .into_iter()
            .chain(Fr::to_bits(Fr::as_montgomery(i0)))
            .collect::<Vec<bool>>();

        let wires_bits = bld.eval_gates(&witness);
        let r_bits: Vec<bool> = r_wires.iter().map(|id| wires_bits[*id]).collect();
        let r_res = Fr::from_bits(r_bits);
        assert_eq!(r_res, Fr::as_montgomery(r0));
    }

    #[test]
    fn test_demo_verfier_vjp() {
        let p1 = G1Projective::random();
        let mont_p1 = G1Projective::as_montgomery(p1);

        let s1 = Fr::random();
        let mont_s1 = Fr::as_montgomery(s1);

        let p1s1 = p1 * s1;
        let mont_p1s1 = G1Projective::as_montgomery(p1s1);
        let mont_r = ark_bn254::Fr::from(Fr::montgomery_r_as_biguint());

        let mut bld = CircuitAdapter::default();
        let p1_mont_wires = G1Projective::wires(&mut bld);
        let p1s1_mont_wires = G1Projective::wires(&mut bld);
        let mont_s1_wires = Fr::wires(&mut bld);
        let mont_r_wires = Fr::wires_set(&mut bld, mont_r.clone());
        let lhs_wires = G1Projective::scalar_mul_montgomery_circuit(
            &mut bld,
            &mont_s1_wires.0.to_vec(),
            &p1_mont_wires.to_vec_wires(),
        );

        let rhs_wires = G1Projective::scalar_mul_montgomery_circuit(
            &mut bld,
            &mont_r_wires.0.to_vec(),
            &p1s1_mont_wires.to_vec_wires(),
        );

        let witness = G1Projective::to_bits(mont_p1)
            .into_iter()
            .chain(G1Projective::to_bits(mont_p1s1))
            .chain(Fr::to_bits(mont_s1).into_iter())
            // .chain(Fr::to_bits(s2).into_iter())
            .collect::<Vec<bool>>();

        let wires_bits = bld.eval_gates(&witness);
        let lhs_bits = lhs_wires.iter().map(|id| wires_bits[*id]).collect();
        let rhs_bits = rhs_wires.iter().map(|id| wires_bits[*id]).collect();

        let stats = bld.gate_counts();
        println!("{stats}");

        let lhs = G1Projective::from_bits_unchecked(lhs_bits);
        let rhs = G1Projective::from_bits_unchecked(rhs_bits);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_equal_g1ps() {
        let p1 = G1Projective::random().double();
        let p1_a = p1.into_affine();
        let p2: ark_bn254::G1Projective = p1_a.into();

        println!("p1: {:?}", p1);
        println!("p2: {:?}", p2);

        let mut bld = CircuitAdapter::default();
        let p1_wires = G1Projective::wires(&mut bld);
        let p2_wires = G1Projective::wires(&mut bld);
        let eq_wire = G1Projective::equal(&mut bld, &p1_wires.to_vec_wires(), &p2_wires.to_vec_wires());
        let witness = G1Projective::to_bits(p1)
            .into_iter()
            .chain(G1Projective::to_bits(p2))
            .collect::<Vec<bool>>();

        let wires_bits = bld.eval_gates(&witness);
        let eq_value = wires_bits[eq_wire];
        assert_eq!(eq_value, true);
    }

    #[test]
    fn test_msm_vjp() {
        let p1 = G1Projective::random();
        let p2 = G1Projective::random();
        let mont_p1 = G1Projective::as_montgomery(p1);
        let mont_p2 = G1Projective::as_montgomery(p2);

        let s1 = Fr::random();
        let s2 = Fr::random();

        let mut bld = CircuitAdapter::default();
        let p1_wires = G1Projective::wires(&mut bld);
        let p2_wires = G1Projective::wires(&mut bld);
        let s1_wires = Fr::wires(&mut bld);
        let s2_wires = Fr::wires(&mut bld);
        let out_wires = G1Projective::msm_montgomery_circuit(
            &mut bld,
            &vec![s1_wires.0.to_vec(), s2_wires.0.to_vec()],
            &vec![p1_wires.to_vec_wires(), p2_wires.to_vec_wires()],
        );
        let witness = G1Projective::to_bits(mont_p1)
            .into_iter()
            .chain(G1Projective::to_bits(mont_p2))
            .chain(Fr::to_bits(s1).into_iter())
            .chain(Fr::to_bits(s2).into_iter())
            .collect::<Vec<bool>>();

        let wires_bits = bld.eval_gates(&witness);
        let out_bits: Vec<bool> = out_wires.iter().map(|id| wires_bits[*id]).collect();
        let result = G1Projective::from_bits_unchecked(out_bits);
        assert_eq!(result, G1Projective::as_montgomery(p1 * s1 + p2 * s2));

        let stats = bld.gate_counts();
        println!("{stats}");
    }

    #[test]
    fn test_g1p_scalar_mul_montgomery_circuit_vjp() {
        let point = G1Projective::random();
        let mont_p = G1Projective::as_montgomery(point);
        let s = Fr::random();

        let mut bld = CircuitAdapter::default();
        let point_wires = G1Projective::wires(&mut bld);
        let s_wires = Fr::wires(&mut bld);
        let out_wires = G1Projective::scalar_mul_montgomery_circuit(
            &mut bld,
            &s_wires.0,
            &point_wires.to_vec_wires(),
        );
        let witness = G1Projective::to_bits(mont_p)
            .into_iter()
            .chain(Fr::to_bits(s).into_iter())
            .collect::<Vec<bool>>();

        let wires_bits = bld.eval_gates(&witness);
        let out_bits: Vec<bool> = out_wires.iter().map(|id| wires_bits[*id]).collect();
        let result = G1Projective::from_bits_unchecked(out_bits);
        assert_eq!(result, G1Projective::as_montgomery(point * s));

        let stats = bld.gate_counts();
        println!("{stats}");
    }

    #[test]
    fn test_g1p_add_montgomery_vjp() {
        let a = G1Projective::random();
        let b = ark_bn254::G1Projective::ZERO;
        let mont_a = G1Projective::as_montgomery(a);
        let mont_b = G1Projective::as_montgomery(b);

        let mut bld = CircuitAdapter::default();
        let a_wires = G1Projective::wires(&mut bld);
        let b_wires = G1Projective::wires(&mut bld);
        let out_wires = G1Projective::add_montgomery(
            &mut bld,
            &a_wires.to_vec_wires(),
            &b_wires.to_vec_wires(),
        );
        let witness = G1Projective::to_bits(mont_a)
            .into_iter()
            .chain(G1Projective::to_bits(mont_b).into_iter())
            .collect::<Vec<bool>>();
        let wires_bits = bld.eval_gates(&witness);
        let out_bits: Vec<bool> = out_wires.iter().map(|id| wires_bits[*id]).collect();
        let c = G1Projective::from_bits_unchecked(out_bits);
        assert_eq!(c, G1Projective::as_montgomery(a + b));
    }

    #[test]
    fn test_fq_inverse_montgomery_vjp() {
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

    #[test]
    fn projective_to_affine_bn254() {
        let p_projective = G1Projective::random().double();
        assert_ne!(p_projective.z, ark_bn254::Fq::ONE);
        let p_affine = p_projective.into_affine();

        let mont_pp = G1Projective::as_montgomery(p_projective);

        let mut bld = CircuitAdapter::default();
        let point = G1Projective::wires(&mut bld);
        let witness =  G1Projective::to_bits(mont_pp);
        let output_wires = projective_to_affine_montgomery(&mut bld, &point);

        let stats = bld.gate_counts();
        println!("{stats}");

        let wires = bld.eval_gates(&witness);
        let affine_x: Vec<bool> = output_wires.x.0.iter().map(|id| wires[*id]).collect();
        let affine_y: Vec<bool> = output_wires.y.0.iter().map(|id| wires[*id]).collect();

        let affine_x_value = Fq::from_bits(affine_x);
        let affine_y_value = Fq::from_bits(affine_y);
        let x = Fq::from_montgomery(affine_x_value);
        let y = Fq::from_montgomery(affine_y_value);

        assert_eq!(x, p_affine.x);
        assert_eq!(y, p_affine.y);
    }

    #[test]
    fn point_on_curve_bn254() {
        let p_projective = G1Projective::random().double();
        assert_ne!(p_projective.z, ark_bn254::Fq::ONE);
        let mont_p = G1Projective::as_montgomery(p_projective);

        let mut bld = CircuitAdapter::default();
        let p_wires = G1Projective::wires(&mut bld);
        let witness =  G1Projective::to_bits(mont_p);
        let out_wire = G1Projective::emit_projective_montgomery_point_is_on_curve(&mut bld, &p_wires);

        let wires = bld.eval_gates(&witness);
        let out_bit = wires[out_wire];
        assert!(out_bit);

        let stats = bld.gate_counts();
        println!("{stats}");
    }
}
//     use crate::circuits::bn254::utils::create_rng;
//
//     use super::*;
//     use ark_ec::{CurveGroup, scalar_mul::variable_base::VariableBaseMSM};
//     use ark_ff::Field;
//     use rand::Rng;
//
//     #[test]
//     fn test_g1p_random() {
//         let u = G1Projective::random();
//         println!("u: {:?}", u);
//         let b = G1Projective::to_bits(u);
//         let v = G1Projective::from_bits(b);
//         println!("v: {:?}", v);
//         assert_eq!(u, v);
//     }
//
//     #[test]
//     fn test_g1p_add_montgomery() {
//         let a = G1Projective::random();
//         let b = G1Projective::random();
//         let c = ark_bn254::G1Projective::ZERO;
//         let circuit = G1Projective::add_montgomery(
//             G1Projective::wires_set_montgomery(a),
//             G1Projective::wires_set_montgomery(b),
//         );
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let d = G1Projective::from_wires_unchecked(circuit.0);
//         assert_eq!(d, G1Projective::as_montgomery(a + b));
//
//         let circuit = G1Projective::add_montgomery(
//             G1Projective::wires_set_montgomery(a),
//             G1Projective::wires_set_montgomery(c),
//         );
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let d = G1Projective::from_wires_unchecked(circuit.0);
//         assert_eq!(d, G1Projective::as_montgomery(a));
//
//         let circuit = G1Projective::add_montgomery(
//             G1Projective::wires_set_montgomery(c),
//             G1Projective::wires_set_montgomery(b),
//         );
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let d = G1Projective::from_wires_unchecked(circuit.0);
//         assert_eq!(d, G1Projective::as_montgomery(b));
//
//         let circuit = G1Projective::add_montgomery(
//             G1Projective::wires_set_montgomery(c),
//             G1Projective::wires_set_montgomery(c),
//         );
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let d = G1Projective::from_wires_unchecked(circuit.0);
//         assert_eq!(d, G1Projective::as_montgomery(c));
//     }
//
//     #[test]
//     fn test_g1p_double_montgomery() {
//         let a = G1Projective::random();
//         let circuit = G1Projective::double_montgomery(G1Projective::wires_set_montgomery(a));
//         circuit.gate_counts().print();
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let c = G1Projective::from_wires_unchecked(circuit.0);
//         assert_eq!(c, G1Projective::as_montgomery(a + a));
//
//         let b = ark_bn254::G1Projective::ZERO;
//         let circuit = G1Projective::double_montgomery(G1Projective::wires_set_montgomery(b));
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//         let c = G1Projective::from_wires_unchecked(circuit.0);
//         assert_eq!(c, G1Projective::as_montgomery(b));
//     }
//
//     #[test]
//     fn test_g1p_multiplexer() {
//         let w = 10;
//         let n = 2_usize.pow(w as u32);
//         let a: Vec<ark_bn254::G1Projective> = (0..n).map(|_| G1Projective::random()).collect();
//         let s: Wires = (0..w).map(|_| new_wirex()).collect();
//
//         let mut a_wires = Vec::new();
//         for e in a.iter() {
//             a_wires.push(G1Projective::wires_set(*e));
//         }
//
//         let mut u = 0;
//         for wire in s.iter().rev() {
//             let mut rng = create_rng();
//
//             let x = rng.r#gen();
//             u = u + u + if x { 1 } else { 0 };
//             wire.borrow_mut().set(x);
//         }
//
//         let circuit = G1Projective::multiplexer(a_wires, s.clone(), w);
//         circuit.gate_counts().print();
//
//         for mut gate in circuit.1 {
//             gate.evaluate();
//         }
//
//         let result = G1Projective::from_wires(circuit.0);
//         let expected = a[u];
//
//         assert_eq!(result, expected);
//     }
//
//     #[test]
//     fn test_g1p_multiplexer_evaluate() {
//         let w = 10;
//         let n = 2_usize.pow(w as u32);
//         let a: Vec<ark_bn254::G1Projective> = (0..n).map(|_| G1Projective::random()).collect();
//         let s: Wires = (0..w).map(|_| new_wirex()).collect();
//
//         let mut rng = create_rng();
//         let mut a_wires = Vec::new();
//         for e in a.iter() {
//             a_wires.push(G1Projective::wires_set(*e));
//         }
//
//         let mut u = 0;
//         for wire in s.iter().rev() {
//             let x = rng.r#gen();
//             u = u + u + if x { 1 } else { 0 };
//             wire.borrow_mut().set(x);
//         }
//
//         let (result_wires, gate_count) = G1Projective::multiplexer_evaluate(a_wires, s.clone(), w);
//         gate_count.print();
//         let result = G1Projective::from_wires(result_wires);
//         let expected = a[u];
//
//         assert_eq!(result, expected);
//     }
//
//     // #[test]
//     // fn test_g1p_scalar_mul_with_constant_base_evaluate_montgomery() {
//     //     let base = G1Projective::random();
//     //     let s = Fr::random();
//     //     let (result_wires, gate_count) =
//     //         G1Projective::scalar_mul_by_constant_base_evaluate_montgomery::<10>(
//     //             Fr::wires_set(s),
//     //             base,
//     //         );
//     //     gate_count.print();
//     //     let result = G1Projective::from_wires_unchecked(result_wires);
//     //     assert_eq!(result, G1Projective::as_montgomery(base * s));
//     // }
//     //
//     // #[test]
//     // fn test_msm_with_constant_bases_evaluate_montgomery() {
//     //     let n = 1;
//     //     let bases = (0..n).map(|_| G1Projective::random()).collect::<Vec<_>>();
//     //     let scalars = (0..n).map(|_| Fr::random()).collect::<Vec<_>>();
//     //     let (result_wires, gate_count) =
//     //         G1Projective::msm_with_constant_bases_evaluate_montgomery::<10>(
//     //             scalars.iter().map(|s| Fr::wires_set(*s)).collect(),
//     //             bases.clone(),
//     //         );
//     //     gate_count.print();
//     //     let result = G1Projective::from_wires_unchecked(result_wires);
//     //     let bases_affine = bases.iter().map(|g| g.into_affine()).collect::<Vec<_>>();
//     //     let expected = ark_bn254::G1Projective::msm(&bases_affine, &scalars).unwrap();
//     //     assert_eq!(result, G1Projective::as_montgomery(expected));
//     // }
// }
