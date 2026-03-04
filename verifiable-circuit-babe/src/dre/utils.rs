use std::ops::Mul;
use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand, Zero};
use rand::Rng;
use crate::dre::{L, N};

/// Sample n G1 points ρ₀, ρ₁, ..., ρ_{n-1} satisfying:
///   ∑_{i=0}^{n-1} 2^i · ρ_i = O  (point at infinity)
fn sample_rhos<R: Rng>(rng: &mut R) -> Vec<G1Affine> {
    // Sample ρ₁, ..., ρ_{n-1} uniformly at random
    let rho_tail: Vec<G1Projective> = (1..N)
        .map(|_| G1Projective::rand(rng))
        .collect();

    // ρ₀ = -∑_{i=1}^{n-1} 2^i · ρ_i
    let mut rho_0 = G1Projective::zero();
    let mut power = Fr::from(2u64); // starts at 2^1
    for rho_i in &rho_tail {
        rho_0 += rho_i.mul(power);
        power *= Fr::from(2u64);
    }
    rho_0 = -rho_0;

    let mut rho = Vec::with_capacity(N);
    rho.push(rho_0);
    rho.extend(rho_tail);

    G1Projective::normalize_batch(&rho)
}

/// Sample L = 1+5N base field elements s_0, ..., s_{L-1} ∈ F_p satisfying:
///   ∑_{i=0}^{L-1} 2^i · s_i = 0  in F_p
///
/// Strategy: sample s_1..s_{L-1} randomly, then solve for s_0:
///   s_0 = -∑_{i=1}^{M-1} 2^i · s_i
fn sample_s<R: Rng>(rng: &mut R) -> Vec<Fq> {
    let s_tail: Vec<Fq> = (1..L).map(|_| Fq::rand(rng)).collect();

    // s_0 = -∑_{i=1}^{L-1} 2^i · s_i
    let mut s_0 = Fq::zero();
    let mut power = Fq::from(2u64); // starts at 2^1
    for s_i in &s_tail {
        s_0 += power * s_i;
        power += power; // 2^i -> 2^{i+1}
    }
    s_0 = -s_0;

    let mut s = Vec::with_capacity(L);
    s.push(s_0);
    s.extend(s_tail);
    s
}

#[test]
fn test_sample_s() {
    let mut rng = rand::thread_rng();
    let s = sample_s(&mut rng);

    assert_eq!(s.len(), L);

    // Verify: ∑ 2^i · s_i = 0
    let mut sum = Fq::zero();
    let mut power = Fq::from(1u64);
    for s_i in &s {
        sum += power * s_i;
        power += power;
    }

    assert!(sum.is_zero(), "constraint ∑ 2^i·s_i = 0 not satisfied");
    println!("sample_s OK: all {L} elements satisfy the constraint");
}

#[test]
fn test_sample_rho() {
    use rand::thread_rng;
    use ark_ec::CurveGroup;

    let mut rng = thread_rng();
    let rho = sample_rhos(&mut rng);

    assert_eq!(rho.len(), N);

    // Verify: ∑ 2^i · ρ_i = O
    let mut sum = G1Projective::zero();
    let mut power = Fr::from(1u64);
    for rho_i in &rho {
        sum += G1Projective::from(*rho_i).mul(power);
        power *= Fr::from(2u64);
    }

    assert!(sum.is_zero(), "constraint ∑ 2^i·ρ_i = O not satisfied");
    println!("sample_rho OK: all {N} points satisfy the constraint");
}

#[test]
fn test_vjp() {
    println!("Fr modulus: {:?}", Fr::MODULUS);
}