use std::ops::Mul;
use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use rand::Rng;
use crate::dre::{L, N};

/// Sample n G1 points ρ₀, ρ₁, ..., ρ_{n-1} satisfying:
///   ∑_{i=0}^{n-1} 2^i · ρ_i = O  (point at infinity)
pub fn sample_rhos<R: Rng>(rng: &mut R) -> Vec<G1Affine> {
    // Sample ρ₁, ..., ρ_{n-1} uniformly at random
    let rho_tail: Vec<G1Projective> = (1..N)
        .map(|_| G1Projective::rand(rng))
        .collect();

    // ρ₀ = -∑_{i=1}^{n-1} 2^i · ρ_i
    let mut rho_0 = G1Projective::zero();
    let mut power = Fr::from(2u64);
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

/// Sample L base field elements s_0, ..., s_{L-1} ∈ F_p satisfying:
///   ∑_{i=0}^{L-1} s_i = 0  in F_p
pub fn sample_s<R: Rng>(rng: &mut R) -> Vec<Fq> {
    let s_tail: Vec<Fq> = (1..L).map(|_| Fq::rand(rng)).collect();
    let s_0 = -s_tail.iter().copied().sum::<Fq>();

    let mut s = Vec::with_capacity(L);
    s.push(s_0);
    s.extend(s_tail);
    s
}

/// Recover affine point from Jacobian (X,Y,Z): x=X/Z², y=Y/Z³
pub fn jacobian_to_affine(xyz: (Fq, Fq, Fq)) -> ark_bn254::G1Affine {
    let z_inv = xyz.2.inverse().unwrap();
    let z2_inv = z_inv * z_inv;
    let z3_inv = z2_inv * z_inv;
    G1Affine::new_unchecked(xyz.0 * z2_inv, xyz.1 * z3_inv)
}

#[cfg(test)]
mod tests {
    use std::ops::Mul;
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_ff::Zero;
    use rand::thread_rng;
    use crate::dre::{L, N};
    use crate::dre::utils::{sample_rhos, sample_s};

    #[test]
    fn test_sample_s() {
        let mut rng = rand::thread_rng();
        let s = sample_s(&mut rng);

        assert_eq!(s.len(), L);

        let sum: Fq = s.iter().copied().sum();
        assert!(sum.is_zero(), "constraint ∑ s_i = 0 not satisfied");
    }

    #[test]
    fn test_sample_rho() {

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
    }
}
