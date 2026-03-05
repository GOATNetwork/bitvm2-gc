use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use crate::dre::{DRE, N};

pub struct WeightedDRE {}

pub struct WeightedDREInput {
    pub r: Fr,
    pub pi: G1Affine,
    pub rhos: Vec<G1Affine>,
    pub deltas: Vec<Fq>,
}

pub struct WeightedDREEncoding {
    // f_i = r_i·π + ρ_i in a uniformly random Jacobian form.
    pub dre_f_i: Vec<(Fq, Fq, Fq)>,
}

pub struct WeightedDREDecoding {
    pub r_pi: G1Affine,
}

impl DRE for WeightedDRE {
    type Input = WeightedDREInput;
    type Encoding = WeightedDREEncoding;
    type Decoding = WeightedDREDecoding;
    
    fn enc(input: Self::Input) -> Self::Encoding {
        let bits = input.r.into_bigint().to_bits_le(); // LSB-first

        let dre_f_i = (0..N)
            .map(|i| {
                let r_i = if bits[i] { Fr::one() } else { Fr::zero() };

                // f_i = r_i·π + ρ_i  (affine, Z=1)
                let f_affine = input.pi * r_i + input.rhos[i];
                let f_projective = G1Projective::from(f_affine);

                // Apply diag(λ_i) to obtain a uniformly random Jacobian representation
                let lam = input.deltas[i];
                let lam2 = lam * lam;
                let lam3 = lam2 * lam;
                (lam2 * f_projective.x, lam3 * f_projective.y, f_projective.z * lam)
            })
            .collect();

        WeightedDREEncoding { dre_f_i }
    }

    /// Correctness: ∑ 2^i · f_i = ∑ 2^i·(r_i·π + ρ_i) = r·π + ∑ 2^i·ρ_i = r·π
    fn dec(encoding: Self::Encoding) -> Self::Decoding {
        let mut sum = G1Projective::zero();
        let mut weight = Fr::one(); // 2^i

        for (xj, yj, zj) in &encoding.dre_f_i {
            let f_i = G1Projective::new(*xj, *yj, *zj);
            sum += f_i * weight;
            weight += weight; 
        }

        WeightedDREDecoding {
            r_pi: sum.into_affine()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use crate::dre::utils::sample_rhos;

    fn random_lambdas(n: usize) -> Vec<Fq> {
        let mut rng = rand::thread_rng();
        (0..n).map(|_| loop {
            let l = Fq::rand(&mut rng);
            if !l.is_zero() { break l; }
        }).collect()
    }

    #[test]
    fn test_weighted_dre() {
        let mut rng = rand::thread_rng();

        let r     = Fr::rand(&mut rng);
        let pi    = G1Projective::rand(&mut rng).into_affine();
        let rhos = sample_rhos(&mut rng);
        let deltas = random_lambdas(N);

        let expected = (G1Projective::from(pi) * r).into_affine();

        let encoding = WeightedDRE::enc(WeightedDREInput { r, pi, rhos, deltas });
        let decoding = WeightedDRE::dec(encoding);

        assert_eq!(decoding.r_pi, expected, "dec(enc(r,π)) should equal r·π");
    }
}