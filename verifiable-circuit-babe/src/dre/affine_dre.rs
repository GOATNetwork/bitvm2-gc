use ark_bn254::{Fq, Fr};
use ark_ff::{One, Zero};
use crate::dre::{DRE, L};
use crate::dre::matrices::build_d_i;

pub struct AffineDRE {}

pub struct AffineDREInput {
    pub r_i: Fr,
    pub bar_u: Vec<Fq>,
    pub rho_i: ark_bn254::G1Affine,
    pub delta_i: Fq,
    pub s_i: Vec<Vec<Fq>>,
}

/// Encoding: dre_g_i[j][k] = D_{i,j,k} · ū_k(π) + s_{i,j,k}
/// Shape: 3 rows × L columns
pub struct AffineDREEncoding {
    pub dre_g_i: Vec<Vec<Fq>>,
}

/// Decoding: f_i = r_i·π + ρ_i
pub struct AffineDREDecoding {
    pub f_i: (Fq, Fq, Fq),
}

impl DRE for AffineDRE {
    type Input = AffineDREInput;
    type Encoding = AffineDREEncoding;
    type Decoding = AffineDREDecoding;

    /// Enc: ĝ_{i,j,k} = (D_{i,j,k}·ū_k(π) + s_{i,j,k})
    fn enc(input: Self::Input) -> Self::Encoding {
        assert!(input.r_i == Fr::zero() || input.r_i == Fr::one());
        assert_eq!(input.bar_u.len(), L);
        assert_eq!(input.s_i.len(), 3);

        let fq_r_i = if input.r_i == Fr::zero() { Fq::zero() } else { Fq::one() };

        // build D_i matrix
        let d_i = build_d_i(input.delta_i, fq_r_i, &input.rho_i);
        let dre_g_i = (0..3)
            .map(|j| {
                (0..L)
                    .map(|k| d_i[j * L + k] * input.bar_u[k] + input.s_i[j][k])
                    .collect()
            })
            .collect();

        AffineDREEncoding { dre_g_i }
    }

    /// Dec: Dec_{i,j}((y_1,...,y_L)) = ∑_k y_k
    fn dec(encoding: Self::Encoding) -> Self::Decoding {
        let coords: Vec<Fq> = encoding.dre_g_i
            .iter()
            .map(|row| row.iter().copied().sum())
            .collect();

        AffineDREDecoding {
            f_i: (coords[0], coords[1], coords[2]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::G1Projective;
    use ark_ec::CurveGroup;
    use ark_ff::{Field, UniformRand};
    use crate::dre::matrices::u_bar_vec;
    use crate::dre::utils::{jacobian_to_affine, sample_s};

    #[test]
    fn test_affine_dre() {
        let mut rng = rand::thread_rng();

        // Pick a random G1 point π and a random scalar r with one bit r_i
        let pi    = G1Projective::rand(&mut rng).into_affine();
        let r_i   = Fr::from(rand::random::<bool>() as u64);

        // Sample ρ_i (single point, no constraint needed for single-point test)
        let rho_i = G1Projective::rand(&mut rng).into_affine();

        // λ_i ∈ F_p*
        let delta_i = loop {
            let l = Fq::rand(&mut rng);
            if !l.is_zero() { break l; }
        };

        // s_{i,j}: 3 rows, each length L summing to 0
        let s_i: Vec<Vec<Fq>> = (0..3).map(|_| sample_s(&mut rng)).collect();

        // ū(π)
        let bar_u = u_bar_vec(&pi);

        let encoding = AffineDRE::enc(AffineDREInput {
            r_i,
            bar_u,
            rho_i,
            delta_i,
            s_i,
        });

        let decoding = AffineDRE::dec(encoding);

        // The decoded Jacobian triple must represent r_i·π + ρ_i.
        // diag(λ²,λ³,λ) is a valid Jacobian re-scaling (Lemma 5),
        let expected_affine = (G1Projective::from(pi) * r_i + G1Projective::from(rho_i))
            .into_affine();

        assert_eq!(
            jacobian_to_affine(decoding.f_i),
            expected_affine,
            "Jacobian coords should decode to r_i·π + ρ_i"
        );
    }
}