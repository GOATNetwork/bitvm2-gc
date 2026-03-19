use ark_bn254::{Fq, Fr};
use ark_ff::{One, Zero};
use crate::dre::DRE;
use crate::dre::matrices::{build_d_i_sparse, nonzero_col_indices};

pub struct AffineDRE {}

pub struct AffineDREInput {
    pub r_i: Fr,
    pub bar_u: Vec<Fq>,
    pub rho_i: ark_bn254::G1Affine,
    pub delta_i: Fq,
    /// s_i[j] has length nonzero_col_indices()[j].len(), summing to 0
    pub s_i: Vec<Vec<Fq>>,
}

/// Sparse encoding: dre_g_i[j][k'] = D_{i,j,nz[k']} · ū_{nz[k']}(π) + s_{i,j,k'}
/// where nz = nonzero_col_indices()[j]. Shape: 3 rows × nonzero_count[j] columns.
pub struct AffineDREEncoding {
    pub dre_g_i: Vec<Vec<Fq>>,
}

/// Decoding: f_i = r_i·π + ρ_i  (Jacobian coords)
pub struct AffineDREDecoding {
    pub f_i: (Fq, Fq, Fq),
}

impl DRE for AffineDRE {
    type Input = AffineDREInput;
    type Encoding = AffineDREEncoding;
    type Decoding = AffineDREDecoding;

    /// Enc: ĝ_{i,j,k'} = D_{i,j,nz[k']} · ū_{nz[k']}(π) + s_{i,j,k'}
    /// Only nonzero-D positions are encoded; s sums to 0 over those positions.
    fn enc(input: Self::Input) -> Self::Encoding {
        assert!(input.r_i == Fr::zero() || input.r_i == Fr::one());
        assert_eq!(input.s_i.len(), 3);

        let fq_r_i = if input.r_i == Fr::zero() { Fq::zero() } else { Fq::one() };
        let d = build_d_i_sparse(input.delta_i, fq_r_i, &input.rho_i);
        let col_indices = nonzero_col_indices();

        let dre_g_i = (0..3)
            .map(|j| {
                assert_eq!(input.s_i[j].len(), col_indices[j].len());
                col_indices[j]
                    .iter()
                    .zip(d[j].iter())
                    .zip(input.s_i[j].iter())
                    .map(|((&k, &d_val), &s_val)| d_val * input.bar_u[k] + s_val)
                    .collect()
            })
            .collect();

        AffineDREEncoding { dre_g_i }
    }

    /// Dec: f_{i,j} = ∑_{k'} ĝ_{i,j,k'} = ∑_{k'∈nz} D_k'·ū_k'
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
    use ark_ff::UniformRand;
    use crate::dre::matrices::{nonzero_col_indices, u_bar_vec};
    use crate::dre::utils::{jacobian_to_affine, sample_s_sparse};

    #[test]
    fn test_affine_dre() {
        let mut rng = rand::thread_rng();

        let pi    = G1Projective::rand(&mut rng).into_affine();
        let r_i   = Fr::from(rand::random::<bool>() as u64);
        let rho_i = G1Projective::rand(&mut rng).into_affine();

        let delta_i = loop {
            let l = Fq::rand(&mut rng);
            if !l.is_zero() { break l; }
        };

        // s sparse: one Vec per row, length = nonzero count for that row, sum = 0
        let col_indices = nonzero_col_indices();
        let s_i: Vec<Vec<Fq>> = (0..3)
            .map(|j| sample_s_sparse(&mut rng, col_indices[j].len()))
            .collect();

        let bar_u = u_bar_vec(&pi);
        let encoding = AffineDRE::enc(AffineDREInput { r_i, bar_u, rho_i, delta_i, s_i });
        let decoding = AffineDRE::dec(encoding);

        let expected_affine = (G1Projective::from(pi) * r_i + G1Projective::from(rho_i))
            .into_affine();
        assert_eq!(
            jacobian_to_affine(decoding.f_i),
            expected_affine,
            "Jacobian coords should decode to r_i·π + ρ_i"
        );
    }
}