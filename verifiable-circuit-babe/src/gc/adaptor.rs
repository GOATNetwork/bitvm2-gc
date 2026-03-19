use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ff::{UniformRand, Zero};
use crate::dre::affine_dre::AffineDREDecoding;
use crate::dre::{L, N};
use crate::dre::matrices::{build_d_i_sparse, nonzero_col_indices};
use crate::dre::utils::{sample_rhos, sample_s_sparse};
use crate::gc::utils::{aes_dec, aes_enc};

/// Ciphertext of one Fq element (32 bytes = 2 AES-128 blocks)
pub type Ct = [u8; 32];

/// Ciphertext pairs for one D row, only at nonzero_col_indices() positions.
pub struct SparseAdaptorRow {
    /// [ct_for_ubar=0, ct_for_ubar=1] per nonzero column, same order as nonzero_col_indices()
    pub cts: Vec<[Ct; 2]>,
}

pub struct SparseAdaptorEntry {
    pub x: SparseAdaptorRow,
    pub y: SparseAdaptorRow,
    pub z: SparseAdaptorRow,
}

/// Adaptor table storing ciphertexts only for structurally nonzero D entries.
/// Reduces size by ~1.87× vs the dense table.
pub struct SparseAdaptorTable {
    pub entries: Vec<SparseAdaptorEntry>,
}

impl SparseAdaptorTable {
    pub fn build_from_r_and_labels(r: Fr, labels: &[[u8; 16]]) -> Self {
        assert_eq!(labels.len(), 2 * L);
        let mut rng = rand::thread_rng();
        let r_bits = garbled_snark_verifier::dv_bn254::fr::Fr::to_bits(r);
        let rhos = sample_rhos(&mut rng);
        let deltas: Vec<Fq> = (0..N)
            .map(|_| loop {
                let l = Fq::rand(&mut rng);
                if !l.is_zero() { break l; }
            })
            .collect();

        let col_indices = nonzero_col_indices();

        let entries = (0..N)
            .map(|i| {
                let r_i = Fq::from(r_bits[i] as u8);
                let d = build_d_i_sparse(deltas[i], r_i, &rhos[i]);

                let mut build_row = |j: usize| -> SparseAdaptorRow {
                    let s = sample_s_sparse(&mut rng, col_indices[j].len());
                    let cts = col_indices[j]
                        .iter()
                        .zip(d[j].iter())
                        .zip(s.iter())
                        .map(|((&k, &d_val), &s_val)| {
                            // g0 = D_k*0 + s_k = s_k
                            // g1 = D_k*1 + s_k = D_k + s_k
                            [
                                aes_enc(&s_val, &labels[2 * k]),
                                aes_enc(&(d_val + s_val), &labels[2 * k + 1]),
                            ]
                        })
                        .collect();
                    SparseAdaptorRow { cts }
                };

                SparseAdaptorEntry {
                    x: build_row(0),
                    y: build_row(1),
                    z: build_row(2),
                }
            })
            .collect();

        SparseAdaptorTable { entries }
    }

    pub fn build_in_zkvm(
        labels: &[[u8; 16]],
        r_bits: &[u8],
        rhos: &[G1Affine],
        s_all: &[Vec<Vec<Fq>>],
        deltas: &[Fq],
    ) -> Self {
        assert_eq!(rhos.len(), N);
        assert_eq!(s_all.len(), N);
        assert_eq!(deltas.len(), N);
        assert_eq!(labels.len(), 2 * L);
        assert_eq!(r_bits.len(), N);

        let col_indices = nonzero_col_indices();

        // Verify ∑ 2^i · ρ_i = O
        let mut weighted_sum = G1Projective::zero();
        let mut power = Fr::from(1u64);
        for rho_i in rhos {
            weighted_sum += *rho_i * power;
            power *= Fr::from(2u64);
        }
        assert!(weighted_sum.is_zero(), "constraint ∑ 2^i·ρ_i = O not satisfied");

        // Verify s and delta constraints (s now over nonzero positions only)
        for i in 0..N {
            assert!(!deltas[i].is_zero(), "delta[{i}] must be non-zero");
            assert_eq!(s_all[i].len(), 3);
            for j in 0..3 {
                assert_eq!(s_all[i][j].len(), col_indices[j].len(),
                    "s_all[{i}][{j}] must have {} entries", col_indices[j].len());
                let sum: Fq = s_all[i][j].iter().copied().sum();
                assert!(sum.is_zero(), "∑_k s_all[{i}][{j}][k] = 0 not satisfied");
            }
        }

        let entries = (0..N)
            .map(|i| {
                let r_i = Fq::from(r_bits[i] as u8);
                let d = build_d_i_sparse(deltas[i], r_i, &rhos[i]);

                let build_row = |j: usize| -> SparseAdaptorRow {
                    let cts = col_indices[j]
                        .iter()
                        .zip(d[j].iter())
                        .zip(s_all[i][j].iter())
                        .map(|((&k, &d_val), &s_val)| {
                            [
                                aes_enc(&s_val, &labels[2 * k]),
                                aes_enc(&(d_val + s_val), &labels[2 * k + 1]),
                            ]
                        })
                        .collect();
                    SparseAdaptorRow { cts }
                };

                SparseAdaptorEntry {
                    x: build_row(0),
                    y: build_row(1),
                    z: build_row(2),
                }
            })
            .collect();

        SparseAdaptorTable { entries }
    }

    /// Decrypt the adaptor table and sum each row to recover Jacobian coords of r_i·π + ρ_i.
    pub fn eval(&self, labels: &[[u8; 16]], u_bar: &[Fq]) -> Vec<AffineDREDecoding> {
        assert_eq!(labels.len(), L);
        assert_eq!(u_bar.len(), L);

        let col_indices = nonzero_col_indices();

        self.entries
            .iter()
            .map(|entry| {
                let dec_row = |row: &SparseAdaptorRow, j: usize| -> Fq {
                    col_indices[j]
                        .iter()
                        .zip(row.cts.iter())
                        .map(|(&k, ct_pair)| {
                            if u_bar[k].is_zero() {
                                aes_dec(&ct_pair[0], &labels[k])
                            } else {
                                aes_dec(&ct_pair[1], &labels[k])
                            }
                        })
                        .sum()
                };

                AffineDREDecoding {
                    f_i: (dec_row(&entry.x, 0), dec_row(&entry.y, 1), dec_row(&entry.z, 2)),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective};
    use ark_ec::CurveGroup;
    use ark_ff::{UniformRand, Zero, One};
    use garbled_snark_verifier::core::s::S;
    use garbled_snark_verifier::core::utils::DELTA;
    use crate::dre::{L, N};
    use crate::dre::matrices::u_bar_vec;

    #[test]
    fn test_sparse_adaptor_table() {
        let mut rng = rand::thread_rng();
        let pi = G1Projective::rand(&mut rng).into_affine();
        let r = Fr::rand(&mut rng);

        let u_bar_pi = u_bar_vec(&pi);

        let labels: Vec<[u8; 16]> = (0..L)
            .flat_map(|_| {
                let l0 = S::random();
                let l1 = l0 ^ DELTA;
                [l0.0, l1.0]
            })
            .collect();

        let table = SparseAdaptorTable::build_from_r_and_labels(r, &labels);

        let eval_labels: Vec<[u8; 16]> = (0..L)
            .map(|k| if u_bar_pi[k].is_zero() { labels[2 * k] } else { labels[2 * k + 1] })
            .collect();

        let decodings = table.eval(&eval_labels, &u_bar_pi);

        let mut sum = G1Projective::zero();
        let mut weight = Fr::one();
        for decoding in decodings {
            let (x, y, z) = decoding.f_i;
            sum += G1Projective::new(x, y, z) * weight;
            weight += weight;
        }

        let expected = (G1Projective::from(pi) * r).into_affine();
        assert_eq!(sum.into_affine(), expected, "Sparse: ∑ 2^i·f_i should equal r·π");
    }
}