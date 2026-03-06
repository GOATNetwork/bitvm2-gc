use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use ark_bn254::Fq;
use ark_ff::{PrimeField, Zero};
use garbled_snark_verifier::core::s::S;
use crate::dre::affine_dre::AffineDREEncoding;
use crate::dre::{L, N};
use crate::gc::utils::{aes_dec, aes_enc};

/// Ciphertext of one Fq element (32 bytes = 2 AES-128 blocks)
pub type Ct = [u8; 32];

/// All encrypted entries for index i, with key u_bar = 0 or 1.
/// Each has size L, j = 0,1,2 for x,y,z coordinates.
pub struct AdaptorEntry {
    pub x: Vec<[Ct; 2]>,
    pub y: Vec<[Ct; 2]>,
    pub z: Vec<[Ct; 2]>,
}

/// Adaptor table: encrypts g_{i,j,k} under both labels so
/// the evaluator can decrypt with their held label.
pub struct AdaptorTable {
    /// entries[i] covers all (j, k) pairs.
    pub entries: Vec<AdaptorEntry>,
}

impl AdaptorTable {
    /// Build the adaptor table from the DRE encodings and labels.
    /// Require: dre_g has 2*N entries, where each pair of contiguous
    /// entries corresponds to u_bar = 0 and 1 for the same i.
    pub fn build(dre_g: &[AffineDREEncoding], labels: &[[S; 2]]) -> Self {
        assert_eq!(dre_g.len(), 2 * N);
        assert_eq!(labels.len(), L);

        let entries = (0..N)
            .map(|i| {
                let enc_0 = &dre_g[2 * i];     // ū_k = 0
                let enc_1 = &dre_g[2 * i + 1]; // ū_k = 1

                // check the size of the encodings match expected dimensions
                assert_eq!(enc_0.dre_g_i.len(), 3);
                for j in 0..3 {
                    assert_eq!(enc_0.dre_g_i[j].len(), L);
                    assert_eq!(enc_1.dre_g_i[j].len(), L);
                }
                // todo: we can avoid using labels again as key for security
                let enc_row = |row_0: &[Fq], row_1: &[Fq]| -> Vec<[Ct; 2]> {
                    row_0
                        .iter()
                        .zip(row_1.iter())
                        .enumerate()
                        .map(|(k, (g0, g1))| {
                            [aes_enc(g0, &labels[k][0]), aes_enc(g1, &labels[k][1])]
                        })
                        .collect()
                };

                AdaptorEntry {
                    x: enc_row(&enc_0.dre_g_i[0], &enc_1.dre_g_i[0]),
                    y: enc_row(&enc_0.dre_g_i[1], &enc_1.dre_g_i[1]),
                    z: enc_row(&enc_0.dre_g_i[2], &enc_1.dre_g_i[2]),
                }
            })
            .collect();

        AdaptorTable { entries }
    }

    pub fn eval(&self, labels: &[S], u_bar: &[Fq]) -> Vec<AffineDREEncoding> {
        assert_eq!(labels.len(), L);
        assert_eq!(u_bar.len(), L);

        self.entries
            .iter()
            .map(|entry| {
                // For each column k, decrypt using the label held for bit k
                let dec_row = |row: &Vec<[Ct; 2]>| -> Vec<Fq> {
                    row.iter()
                        .enumerate()
                        .map(|(k, ct_pair)| {
                            if u_bar[k].is_zero() {
                                aes_dec(&ct_pair[0], &labels[k])
                            } else {
                                aes_dec(&ct_pair[1], &labels[k])
                            }
                        })
                        .collect()
                };

                let dre_g_i = vec![
                    dec_row(&entry.x),
                    dec_row(&entry.y),
                    dec_row(&entry.z),
                ];

                AffineDREEncoding { dre_g_i }
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
    use crate::dre::{DRE, L, N};
    use crate::dre::affine_dre::{AffineDRE, AffineDREInput};
    use crate::dre::matrices::u_bar_vec;
    use crate::dre::utils::{jacobian_to_affine, sample_rhos, sample_s};

    #[test]
    fn test_adaptor_table() {
        // create random r and \pi
        let mut rng = rand::thread_rng();
        let pi = G1Projective::rand(&mut rng).into_affine();
        let r: Vec<Fr> = (0..N).map(|_| Fr::from(rand::random::<bool>() as u64)).collect();

        // create u_bar_pi based on pi
        let u_bar_pi = u_bar_vec(&pi);

        // create 2 * L random labels for L bits (2 labels per bit position)
        let labels: Vec<[S; 2]> = (0..L)
            .map(|_| {
                let l0 = S::random();
                let l1 = l0 ^ DELTA;
                [l0, l1]
            })
            .collect();

        // generate rhos: N points satisfying ∑ 2^i·ρ_i = O
        let rhos = sample_rhos(&mut rng);

        // generate deltas: N non-zero random Fq scalars
        let deltas: Vec<Fq> = (0..N)
            .map(|_| loop {
                let l = Fq::rand(&mut rng);
                if !l.is_zero() { break l; }
            })
            .collect();

        // u_bar = 0 and 1
        let u_bar_zeros: Vec<Fq> = vec![Fq::zero(); L];
        let u_bar_ones: Vec<Fq> = vec![Fq::one(); L];

        let mut all_encodings: Vec<AffineDREEncoding> = Vec::with_capacity(2 * N);
        for i in 0..N {
            let s_i: Vec<Vec<Fq>> = (0..3).map(|_| sample_s(&mut rng)).collect();

            // enc for ū_k = 0: dre_g_i[j][k] = s_{i,j,k}
            let enc_0 = AffineDRE::enc(AffineDREInput {
                r_i: r[i],
                bar_u: u_bar_zeros.clone(),
                rho_i: rhos[i],
                delta_i: deltas[i],
                s_i: s_i.clone(),
            });
            // enc for ū_k = 1: dre_g_i[j][k] = D_{i,j,k} + s_{i,j,k}
            let enc_1 = AffineDRE::enc(AffineDREInput {
                r_i: r[i],
                bar_u: u_bar_ones.clone(),
                rho_i: rhos[i],
                delta_i: deltas[i],
                s_i,
            });

            all_encodings.push(enc_0); // index 2*i   → ū_k = 0
            all_encodings.push(enc_1); // index 2*i+1 → ū_k = 1
        }

        // build the adaptor table from the encodings and labels
        let table = AdaptorTable::build(&all_encodings, &labels);

        // evaluate the adaptor table with the held labels and bar_u
        // For each bit position k, the evaluator holds labels[k][u_bar_pi[k]]
        let eval_labels: Vec<S> = (0..L)
            .map(|k| if u_bar_pi[k].is_zero() { labels[k][0] } else { labels[k][1] })
            .collect();

        let decrypted_encodings = table.eval(&eval_labels, &u_bar_pi);

        // compute the AffineDREDecoding from the decrypted encodings and check it matches r_i·π + ρ_i
        for i in 0..decrypted_encodings.len() {
            let decoding = AffineDRE::dec(AffineDREEncoding {
                dre_g_i: decrypted_encodings[i].dre_g_i.clone(),
            });

            let expected = (G1Projective::from(pi) * r[i] + G1Projective::from(rhos[i]))
                .into_affine();

            assert_eq!(
                jacobian_to_affine(decoding.f_i),
                expected,
                "entry {i}: decoded point should equal r_i·π + ρ_i"
            );
        }
    }
}