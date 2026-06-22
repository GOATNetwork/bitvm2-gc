use ark_bn254::{Fr, G1Affine};
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use garbled_snark_verifier::bag::S;
use garbled_snark_verifier::dv_bn254::fq::Fq as DvFq;
use garbled_snark_verifier::dv_bn254::fr::Fr as DvFr;
use serde::{Deserialize, Serialize};
use crate::cac::CACSetupPackage;
use crate::gc::SGC_PART1_CONSTANT_SIZE;
use crate::instance::CACInstance;
use crate::instance::commit::CACInstanceCommit;

/// Instances processed in parallel per batch (RAM gate).
/// Override via CAC_BATCH_SIZE env var at runtime.
pub const BATCH_SIZE: usize = 8;

/// Per-instance encoding secrets needed for label computation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstanceLightSecrets {
    pub delta: [S; 2],
    pub input_0labels: [Vec<S>; 2],
}

impl InstanceLightSecrets {
    pub fn from_seed(seed: u64) -> Self {
        let (delta, input_0labels) = crate::instance::secret::derive_light_from_seed(seed);
        Self { delta, input_0labels }
    }

    pub fn compute_pi1_labels(&self, pi1: G1Affine) -> Vec<S> {
        let delta = self.delta[0];
        DvFq::to_bits(pi1.x)
            .into_iter()
            .chain(DvFq::to_bits(pi1.y))
            .enumerate()
            .map(|(i, b)| {
                let key = self.input_0labels[0][i];
                if b { key ^ delta } else { key }
            })
            .collect()
    }

    pub fn compute_x_d_labels(&self, x_d: Fr) -> Vec<S> {
        let delta = self.delta[1];
        DvFr::to_bits(x_d)
            .into_iter()
            .enumerate()
            .map(|(i, b)| {
                let key = self.input_0labels[1][i];
                if b { key ^ delta } else { key }
            })
            .collect()
    }
}

/// The C&C Verifier: manages N_CC garbled-circuit instances for Cut-and-Choose.
pub struct BABEVerifier {
    seeds: Vec<u64>,
    commits: CACSetupPackage,
    vk: Groth16VerifyingKey<ark_bn254::Bn254>,
    static_public_inputs: Fr,
}

impl BABEVerifier {
    /// Create `n_cc` fresh instances processed in batches of BATCH_SIZE.
    pub fn new(
        n_cc: usize,
        vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
        static_public_inputs: Fr,
    ) -> Result<Self, String> {
        use p3_maybe_rayon::prelude::*;

        let seeds: Vec<u64> = (0..n_cc).map(|_| rand::random()).collect();

        let n_cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
        let batch_size = std::env::var("CAC_BATCH_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(BATCH_SIZE)
            .min(n_cores)
            .min(n_cc);

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(batch_size)
            .build()
            .map_err(|e| e.to_string())?;

        let mut commits = Vec::with_capacity(n_cc);

        for batch_seeds in seeds.chunks(batch_size) {
            // Generate up to BATCH_SIZE instances in parallel. For each instance,
            // stream-hash the ciphertexts and adaptor table without materializing them.
            let batch_results: Vec<Result<CACInstanceCommit, String>> =
                pool.install(|| {
                    batch_seeds
                        .par_iter()
                        .map(|&seed| {
                            let commit =
                                CACInstance::commit_from_seed(seed, vk, static_public_inputs)?;
                            Ok(commit)
                        })
                        .collect()
                });

            for result in batch_results {
                commits.push(result?);
            }
        }
        let commits = CACSetupPackage { commits };
        Ok(Self {
            seeds,
            commits,
            vk: vk.clone(),
            static_public_inputs,
        })
    }

    /// Restore a `BABEVerifier` from previously persisted state.
    pub fn from_state(
        seeds: &[u64],
        commits: &CACSetupPackage,
        vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
        static_public_inputs: Fr,
    ) -> Option<Self> {
        if seeds.len() != commits.commits.len() {
            return None;
        }
        Some(Self {
            seeds: seeds.to_vec(),
            commits: commits.clone(),
            vk: vk.clone(),
            static_public_inputs
        })

    }

    /// Return the C&C commit package from pre-computed commitments.
    pub fn commit(&self) -> CACSetupPackage {
        self.commits.clone()
    }

    /// After receiving the finalized indices, reveal:
    /// - seeds for the non-finalized instances (N_CC - M_CC)
    /// - full GC data for the M_CC finalized instances, regenerated one-by-one
    pub fn open(
        &self,
        finalized_indices: &[usize],
    ) -> Result<(Vec<(usize, u64)>, Vec<crate::cac::FinalizedInstanceData>), String> {
        let finalized_set: std::collections::HashSet<usize> =
            finalized_indices.iter().copied().collect();

        let opened: Vec<(usize, u64)> = (0..self.seeds.len())
            .filter(|i| !finalized_set.contains(i))
            .map(|i| (i, self.seeds[i]))
            .collect();

        // Regenerate all M_CC finalized instances in parallel
        use p3_maybe_rayon::prelude::*;
        let finalized: Vec<Result<crate::cac::FinalizedInstanceData, String>> = finalized_indices
            .par_iter()
            .map(|&i| {
                let inst = CACInstance::new_from_seed(
                    self.seeds[i],
                    &self.vk,
                    self.static_public_inputs,
                )?;

                let constant_labels_0 = [
                    inst.secrets.constant_0labels[0][0],
                    inst.secrets.constant_0labels[0][1] ^ inst.secrets.delta[0],
                ];
                let mut constant_labels_1 = vec![
                    inst.secrets.constant_0labels[1][0],
                    inst.secrets.constant_0labels[1][1] ^ inst.secrets.delta[1],
                ];
                constant_labels_1.extend(inst.get_b_value_labels());
                assert_eq!(constant_labels_1.len(), SGC_PART1_CONSTANT_SIZE);

                Ok(crate::cac::FinalizedInstanceData {
                    index: i,
                    ciphertext_sets: inst.ciphertexts_sets,
                    adaptor_tables: inst.adaptor_tables,
                    ct_setup: inst.ct_setup,
                    constant_labels_0,
                    constant_labels_1,
                    b: inst.secrets.b,
                })
                // inst is dropped here
            })
            .collect();
        let finalized = finalized.into_iter().collect::<Result<Vec<_>, _>>()?;

        Ok((opened, finalized))
    }

    /// Compute the active π₁ input labels for instance `idx` given a concrete π₁.
    pub fn compute_pi1_labels(&self, idx: usize, pi1: G1Affine) -> Vec<S> {
        let ls = InstanceLightSecrets::from_seed(self.seeds[idx]);
        ls.compute_pi1_labels(pi1)
    }

    /// Compute the active x_d input labels for instance `idx` given a concrete x_d.
    pub fn compute_x_d_labels(&self, idx: usize, x_d: Fr) -> Vec<S> {
        let ls = InstanceLightSecrets::from_seed(self.seeds[idx]);
        ls.compute_x_d_labels(x_d)
    }

    pub fn get_seeds(&self) -> Vec<u64> {
        self.seeds.clone()
    }

    pub fn light_secrets_for(&self, idx: usize) -> InstanceLightSecrets {
        InstanceLightSecrets::from_seed(self.seeds[idx])
    }
}
