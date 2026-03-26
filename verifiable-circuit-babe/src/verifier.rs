use ark_bn254::Fr;
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use crate::instance::BABEInstance;

/// The C&C Verifier: manages N_CC garbled-circuit instances for Cut-and-Choose.
pub struct BABEVerifier {
    /// All N_CC instances, each fully derived from its own seed.
    pub instances: Vec<BABEInstance>,
}

impl BABEVerifier {
    /// Create `n_cc` fresh instances and run `enc_setup` on each.
    ///
    /// Each instance gets a random seed. `enc_setup` binds each instance's
    /// secret message to the given Groth16 verifying key and public inputs.
    pub fn new(
        n_cc: usize,
        vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
        public_inputs: &[Fr],
    ) -> Result<Self, String> {
        use p3_maybe_rayon::prelude::*;
        let seeds: Vec<u64> = (0..n_cc).map(|_| rand::random()).collect();
        let instances = seeds
            .par_iter()
            .map(|&seed| {
                let mut inst = BABEInstance::new_from_seed(seed);
                inst.enc_setup(vk, public_inputs)?;
                Ok::<BABEInstance, String>(inst)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { instances })
    }

    /// Build the C&C commit package: one `CACInstanceCommit` per instance.
    /// Sent to the Prover at the start of the C&C protocol.
    pub fn commit(&self) -> crate::cac::CACSetupPackage {
        crate::cac::CACSetupPackage {
            commits: self.instances.iter().map(|inst| inst.commit()).collect(),
        }
    }

    /// After receiving the Prover's finalized indices, reveal the open round:
    /// - seeds for instance not in I
    /// - GC data for every instance in I
    pub fn open(
        &self,
        finalized_indices: &[usize],
    ) -> (Vec<(usize, u64)>, Vec<crate::cac::FinalizedInstanceData>) {
        let mut opened = Vec::new();
        for (i, inst) in self.instances.iter().enumerate() {
            if !finalized_indices.contains(&i) {
                opened.push((i, inst.seed));
            }
        }

        let mut finalized = Vec::new();
        for &i in finalized_indices {
            let inst = &self.instances[i];
            finalized.push(crate::cac::FinalizedInstanceData {
                index: i,
                gc_ciphertexts: inst.ciphertexts.clone(),
                adaptor_table: inst.adaptor_table.clone(),
                ct_setup: inst.ct_setup.clone(),
            });
        }

        (opened, finalized)
    }
}