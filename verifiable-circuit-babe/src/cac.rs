use ark_bn254::Fr;
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use crate::babe::{h, WeKnownPi1SetupCt};
use crate::instance::commit::CACInstanceCommit;
use crate::gc::{gc_ciphertexts_commit, SparseAdaptorTable};
use garbled_snark_verifier::bag::S;
use rand::Rng;
use rand_chacha::ChaCha12Rng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use crate::instance::BABEInstance;

/// What the Verifier sends to the Prover during the C&C commit phase.
pub struct CACSetupPackage {
    pub commits: Vec<CACInstanceCommit>,
}

/// Derive the finalized instance indices deterministically from the committed values.
pub fn cac_finalize_indices(package: &CACSetupPackage, m_cc: usize) -> Vec<usize> {
    let n_cc = package.commits.len();
    assert!(m_cc <= n_cc, "m_cc ({m_cc}) must be <= n_cc ({n_cc})");

    let mut hasher = Sha256::new();
    for commit in &package.commits {
        for wire_pair in &commit.epk {
            hasher.update(wire_pair[0]);
            hasher.update(wire_pair[1]);
        }
        for wire_pair in &commit.constant_commits {
            hasher.update(wire_pair[0]);
            hasher.update(wire_pair[1]);
        }
        hasher.update(commit.h_msg);
        hasher.update(commit.h_ct_setup);
        hasher.update(commit.com_adaptor);
        hasher.update(commit.com_gc);
    }
    let seed: [u8; 32] = hasher.finalize().into();
    let mut rng = ChaCha12Rng::from_seed(seed);

    let mut seen = std::collections::HashSet::new();
    let mut indices = Vec::with_capacity(m_cc);
    while indices.len() < m_cc {
        let idx = rng.gen_range(0..n_cc);
        if seen.insert(idx) {
            indices.push(idx);
        }
    }
    indices
}

/// GC data the Verifier reveals for each finalized (kept) instance.
pub struct FinalizedInstanceData {
    pub index: usize,
    pub gc_ciphertexts: Vec<Option<S>>,
    pub adaptor_table: SparseAdaptorTable,
    pub ct_setup: WeKnownPi1SetupCt,
}

pub fn verify_opened_instances(
    package: &CACSetupPackage,
    opened: &[(usize, u64)],
    vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
    public_inputs: &[Fr],
) -> Result<(), String> {
    use p3_maybe_rayon::prelude::*;
    opened
        .par_iter()
        .map(|&(idx, seed)| {
            let mut inst = BABEInstance::new_from_seed(seed);
            inst.enc_setup(vk, public_inputs)
                .map_err(|e| format!("instance {idx}: enc_setup failed: {e}"))?;

            let recomputed = inst.commit();
            let committed = &package.commits[idx];

            if recomputed.epk != committed.epk {
                return Err(format!("instance {idx}: input_commits mismatch"));
            }
            if recomputed.constant_commits != committed.constant_commits {
                return Err(format!("instance {idx}: constant_commits mismatch"));
            }
            if recomputed.h_msg != committed.h_msg {
                return Err(format!("instance {idx}: h_msg mismatch"));
            }
            if recomputed.h_ct_setup != committed.h_ct_setup {
                return Err(format!("instance {idx}: ct_setup mismatch"));
            }
            if recomputed.com_adaptor != committed.com_adaptor {
                return Err(format!("instance {idx}: com_adaptor mismatch"));
            }
            if recomputed.com_gc != committed.com_gc {
                return Err(format!("instance {idx}: com_gc mismatch"));
            }
            Ok(())
        })
        .collect::<Vec<_>>()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    Ok(())
}

pub fn verify_finalized_instances(
    package: &CACSetupPackage,
    finalized: &[FinalizedInstanceData],
) -> Result<(), String> {
    for data in finalized {
        let idx = data.index;
        let committed = &package.commits[idx];

        if gc_ciphertexts_commit(&data.gc_ciphertexts) != committed.com_gc {
            return Err(format!("instance {idx}: gc_ciphertexts do not match com_gc"));
        }
        if data.adaptor_table.commit() != committed.com_adaptor {
            return Err(format!("instance {idx}: adaptor_table does not match com_adaptor"));
        }
        let mut ct_bytes = Vec::new();
        ct_bytes.extend_from_slice(&data.ct_setup.ct2_r_delta_g2);
        ct_bytes.extend_from_slice(&data.ct_setup.ct3_masked_msg);
        if h(&ct_bytes) != committed.h_ct_setup {
            return Err(format!("instance {idx}: ct_setup does not match h_ct_setup"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_ff::PrimeField;
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use rand::SeedableRng;
    use crate::verifier::BABEVerifier;

    const TEST_N_CC: usize = 10;
    const TEST_M_CC: usize = 4;

    #[derive(Copy, Clone)]
    struct DummyMulCircuit<F: PrimeField> {
        a: Option<F>,
        b: Option<F>,
    }

    impl<F: PrimeField> ConstraintSynthesizer<F> for DummyMulCircuit<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.new_input_variable(|| Ok(self.a.unwrap() * self.b.unwrap()))?;
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            Ok(())
        }
    }

    #[test]
    fn test_cac_commit_open_verify() {
        let mut rng = ChaCha12Rng::seed_from_u64(42);

        let a = Fr::from(3u64);
        let b = Fr::from(7u64);
        let (_, vk) = ark_groth16::Groth16::<ark_bn254::Bn254>::setup(
            DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) }, &mut rng,
        ).expect("groth16 setup");
        let public_inputs = vec![a * b];

        // Verifier creates TEST_N_CC instances and commits.
        let now = std::time::Instant::now();
        let verifier = BABEVerifier::new(TEST_N_CC, &vk, &public_inputs)
            .expect("BABEVerifier::new failed");
        let elapsed = now.elapsed();
        println!("Verifier setup for {TEST_N_CC} instances took {elapsed:.2?}");

        let now = std::time::Instant::now();
        let package = verifier.commit();
        assert_eq!(package.commits.len(), TEST_N_CC);
        let elapsed = now.elapsed();
        println!("Verifier commit for {TEST_N_CC} instances took {elapsed:.2?}");

        let finalized_indices = cac_finalize_indices(&package, TEST_M_CC);

        // Verifier opens: seeds for the rest, GC data for finalized.
        let now = std::time::Instant::now();
        let (opened, finalized) = verifier.open(&finalized_indices);
        assert_eq!(opened.len(), TEST_N_CC - TEST_M_CC);
        assert_eq!(finalized.len(), TEST_M_CC);
        let elapsed = now.elapsed();
        println!("Verifier open for {TEST_N_CC} instances (finalizing {TEST_M_CC}) took {elapsed:.2?}");

        let now = std::time::Instant::now();
        // Prover verifies opened instances by re-deriving from seed.
        verify_opened_instances(&package, &opened, &vk, &public_inputs)
            .expect("opened instance verification failed");
        let elapsed = now.elapsed();
        println!("Prover verification of opened instances took {elapsed:.2?}");

        // Prover verifies finalized instances via com_gc / com_adaptor.
        let now = std::time::Instant::now();
        verify_finalized_instances(&package, &finalized)
            .expect("finalized instance verification failed");
        let elapsed = now.elapsed();
        println!("Prover verification of finalized instances took {elapsed:.2?}");
    }
}
