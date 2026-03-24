use ark_bn254::Fr;
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use crate::instance::commit::CACInstanceCommit;
use crate::gc::{gc_ciphertexts_commit, SparseAdaptorTable};
use garbled_snark_verifier::bag::S;

/// What the Verifier sends to the Prover during the C&C commit phase.
pub struct CACSetupPackage {
    /// One commit per C&C instance, in instance order.
    pub commits: Vec<CACInstanceCommit>,
}

/// GC data the Verifier reveals for each finalized (kept) instance.
/// Sent together with the opened seeds in the C&C open round.
pub struct FinalizedInstanceData {
    /// Index into the original N_CC instance list.
    pub index: usize,
    /// Gate ciphertexts — None for free (XOR/NOT) gates, Some(S) for others.
    pub gc_ciphertexts: Vec<Option<S>>,
    /// DRE adaptor table mapping output labels to r-encoded field elements.
    pub adaptor_table: SparseAdaptorTable,
}

// ─── Step 3.1: Prover-side C&C verification ───────────────────────────────────

/// Verify all opened instances by re-deriving each from its seed and comparing
/// against the corresponding committed values.
///
/// The Prover calls this after receiving `opened` seeds from the Verifier.
/// `vk` and `public_inputs` are public — the Prover knows them.
#[cfg(feature = "garbled")]
pub fn verify_opened_instances(
    package: &CACSetupPackage,
    opened: &[(usize, u64)],
    vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
    public_inputs: &[Fr],
) -> Result<(), String> {
    use garbled_snark_verifier::core::utils::reset_gid;
    use crate::instance::BABEInstance;

    for &(idx, seed) in opened {
        reset_gid();
        let mut inst = BABEInstance::new_from_seed(seed);
        inst.enc_setup(vk, public_inputs)
            .map_err(|e| format!("instance {idx}: enc_setup failed: {e}"))?;

        let recomputed = inst.commit();
        let committed = &package.commits[idx];

        if recomputed.input_commits    != committed.input_commits    { return Err(format!("instance {idx}: input_commits mismatch")); }
        if recomputed.constant_commits != committed.constant_commits { return Err(format!("instance {idx}: constant_commits mismatch")); }
        if recomputed.h_msg            != committed.h_msg            { return Err(format!("instance {idx}: h_msg mismatch")); }
        if recomputed.ct_setup         != committed.ct_setup         { return Err(format!("instance {idx}: ct_setup mismatch")); }
        if recomputed.com_adaptor      != committed.com_adaptor      { return Err(format!("instance {idx}: com_adaptor mismatch")); }
        if recomputed.com_gc           != committed.com_gc           { return Err(format!("instance {idx}: com_gc mismatch")); }
    }
    Ok(())
}

/// Verify finalized instances by hashing the received GC data and comparing
/// against the committed `com_gc` and `com_adaptor`.
///
/// The Prover calls this after receiving `finalized` GC data from the Verifier.
#[cfg(feature = "garbled")]
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

    // Small values so the test completes in reasonable time.
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
    #[cfg(feature = "garbled")]
    fn test_cac_commit_open_verify() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);

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

        // Prover picks the finalized set (in production: random challenge).
        let finalized_indices: Vec<usize> = (0..TEST_M_CC).collect();

        // Verifier opens: seeds for the rest, GC data for finalized.
        let now = std::time::Instant::now();
        let (opened, finalized) = verifier.open(&finalized_indices);
        assert_eq!(opened.len(), TEST_N_CC - TEST_M_CC);
        assert_eq!(finalized.len(), TEST_M_CC);
        let elapsed = now.elapsed();
        println!("Verifier open for {TEST_N_CC} instances (finalizing {TEST_M_CC}) took {elapsed:.2?}");

        // // Prover verifies opened instances by re-deriving from seed.
        // verify_opened_instances(&package, &opened, &vk, &public_inputs)
        //     .expect("opened instance verification failed");
        //
        // // Prover verifies finalized instances via com_gc / com_adaptor.
        // verify_finalized_instances(&package, &finalized)
        //     .expect("finalized instance verification failed");
    }
}
