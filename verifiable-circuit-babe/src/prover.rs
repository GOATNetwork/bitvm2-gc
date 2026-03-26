use ark_bn254::{Bn254, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::pairing::Pairing;
use ark_ff::{One, Zero};
use ark_groth16::Proof as Groth16Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use garbled_snark_verifier::bag::{Circuit, S};
use garbled_snark_verifier::dv_bn254::fq::Fq;
use crate::babe::{derive_hashlock, h, WeKnownPi1ProveCt, WeKnownPi1SetupCt};
use crate::cac::{CACSetupPackage, FinalizedInstanceData};
use crate::dre::matrices::u_bar_vec;
use crate::gc::SparseAdaptorTable;
use crate::instance::commit::CACInstanceCommit;
use crate::soldering::{SolderedLabelsData, SolderingData};

pub struct BABEProver {
    groth16_proof: Groth16Proof<Bn254>,
    encoding_keys: Vec<S>,
    pub valid_msg: Option<[u8; 32]>,
    pub valid_ct_prove: Option<WeKnownPi1ProveCt>,
    pub valid_finalized_id: Option<usize>,
}

impl BABEProver {
    pub fn new(groth16_proof: Groth16Proof<Bn254>) -> Self {
        let encoding_keys = (0..2 * crate::dre::N).map(|_| S::random()).collect();
        Self {
            groth16_proof,
            encoding_keys,
            valid_msg: None,
            valid_ct_prove: None,
            valid_finalized_id: None,
        }
    }

    /// Verify that the guest output's commitments match the `CACSetupPackage`.
    pub fn verify_soldering_output_match_commitment(
        output: &SolderedLabelsData,
        package: &CACSetupPackage,
        finalized_indices: &[usize],
    ) -> Result<(), String> {
        let base_idx = finalized_indices[0];
        for (j, (h0, h1)) in output.base_commitment.iter().enumerate() {
            let committed = &package.commits[base_idx].input_commits[j];
            if h0 != &committed[0] {
                return Err(format!("base commitment mismatch at wire {j} label 0"));
            }
            if h1 != &committed[1] {
                return Err(format!("base commitment mismatch at wire {j} label 1"));
            }
        }
        for (i, &idx) in finalized_indices[1..].iter().enumerate() {
            for (j, (h0, h1)) in output.commitments[i].iter().enumerate() {
                let committed = &package.commits[idx].input_commits[j];
                if h0 != &committed[0] {
                    return Err(format!("instance {idx} commitment mismatch at wire {j} label 0"));
                }
                if h1 != &committed[1] {
                    return Err(format!("instance {idx} commitment mismatch at wire {j} label 1"));
                }
            }
        }
        Ok(())
    }

    /// Called when Prover receives `SolderingData` from Verifier (off-chain).
    ///
    /// Verifies:
    /// 1. The ZK soldering proof output is consistent with the CAC commitments.
    /// 2. Constant labels match the per-instance `constant_commits`.
    /// 3. The committed `h_msg` for every finalized instance equals `h_msg_onchain`.
    pub fn verify_soldering_output(
        package: &CACSetupPackage,
        soldering: &SolderingData,
        h_msgs_onchain: &[[u8; 32]],
    ) -> Result<(), String> {
        let sld_output = &soldering.soldering_proof.soldered_output;

        // 1
        Self::verify_soldering_output_match_commitment(sld_output, package, &soldering.finalized_indices)?;

        // 2
        if soldering.constant_labels.len() != soldering.finalized_indices.len() {
            return Err(format!(
                "constant_labels len {} != finalized_indices len {}",
                soldering.constant_labels.len(),
                soldering.finalized_indices.len()
            ));
        }
        // 3
        for (i, &inst_idx) in soldering.finalized_indices.iter().enumerate() {
            let committed = &package.commits[inst_idx];
            let cl = &soldering.constant_labels[i];

            if h(&cl[0].0) != committed.constant_commits[0][0] {
                return Err(format!("instance {inst_idx}: constant wire-0 label mismatch"));
            }
            if h(&cl[1].0) != committed.constant_commits[1][1] {
                return Err(format!("instance {inst_idx}: constant wire-1 label mismatch"));
            }
            if committed.h_msg != h_msgs_onchain[i] {
                return Err(format!("instance {inst_idx}: h_msg does not match on-chain commitment"));
            }
        }

        Ok(())
    }

    /// Called upon seeing ChallengeAssert Tx on-chain and extracting the input label L from it.
    /// This function checks if Prover can compute the valid msg for WronglyChallenged Txn.
    pub fn check_compute_msg(
        &mut self,
        package: &CACSetupPackage,
        finalized: &[FinalizedInstanceData],
        base_input_labels: &[S],
        soldering: &SolderingData,
        h_msgs_onchain: &[[u8; 32]],
    ) -> bool {
        let sld = &soldering.soldering_proof.soldered_output;

        // Try base instance (finalized[0]).
        let base_full = Self::build_full_labels(&soldering.constant_labels[0], base_input_labels);
        let base_res = self.try_evaluate_instance(
            &finalized[0],
            &package.commits[finalized[0].index],
            &base_full,
            h_msgs_onchain[0]
        );
        match base_res {
            Ok(true) => return true,
            Ok(false) => eprintln!("Warning: base instance did not yield valid msg"),
            Err(e) => eprintln!("Error evaluating base instance: {e}"),
        }

        // If cant get valid msg from base instance, try non-base instances using per-wire deltas.
        for i in 1..finalized.len() {
            let deltas_i = &sld.deltas[i - 1];
            let instance_labels: Vec<S> = base_input_labels
                .iter()
                .enumerate()
                .map(|(j, &base_lbl)| {
                    let (d0, d1) = deltas_i[j];
                    if h(&base_lbl.0) == sld.base_commitment[j].0 {
                        base_lbl ^ S(d0)
                    } else {
                        base_lbl ^ S(d1)
                    }
                })
                .collect();

            let full = Self::build_full_labels(&soldering.constant_labels[i], &instance_labels);
            let temp = self.try_evaluate_instance(
                &finalized[i],
                &package.commits[finalized[i].index],
                &full,
                h_msgs_onchain[i]
            );
            match temp {
                Ok(true) => return true,
                Ok(false) => eprintln!("Warning: non-base instance: {i} did not yield valid msg"),
                Err(e) => eprintln!("Error evaluating non-base instance: {e}"),
            }
        }

        false
    }

    fn build_full_labels(constant_labels: &[S; 2], input_labels: &[S]) -> Vec<S> {
        let mut v = Vec::with_capacity(2 + input_labels.len());
        v.push(constant_labels[0]);
        v.push(constant_labels[1]);
        v.extend_from_slice(input_labels);
        v
    }

    /// Evaluate the garbled circuit for one instance, decrypt the message, and check it
    /// against `h_msg_onchain`. On success, stores the result fields and returns `Ok(true)`.
    fn try_evaluate_instance(
        &mut self,
        data: &FinalizedInstanceData,
        committed: &CACInstanceCommit,
        full_labels: &[S],
        h_msg_onchain: [u8; 32],
    ) -> Result<bool, String> {
        let (mut circuit, gc_output_indices) = crate::gc::read_fresh_circuit();
        let ct_prove = self.compute_ct_prove(
            &mut circuit,
            &gc_output_indices,
            full_labels,
            &data.gc_ciphertexts,
            &data.adaptor_table,
        );
        drop(circuit);

        let msg = Self::compute_msg(&self.groth16_proof, &ct_prove, &committed.ct_setup)?;
        // found the valid one.
        if derive_hashlock(&msg) == h_msg_onchain {
            self.valid_msg = Some(msg);
            self.valid_ct_prove = Some(ct_prove);
            self.valid_finalized_id = Some(data.index);
            return Ok(true);
        }

        Ok(false)
    }

    /// Garble-evaluate the circuit and return the resulting `ct1 = r·π₁`.
    pub fn compute_ct_prove(
        &self,
        garbled_circuit: &mut Circuit,
        gc_output_indices: &[usize],
        input_labels: &[S],
        ciphertext: &[Option<S>],
        adaptor_table: &SparseAdaptorTable,
    ) -> WeKnownPi1ProveCt {
        let pi1 = self.groth16_proof.a;
        for (i, &lbl) in input_labels.iter().enumerate() {
            garbled_circuit.0[i].borrow_mut().label = Some(lbl);
        }

        let witness: Vec<bool> = Fq::to_bits(pi1.x)
            .into_iter()
            .chain(Fq::to_bits(pi1.y).into_iter())
            .collect();

        garbled_circuit.set_witness_value(&witness);
        for gate in &mut garbled_circuit.1 {
            gate.evaluate();
        }

        garbled_circuit.garbled_evaluate_without_delta(ciphertext);

        let output_labels: Vec<[u8; 16]> = gc_output_indices
            .iter()
            .map(|i| garbled_circuit.0[*i].borrow().get_label().0)
            .collect();

        let u_bar = u_bar_vec(&pi1);
        let decrypted_encodings = adaptor_table.eval(&output_labels, &u_bar);

        let mut sum = G1Projective::zero();
        let mut weight = ark_bn254::Fr::one();
        for decoding in decrypted_encodings {
            let (x, y, z) = decoding.f_i;
            sum += G1Projective::new(x, y, z) * weight;
            weight += weight;
        }

        let mut ct1 = Vec::new();
        sum.into_affine().serialize_compressed(&mut ct1).expect("serialize r·π₁");
        WeKnownPi1ProveCt { ct1_r_pi1: ct1 }
    }

    /// Decrypt the message from `ct_prove` and `ct_setup` using the Groth16 proof.
    pub fn compute_msg(
        proof: &Groth16Proof<Bn254>,
        ct_prove: &WeKnownPi1ProveCt,
        ct_setup: &WeKnownPi1SetupCt,
    ) -> Result<[u8; 32], String> {
        let ct1 = G1Affine::deserialize_compressed(ct_prove.ct1_r_pi1.as_slice())
            .map_err(|e| format!("deserialize ct1: {e}"))?
            .into_group();
        let ct2 = G2Affine::deserialize_compressed(ct_setup.ct2_r_delta_g2.as_slice())
            .map_err(|e| format!("deserialize ct2: {e}"))?
            .into_group();

        let r_y = Bn254::pairing(ct1, proof.b) - Bn254::pairing(proof.c, ct2);

        let mut ry_bytes = Vec::new();
        r_y.serialize_compressed(&mut ry_bytes).map_err(|e| format!("serialize r_y: {e}"))?;
        let mask = crate::babe::h(&ry_bytes);

        let ct3 = &ct_setup.ct3_masked_msg;
        if ct3.len() != 32 {
            return Err(format!("ct3 unexpected length {}", ct3.len()));
        }
        let mut msg = [0u8; 32];
        for i in 0..32 {
            msg[i] = ct3[i] ^ mask[i];
        }
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::marker::PhantomData;
    use ark_bn254::{Bn254, Fr};
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ff::PrimeField;
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use rand::SeedableRng;
    use garbled_snark_verifier::core::utils::reset_gid;
    use crate::cac::{cac_finalize_indices, verify_finalized_instances};
    use crate::instance::BABEInstance;
    use crate::soldering::{build_soldered_wires_input, soldering_guest_compute, SolderingProof};
    use crate::verifier::BABEVerifier;

    const TEST_N_CC: usize = 4;
    const TEST_M_CC: usize = 2;

    #[derive(Copy, Clone)]
    struct DummyCircuit<F: PrimeField> {
        a: Option<F>,
        b: Option<F>,
    }

    impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.new_input_variable(|| Ok(self.a.unwrap() * self.b.unwrap()))?;
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            Ok(())
        }
    }

    #[test]
    fn test_prover_ct_prove_decrypts_message() {
        reset_gid();
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);

        // 1. Groth16 setup and prove: a * b = c.
        let a = Fr::from(3u64);
        let b = Fr::from(7u64);
        let (pk, vk) = ark_groth16::Groth16::<Bn254>::setup(
            DummyCircuit::<Fr> { a: Some(a), b: Some(b) },
            &mut rng,
        ).unwrap();
        let proof = ark_groth16::Groth16::<Bn254>::prove(
            &pk,
            DummyCircuit::<Fr> { a: Some(a), b: Some(b) },
            &mut rng,
        ).unwrap();
        let public_inputs = vec![a * b];

        // 2. Verifier enc_setup.
        let mut verifier = BABEInstance::new_from_seed(rand::random());
        verifier.enc_setup(&vk, &public_inputs).unwrap();

        // 3. Full labels: [const_0, const_1, pi1_bits...].
        let full_labels = verifier.compute_pi1_labels_based_on_value(proof.a);

        // 4. Prover evaluates the garbled circuit.
        let prover = BABEProver::new(proof.clone());
        let (mut circuit, gc_output_indices) = crate::gc::read_fresh_circuit();
        let ct_prove = prover.compute_ct_prove(
            &mut circuit,
            &gc_output_indices,
            &full_labels,
            &verifier.ciphertexts,
            &verifier.adaptor_table,
        );
        drop(circuit);

        // 5. Decrypt and verify.
        let msg = BABEProver::compute_msg(&proof, &ct_prove, &verifier.ct_setup).unwrap();
        assert_eq!(msg, verifier.secrets.msg);
    }

    /// Build the common C&C + soldering scaffolding used by both tests below.
    /// Returns `(verifier, package, finalized_indices, finalized, soldering, h_msgs_onchain)`.
    fn setup_cac_soldering() -> (
        BABEVerifier,
        CACSetupPackage,
        Vec<usize>,
        Vec<FinalizedInstanceData>,
        SolderingData,
        Vec<[u8; 32]>,
    ) {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);
        let a = Fr::from(3u64);
        let b = Fr::from(7u64);
        let (_, vk) = ark_groth16::Groth16::<Bn254>::setup(
            DummyCircuit::<Fr> { a: Some(a), b: Some(b) }, &mut rng,
        ).unwrap();
        let public_inputs = vec![a * b];

        let verifier = BABEVerifier::new(TEST_N_CC, &vk, &public_inputs).unwrap();
        let package = verifier.commit();
        let finalized_indices = cac_finalize_indices(&package, TEST_M_CC);
        let (_, finalized) = verifier.open(&finalized_indices);

        let soldered_input = build_soldered_wires_input(&verifier, &finalized_indices);
        let soldered_output = soldering_guest_compute(&soldered_input);

        let constant_labels: Vec<[S; 2]> = finalized_indices.iter().map(|&idx| {
            let inst = &verifier.instances[idx];
            [inst.secrets.constant_0labels[0], inst.secrets.constant_0labels[1] ^ inst.secrets.delta]
        }).collect();

        let soldering = SolderingData {
            finalized_indices: finalized_indices.clone(),
            soldering_proof: SolderingProof { soldered_output, _proof: PhantomData },
            constant_labels,
        };

        let h_msgs_onchain: Vec<[u8; 32]> = finalized_indices.iter()
            .map(|&idx| package.commits[idx].h_msg)
            .collect();

        (verifier, package, finalized_indices, finalized, soldering, h_msgs_onchain)
    }

    // ── verify_soldering_output ───────────────────────────────────────────────

    #[test]
    fn test_verify_soldering_output_ok() {
        let (_, package, _, _, soldering, h_msgs_onchain) = setup_cac_soldering();
        BABEProver::verify_soldering_output(&package, &soldering, &h_msgs_onchain)
            .expect("verify_soldering_output should succeed");
    }

    #[test]
    fn test_verify_soldering_output_bad_h_msg() {
        let (_, package, _, _, soldering, mut h_msgs_onchain) = setup_cac_soldering();
        h_msgs_onchain[0] = [0u8; 32];
        assert!(
            BABEProver::verify_soldering_output(&package, &soldering, &h_msgs_onchain).is_err(),
            "tampered h_msg should fail"
        );
    }

    #[test]
    fn test_verify_soldering_output_bad_constant_label() {
        let (_, package, _, _, mut soldering, h_msgs_onchain) = setup_cac_soldering();
        // corrupt the wire-0 constant label of the first finalized instance
        soldering.constant_labels[0][0] = S::random();
        assert!(
            BABEProver::verify_soldering_output(&package, &soldering, &h_msgs_onchain).is_err(),
            "tampered constant label should fail"
        );
    }

    // ── check_compute_msg ─────────────────────────────────────────────────────

    #[test]
    fn test_check_compute_msg_finds_valid_msg() {
        let (verifier, package, finalized_indices, finalized, soldering, mut h_msgs_onchain) =
            setup_cac_soldering();

        // Prove with the same dummy circuit.
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);
        let a = Fr::from(3u64);
        let b = Fr::from(7u64);
        let (pk, _) = ark_groth16::Groth16::<Bn254>::setup(
            DummyCircuit::<Fr> { a: Some(a), b: Some(b) }, &mut rng,
        ).unwrap();
        let proof = ark_groth16::Groth16::<Bn254>::prove(
            &pk,
            DummyCircuit::<Fr> { a: Some(a), b: Some(b) },
            &mut rng,
        ).unwrap();

        // base_input_labels: active labels for the 508 π₁ input wires of the base instance.
        let base_idx = finalized_indices[0];
        let all_labels = verifier.instances[base_idx].compute_pi1_labels_based_on_value(proof.a);
        let base_input_labels = &all_labels[2..]; // strip constant-wire labels

        let mut prover = BABEProver::new(proof.clone());
        let found = prover.check_compute_msg(
            &package, &finalized, base_input_labels, &soldering, &h_msgs_onchain,
        );

        assert!(found, "expected a valid msg to be found");
        assert!(prover.valid_msg.is_some());
        assert!(prover.valid_ct_prove.is_some());
        assert!(prover.valid_finalized_id.is_some());

        // change the base msg to access non-base instance
        let mut prover = BABEProver::new(proof);
        h_msgs_onchain[0] = [0u8; 32];
        let found = prover.check_compute_msg(
            &package, &finalized, base_input_labels, &soldering, &h_msgs_onchain,
        );
        assert!(found, "expected a valid msg to be found");
        assert!(prover.valid_msg.is_some());
        assert!(prover.valid_ct_prove.is_some());
        assert!(prover.valid_finalized_id.is_some());
        assert_ne!(prover.valid_finalized_id.unwrap(), finalized_indices[0]);
    }
}