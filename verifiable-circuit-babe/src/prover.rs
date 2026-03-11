use ark_bn254::G1Projective;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, Zero};
use ark_groth16::{Proof as Groth16Proof, VerifyingKey as Groth16VerifyingKey};
use ark_serialize::CanonicalSerialize;
use garbled_snark_verifier::bag::{Circuit, S};
use garbled_snark_verifier::dv_bn254::fq::Fq;
use crate::babe::WeKnownPi1ProveCt;
use crate::dre::DRE;
use crate::dre::affine_dre::AffineDRE;
use crate::dre::matrices::u_bar_vec;
use crate::gc::AdaptorTable;

pub struct BABEProver {
    groth16_proof: Groth16Proof<ark_bn254::Bn254>,
    encoding_keys: Vec<S>,
    pub ct_prove: WeKnownPi1ProveCt,
}

impl BABEProver {
    pub fn new(
        groth16_proof: Groth16Proof<ark_bn254::Bn254>,
    ) -> Self {
        // Encoding keys: random 0-labels for each of the 2*N input wires (x bits then y bits).
        let encoding_keys = (0..2 * crate::dre::N).map(|_| S::random()).collect();

        Self {
            groth16_proof,
            encoding_keys,
            ct_prove: WeKnownPi1ProveCt { ct1_r_pi1: vec![] },
        }
    }

    #[cfg(feature = "garbled")]
    pub fn compute_ct_prove(
        &mut self,
        garbled_circuit: &mut Circuit,
        gc_output_indices: &[usize],
        input_labels: &Vec<S>,
        ciphertext: &[Option<S>],
        adaptor_table: &AdaptorTable,
    ) {
        let pi1 = self.groth16_proof.a;
        for (i, &lbl) in input_labels.iter().enumerate() {
            garbled_circuit.0[i].borrow_mut().label = Some(lbl);
        }

        // Step 4: Reset all non-constant wire values left from any previous evaluation,
        // then set π₁ = proof.a as the new witness and re-evaluate all gates.
        let witness: Vec<bool> = Fq::to_bits(pi1.x)
            .into_iter()
            .chain(Fq::to_bits(pi1.y).into_iter())
            .collect();

        garbled_circuit.set_witness_value(&witness);
        for gate in &mut garbled_circuit.1 {
            gate.evaluate();
        }

        // Step 5: Garble-evaluate
        garbled_circuit.garbled_evaluate_without_delta(ciphertext);

        // Step 6: Collect the output label held for each of the L output wires.
        let output_labels: Vec<[u8; 16]> = gc_output_indices.iter().map(|i| {
            garbled_circuit.0[*i].borrow().get_label().0
        })
            .collect();

        // Step 7: Compute ū(π₁) and eval the adaptor table to recover DRE encodings.
        let u_bar = u_bar_vec(&pi1);
        let decrypted_encodings = adaptor_table.eval(&output_labels, &u_bar);

        // Step 8: Decode each AffineDREEncoding and compute ∑ 2^i · f_i = r·π₁.
        let mut sum = G1Projective::zero();
        let mut weight = ark_bn254::Fr::one();
        for encoding in decrypted_encodings {
            let decoding = AffineDRE::dec(encoding);
            let (x, y, z) = decoding.f_i;
            let f_i = G1Projective::new(x, y, z);
            sum += f_i * weight;
            weight += weight;
        }

        // Step 9: Serialize r·π₁ and store as ct1.
        let mut ct1 = Vec::new();
        sum.into_affine().serialize_compressed(&mut ct1).expect("serialize r·π₁");
        self.ct_prove = WeKnownPi1ProveCt { ct1_r_pi1: ct1 };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    use ark_ff::PrimeField;
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use rand::SeedableRng;
    use crate::verifier::BABEVerifier;
    use std::io::Read;
    use std::ops::Mul;

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

    #[cfg(feature = "garbled")]
    #[test]
    fn test_prover_ct_prove_decrypts_message() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);

        // 1. Groth16 setup and prove: a * b = c.
        let a = Fr::from(3u64);
        let b = Fr::from(7u64);
        let (pk, vk) = ark_groth16::Groth16::<Bn254>::setup(
            DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) },
            &mut rng,
        ).unwrap();
        let proof = ark_groth16::Groth16::<Bn254>::prove(
            &pk,
            DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) },
            &mut rng,
        ).unwrap();
        let public_inputs = vec![a * b];
        println!("step 1 done: Groth16 proof generated");

        // 2. Verifier: enc_setup generates (ct2 = r·[delta]_2, ct3 = RO(rY) ⊕ msg).
        let mut verifier = BABEVerifier::new();
        verifier.enc_setup(&vk, &public_inputs).unwrap();
        println!("step 2 done: Verifier generated ct_setup");

        verifier.garbled_circuit.gate_counts().print();

        // let rpi1 = proof.a.into_group() * verifier.r;
        // println!("r pi1 :{:?}", rpi1.into_affine());

        // // 3. Verifier: build adaptor table binding r to the garbled circuit output labels.
        verifier.build_adaptor_table();
        {
            let n = verifier.adaptor_table.entries.len();
            let l = verifier.adaptor_table.entries[0].x.len();
            let adaptor_bytes = n * 3 * l * 2 * 32; // N entries * (x,y,z) * L cols * 2 cts * 32 bytes/ct
            println!("AdaptorTable size: {} bytes ({:.2} MB)", adaptor_bytes, adaptor_bytes as f64 / 1_048_576.0);
        }

        println!("step 3 done: Adaptor table");

        // 4. Verifier: compute the input labels for proof.a = π₁.
        let constant_labels = verifier.constant_0labels;
        let (input_labels, ciphertexts) = verifier.compute_pi1_labels_and_ciphertexts(proof.a);
        println!("step 4 done: Groth16 constant_labels");

        // 5. Prover: compute ct_prove = r·π₁ via garbled circuit + adaptor table.
        let mut prover = BABEProver::new(proof.clone());
        // fresh the circuit
        verifier.garbled_circuit.reset_circuit_except_constants();
        prover.compute_ct_prove(
            &mut verifier.garbled_circuit,
            &verifier.gc_output_indices,
            &input_labels,
            &ciphertexts,
            &verifier.adaptor_table,
        );
        println!("step 5 done: Groth16 constant_labels");

        // 6. Decrypt: msg = ct3 ⊕ RO(e(ct1, π₂) − e(π₃, ct2))
        //    where ct1 = r·π₁, ct2 = r·[delta]_2.
        let ct1 = G1Affine::deserialize_compressed(prover.ct_prove.ct1_r_pi1.as_slice())
            .unwrap()
            .into_group();
        let ct2 = G2Affine::deserialize_compressed(verifier.ct_setup.ct2_r_delta_g2.as_slice())
            .unwrap()
            .into_group();

        let lhs = Bn254::pairing(ct1, proof.b);
        let rhs = Bn254::pairing(proof.c, ct2);
        let r_y = lhs - rhs;

        let mut ry_bytes = Vec::new();
        r_y.serialize_compressed(&mut ry_bytes).unwrap();
        let mask = crate::babe::h(&ry_bytes);

        let decrypted: [u8; 32] = verifier.ct_setup.ct3_masked_msg
            .iter()
            .zip(mask.iter())
            .map(|(c, m)| c ^ m)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        println!("step 6 done: Groth16 mask decrypted");

        // 7. The prover recovered the verifier's secret message.
        assert_eq!(decrypted, verifier.msg);
    }
}