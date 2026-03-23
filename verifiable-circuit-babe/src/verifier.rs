use ark_bn254::Fr;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use garbled_snark_verifier::core::utils::NON_CAC_DELTA;
use garbled_snark_verifier::dv_bn254::fq::Fq;
use ark_serialize::CanonicalSerialize;
use garbled_snark_verifier::bag::{Circuit, S};
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use rand::RngCore;
use crate::babe::WeKnownPi1SetupCt;
use crate::gc::SparseAdaptorTable;

pub struct BABEVerifier {
    pub(crate) msg: [u8; 32],
    pub r: Fr,
    pub garbled_circuit: Circuit,
    pub gc_output_indices: Vec<usize>,
    pub ct_setup: WeKnownPi1SetupCt,
    pub(crate) encoding_keys: Vec<S>,
    pub constant_0labels: [S; 2],
    pub adaptor_table: SparseAdaptorTable,
    pub ciphertexts: Vec<Option<S>>,
}

impl BABEVerifier {
    pub fn new() -> Self {
        // Random 32-byte secret message and random r.
        let mut msg = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut msg);
        let r = Fr::rand(&mut rng);

        // Build circuit structure without witness values and without garbling.
        // The fallback point g can be any fixed generator; we use the BN254 G1 generator.
        let g = ark_bn254::G1Affine::generator();
        let (bld, gc_output_indices) = crate::gc::compile_babe_gc(g);
        let garbled_circuit = bld.build(&[]);

        // Encoding keys: random 0-labels for each of the 2*N input wires (x bits then y bits).
        // Only the 0-labels need to be stored here.
        // This is the ek
        let encoding_keys = (0..2 * crate::dre::N).map(|_| S::random()).collect();
        let zero_label = S::random();
        let one_label = S::random();

        Self {
            msg,
            r,
            garbled_circuit,
            gc_output_indices,
            ct_setup: WeKnownPi1SetupCt { ct2_r_delta_g2: vec![], ct3_masked_msg: vec![] },
            encoding_keys,
            constant_0labels: [zero_label, one_label],
            adaptor_table: SparseAdaptorTable { entries: vec![] },
            ciphertexts: vec![],
        }
    }


    /// Encsetup(crs, x, msg; r): ctsetup = (r·[delta]_2, RO(rY) ⊕ msg),
    /// where Y = e([alpha]_1, [beta]_2) · e(vk_x, [gamma]_2).
    pub fn enc_setup(
        &mut self,
        vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
        public_inputs: &[Fr],
    ) -> Result<(), String> {
        let vk_x = groth16_vk_x(vk, public_inputs).ok_or("Failed to get vk_x")?;

        let r_delta = vk.delta_g2.into_group() * self.r;

        let t1 = ark_bn254::Bn254::pairing(vk.alpha_g1, vk.beta_g2.into_group() * self.r);
        let t2 = ark_bn254::Bn254::pairing(vk_x, vk.gamma_g2.into_group() * self.r);
        let r_y = t1 + t2;

        let mut ry_bytes = Vec::new();
        r_y.serialize_compressed(&mut ry_bytes).or(Err("Failed to serialize ry_bytes"))?;
        let mask = crate::babe::h(&ry_bytes);
        let ct3 = self.msg.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect::<Vec<_>>();

        let ct_setup = WeKnownPi1SetupCt {
            ct2_r_delta_g2: g2_to_ser(r_delta),
            ct3_masked_msg: ct3,
        };
        self.ct_setup = ct_setup;
        Ok(())
    }

    #[cfg(feature = "garbled")]
    pub fn build_adaptor_table_and_ciphertexts(&mut self) {
        use ark_bn254::G1Projective;
        use ark_ff::Zero;
        use crate::dre::matrices::u_bar_vec;

        // Step 1: Fresh circuit and apply encoding-key 0-labels to input wires.
        if !self.garbled_circuit.is_fresh() {
            self.garbled_circuit.reset_circuit_except_constants();
        }
        // add labels
        self.garbled_circuit.0[0].borrow_mut().label = Some(self.constant_0labels[0]);
        self.garbled_circuit.0[1].borrow_mut().label = Some(self.constant_0labels[1]);
        for (i, &key) in self.encoding_keys.iter().enumerate() {
            self.garbled_circuit.0[2 + i].borrow_mut().label = Some(key);
        }

        // Step 2: Pick a random pi1 and evaluate the garbled circuit to obtain output labels.
        let pi1 = G1Projective::rand(&mut rand::thread_rng()).into_affine();
        let witness: Vec<bool> = Fq::to_bits(pi1.x)
            .into_iter()
            .chain(Fq::to_bits(pi1.y).into_iter())
            .collect();
        self.garbled_circuit.set_witness_value(&witness);
        for gate in &mut self.garbled_circuit.1 {
            gate.evaluate();
        }
        let ciphertexts = self.garbled_circuit.garbled_gates();
        self.ciphertexts = ciphertexts;

        // Step 3: Recover the 0-label for each output wire (u_bar bit position).
        // In Free-XOR: label_1 = label_0 XOR NON_CAC_DELTA.
        let u_bar_pi1 = u_bar_vec(&pi1);
        let labels: Vec<[u8;16]> = self.gc_output_indices
            .iter()
            .zip(u_bar_pi1.iter())
            .flat_map(|(idx, u)| {
                let current = self.garbled_circuit.0[*idx]
                    .borrow()
                    .select(self.garbled_circuit.0[*idx].borrow().get_value());
                let label_0 = if u.is_zero() { current } else { current ^ NON_CAC_DELTA };
                [label_0.0, (label_0 ^ NON_CAC_DELTA).0]
            })
            .collect();

        // Step 4: Build and store the adaptor table.
        self.adaptor_table = SparseAdaptorTable::build_from_r_and_labels(self.r, &labels);
    }

    pub fn compute_pi1_labels(
        &mut self,
        pi1: ark_bn254::G1Affine,
    ) -> Vec<S> {
        let x_bits = Fq::to_bits(pi1.x);
        let y_bits = Fq::to_bits(pi1.y);
        let witness: Vec<bool> = x_bits.into_iter().chain(y_bits.into_iter()).collect();

        let mut labels_wo_deltas: Vec<S> = Vec::new();
        labels_wo_deltas.push(self.constant_0labels[0]);
        labels_wo_deltas.push(self.constant_0labels[1] ^ NON_CAC_DELTA);
        let tail: Vec<S> = witness.iter().enumerate().map(|(i, &b)| {
            let key = self.encoding_keys[i].clone();
            if b { key ^ NON_CAC_DELTA } else { key }
        }).collect();
        labels_wo_deltas.extend(tail);
        labels_wo_deltas
    }
}

fn groth16_vk_x(
    vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
    public_inputs: &[Fr],
) -> Option<ark_bn254::G1Projective> {
    if vk.gamma_abc_g1.len() != public_inputs.len() + 1 {
        return None;
    }
    let mut acc = vk.gamma_abc_g1[0].into_group();
    for (i, x) in public_inputs.iter().enumerate() {
        acc += vk.gamma_abc_g1[i + 1].into_group() * *x;
    }
    Some(acc)
}

fn g2_to_ser(p: ark_bn254::G2Projective) -> Vec<u8> {
    let mut out = Vec::new();
    p.into_affine().serialize_compressed(&mut out).expect("serialize g2");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ec::pairing::Pairing;
    use ark_ff::PrimeField;
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_serialize::CanonicalDeserialize;
    use rand::SeedableRng;

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
    fn enc_setup_prove_dec_roundtrip() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);

        // 1. Groth16 setup and prove: a * b = c.
        let a = Fr::from(3u64);
        let b = Fr::from(7u64);
        let circuit = DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) };
        let (pk, vk) = ark_groth16::Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng)
            .expect("groth16 setup");
        let proof = ark_groth16::Groth16::<ark_bn254::Bn254>::prove(
            &pk,
            DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) },
            &mut rng,
        )
        .expect("groth16 prove");
        let public_inputs = vec![a * b];

        // 2. Verifier generates ct_setup = (ct2, ct3).
        //    ct2 = r * [delta]_2,  ct3 = RO(rY) ⊕ msg.
        let mut verifier = BABEVerifier::new();
        verifier.enc_setup(&vk, &public_inputs).unwrap();

        // 3. Prover generates ct_prove: ct1 = r * π1  (proof.a = π1).
        //    Must use verifier.r — the same r used in enc_setup.
        let ct1 = proof.a.into_group() * verifier.r;

        // 4. Decrypt following the paper formula:
        //    msg = ct3 - RO(e(ct1, π2) - e(π3, ct2))
        //    where π2 = proof.b, π3 = proof.c.
        let ct2 = ark_bn254::G2Affine::deserialize_compressed(verifier.ct_setup.ct2_r_delta_g2.as_slice())
            .expect("deserialize ct2")
            .into_group();
        let lhs = ark_bn254::Bn254::pairing(ct1, proof.b);
        let rhs = ark_bn254::Bn254::pairing(proof.c, ct2);
        let r_y = lhs - rhs;

        let mut ry_bytes = Vec::new();
        r_y.serialize_compressed(&mut ry_bytes).unwrap();
        let mask = crate::babe::h(&ry_bytes);

        let decrypted: [u8; 32] = verifier.ct_setup.ct3_masked_msg.iter()
            .zip(mask.iter())
            .map(|(c, m)| c ^ m)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // 5. Recovered msg must match verifier's internal secret.
        assert_eq!(decrypted, verifier.msg);
    }
}
