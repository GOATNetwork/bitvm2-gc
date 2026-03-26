use ark_bn254::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use garbled_snark_verifier::bag::S;
use garbled_snark_verifier::circuits::bn254::fq::Fq;
use crate::babe::WeKnownPi1SetupCt;
use crate::gc::SparseAdaptorTable;
use crate::instance::secret::InstanceSecrets;
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use ark_serialize::CanonicalSerialize;
use crate::instance::commit::CACInstanceCommit;
use crate::utils::{g2_to_ser, groth16_vk_x, h};

pub mod secret;
pub mod commit;

pub struct BABEInstance {
    pub seed: u64,
    pub secrets: InstanceSecrets,
    pub ct_setup: WeKnownPi1SetupCt,
    pub adaptor_table: SparseAdaptorTable,
    pub ciphertexts: Vec<Option<S>>,
}

impl BABEInstance {
    /// Construct a BABE instance fully determined by `seed`.
    /// W/O ct_setup.
    pub fn new_from_seed(seed: u64) -> Self {
        use ark_bn254::G1Projective;
        use ark_ff::Zero;
        use crate::dre::matrices::u_bar_vec;

        let secrets = InstanceSecrets::new_from_seed(seed);

        // Load fresh circuit structure from pre-serialized files; drop after use.
        let (mut circuit, gc_output_indices) = crate::gc::read_fresh_circuit();

        // Apply encoding keys and constant 0-labels to input wires.
        circuit.0[0].borrow_mut().label = Some(secrets.constant_0labels[0]);
        circuit.0[1].borrow_mut().label = Some(secrets.constant_0labels[1]);
        for (i, &key) in secrets.encoding_keys.iter().enumerate() {
            circuit.0[2 + i].borrow_mut().label = Some(key);
        }

        // Evaluate circuit at a random pi1 to obtain output labels.
        let pi1 = G1Projective::rand(&mut rand::thread_rng()).into_affine();
        let witness: Vec<bool> = Fq::to_bits(pi1.x)
            .into_iter()
            .chain(Fq::to_bits(pi1.y).into_iter())
            .collect();
        circuit.set_witness_value(&witness);
        for gate in &mut circuit.1 {
            gate.evaluate();
        }
        let ciphertexts = circuit.garbled_gates_with_delta(secrets.delta);

        // Recover label0 for each output wire.
        let delta = secrets.delta;
        let u_bar_pi1 = u_bar_vec(&pi1);
        let output_labels: Vec<[u8; 16]> = gc_output_indices
            .iter()
            .zip(u_bar_pi1.iter())
            .flat_map(|(idx, u)| {
                let current = circuit.0[*idx]
                    .borrow()
                    .select_with_delta(circuit.0[*idx].borrow().get_value(), delta);
                let label_0 = if u.is_zero() { current } else { current ^ delta };
                [label_0.0, (label_0 ^ delta).0]
            })
            .collect();

        let adaptor_table = SparseAdaptorTable::build_from_r_and_labels(
            secrets.r,
            &output_labels,
            &secrets.rhos,
            &secrets.fq_deltas,
        );

        // circuit is dropped here — not stored in the instance.

        Self {
            seed,
            secrets,
            ct_setup: WeKnownPi1SetupCt { ct2_r_delta_g2: vec![], ct3_masked_msg: vec![] },
            adaptor_table,
            ciphertexts,
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

        let r = self.secrets.r;
        let r_delta = vk.delta_g2.into_group() * r;

        let t1 = ark_bn254::Bn254::pairing(vk.alpha_g1, vk.beta_g2.into_group() * r);
        let t2 = ark_bn254::Bn254::pairing(vk_x, vk.gamma_g2.into_group() * r);
        let r_y = t1 + t2;

        let mut ry_bytes = Vec::new();
        r_y.serialize_compressed(&mut ry_bytes).or(Err("Failed to serialize ry_bytes"))?;
        let mask = h(&ry_bytes);
        let ct3 = self.secrets.msg.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect::<Vec<_>>();

        self.ct_setup = WeKnownPi1SetupCt {
            ct2_r_delta_g2: g2_to_ser(r_delta),
            ct3_masked_msg: ct3,
        };
        Ok(())
    }

    /// Returns the input labels given the bits of pi1.
    pub fn compute_pi1_labels_based_on_value(&self, pi1: ark_bn254::G1Affine) -> Vec<S> {
        let x_bits = Fq::to_bits(pi1.x);
        let y_bits = Fq::to_bits(pi1.y);
        let witness: Vec<bool> = x_bits.into_iter().chain(y_bits.into_iter()).collect();
        let delta = self.secrets.delta;

        let mut labels = Vec::new();
        labels.push(self.secrets.constant_0labels[0]);
        labels.push(self.secrets.constant_0labels[1] ^ delta);
        let tail: Vec<S> = witness.iter().enumerate().map(|(i, &b)| {
            let key = self.secrets.encoding_keys[i];
            if b { key ^ delta } else { key }
        }).collect();
        labels.extend(tail);
        labels
    }

    pub fn commit(&self) -> CACInstanceCommit {
        CACInstanceCommit::from_instance(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_serialize::CanonicalDeserialize;
    use rand::SeedableRng;
    use crate::babe::DummyMulCircuit;

    #[test]
    fn enc_setup_prove_dec_roundtrip() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);

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

        let mut instance = BABEInstance::new_from_seed(42);
        instance.enc_setup(&vk, &public_inputs).unwrap();

        let ct1 = proof.a.into_group() * instance.secrets.r;

        let ct2 = ark_bn254::G2Affine::deserialize_compressed(
            instance.ct_setup.ct2_r_delta_g2.as_slice(),
        )
            .expect("deserialize ct2")
            .into_group();
        let lhs = ark_bn254::Bn254::pairing(ct1, proof.b);
        let rhs = ark_bn254::Bn254::pairing(proof.c, ct2);
        let r_y = lhs - rhs;

        let mut ry_bytes = Vec::new();
        r_y.serialize_compressed(&mut ry_bytes).unwrap();
        let mask = h(&ry_bytes);

        let decrypted: [u8; 32] = instance.ct_setup.ct3_masked_msg.iter()
            .zip(mask.iter())
            .map(|(c, m)| c ^ m)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        assert_eq!(decrypted, instance.secrets.msg);
    }
}