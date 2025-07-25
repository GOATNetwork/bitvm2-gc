use crate::bag::*;
use crate::circuits::bn254::finalexp::{final_exponentiation_evaluate_montgomery_fast, final_exponentiation_montgomery_fast_circuit};
use crate::circuits::bn254::fp254impl::Fp254Impl;
use crate::circuits::bn254::fq::Fq;
use crate::circuits::bn254::fq2::Fq2;
use crate::circuits::bn254::fq12::Fq12;
use crate::circuits::bn254::fr::Fr;
use crate::circuits::bn254::g1::{G1Projective, projective_to_affine_evaluate_montgomery, projective_to_affine_montgomery};
use crate::circuits::bn254::pairing::{deserialize_compressed_g1_circuit, deserialize_compressed_g1_circuit_evaluate, deserialize_compressed_g2_circuit, deserialize_compressed_g2_circuit_evaluate, multi_miller_loop_groth16_evaluate_montgomery_fast, multi_miller_loop_groth16_montgomery_fast_circuit};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::Field;
use ark_serialize::*;

/// A verification key in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<E: Pairing> {
    /// The `alpha * G`, where `G` is the generator of `E::G1`.
    pub alpha_g1: E::G1Affine,
    /// The `alpha * H`, where `H` is the generator of `E::G2`.
    pub beta_g2: E::G2Affine,
    /// The `gamma * H`, where `H` is the generator of `E::G2`.
    pub gamma_g2: E::G2Affine,
    /// The `delta * H`, where `H` is the generator of `E::G2`.
    pub delta_g2: E::G2Affine,
    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is
    /// the generator of `E::G1`.
    pub gamma_abc_g1: Vec<E::G1Affine>,
}

pub fn groth16_verifier_evaluate_montgomery(
    public: Wires,
    proof_a: Wires,
    proof_b: Wires,
    proof_c: Wires,
    vk: VerifyingKey<ark_bn254::Bn254>,
    compressed: bool,
) -> (Wirex, GateCount) {
    let mut gate_count = GateCount::zero();

    let mut proof_a = proof_a;
    let mut proof_b = proof_b;
    let mut proof_c = proof_c;
    let mut gc;
    if compressed {
        (proof_a, gc) = deserialize_compressed_g1_circuit_evaluate(
            proof_a[..Fq::N_BITS].to_vec(),
            proof_a[Fq::N_BITS].clone(),
        );
        gate_count += gc;
        assert_eq!(proof_a.len(), 2 * Fq::N_BITS);
        (proof_b, gc) = deserialize_compressed_g2_circuit_evaluate(
            proof_b[..Fq2::N_BITS].to_vec(),
            proof_b[Fq2::N_BITS].clone(),
        );
        gate_count += gc;
        assert_eq!(proof_b.len(), 2 * Fq2::N_BITS);

        (proof_c, gc) = deserialize_compressed_g1_circuit_evaluate(
            proof_c[..Fq::N_BITS].to_vec(),
            proof_c[Fq::N_BITS].clone(),
        );
        gate_count += gc;
        assert_eq!(proof_c.len(), 2 * Fq::N_BITS);
    }

    let (msm_temp, gc) = (
        G1Projective::wires_set_montgomery(
            ark_bn254::G1Projective::msm(&[vk.gamma_abc_g1[1]], &[Fr::from_wires(public.clone())])
                .unwrap(),
        ),
        GateCount::msm_montgomery(),
    );
    // let (msm_temp, gc) = G1Projective::msm_with_constant_bases_evaluate_montgomery::<10>(vec![public], vec![vk.gamma_abc_g1[1].into_group()]);
    gate_count += gc;
    // let (msm, gc) = G1Projective::add_evaluate_montgomery(
    //     msm_temp,
    //     G1Projective::wires_set_montgomery(vk.gamma_abc_g1[0].into_group()),
    // );
    // gate_count += gc;
    let mut circuit = Circuit::empty();
    let mut msm_circuit = G1Projective::add_montgomery(
        msm_temp,
        G1Projective::wires_set_montgomery(vk.gamma_abc_g1[0].into_group())
    );
    // msm_circuit.evaluate();
    gate_count += msm_circuit.gate_counts();
    let msm = circuit.extend(msm_circuit);

    let (msm_affine, gc) = projective_to_affine_evaluate_montgomery(msm);
    gate_count += gc;

    let (f, gc) = multi_miller_loop_groth16_evaluate_montgomery_fast(
        msm_affine,
        proof_c,
        proof_a,
        -vk.gamma_g2,
        -vk.delta_g2,
        proof_b,
    );
    gate_count += gc;

    let alpha_beta = ark_bn254::Bn254::final_exponentiation(ark_bn254::Bn254::multi_miller_loop(
        [vk.alpha_g1.into_group()],
        [-vk.beta_g2],
    ))
    .unwrap()
    .0
    .inverse()
    .unwrap();
    let (f, gc) = final_exponentiation_evaluate_montgomery_fast(f); // Fq12::wires_set(ark_bn254::Bn254::final_exponentiation(MillerLoopOutput(Fq12::from_wires(f))).unwrap().0);
    gate_count += gc;

    let (result, gc) = Fq12::equal_constant_evaluate(f, Fq12::as_montgomery(alpha_beta));
    gate_count += gc;
    (result[0].clone(), gate_count)
}

pub fn groth16_verifier_montgomery_circuit(
    public: Wires,
    proof_a: Wires,
    proof_b: Wires,
    proof_c: Wires,
    vk: VerifyingKey<ark_bn254::Bn254>,
    compressed: bool,
) -> Circuit {
    let mut circuit = Circuit::empty();
    
    let mut proof_a = proof_a;
    let mut proof_b = proof_b;
    let mut proof_c = proof_c;
    if compressed {
        let proof_a_circuit = deserialize_compressed_g1_circuit(
            proof_a[..Fq::N_BITS].to_vec(),
            proof_a[Fq::N_BITS].clone(),
        );

        proof_a = circuit.extend(proof_a_circuit);
        assert_eq!(proof_a.len(), 2 * Fq::N_BITS);
        
        let proof_b_circuit = deserialize_compressed_g2_circuit(
            proof_b[..Fq2::N_BITS].to_vec(),
            proof_b[Fq2::N_BITS].clone(),
        );
        proof_b = circuit.extend(proof_b_circuit);
        assert_eq!(proof_b.len(), 2 * Fq2::N_BITS);
        
        let proof_c_circuit = deserialize_compressed_g1_circuit(
            proof_c[..Fq::N_BITS].to_vec(),
            proof_c[Fq::N_BITS].clone(),
        );
        proof_c = circuit.extend(proof_c_circuit);
        assert_eq!(proof_c.len(), 2 * Fq::N_BITS);
    }
    
    let msm_temp_circuit = G1Projective::msm_with_constant_bases_montgomery_circuit::<10>(
        vec![public], vec![vk.gamma_abc_g1[1].into_group()]);
    let msm_temp = circuit.extend(msm_temp_circuit);
    
    let msm_circuit = G1Projective::add_montgomery(
        msm_temp,
        G1Projective::wires_set_montgomery(vk.gamma_abc_g1[0].into_group())
    );
    let msm = circuit.extend(msm_circuit);
   
    let msm_affine_circuit = projective_to_affine_montgomery(msm);
    let msm_affine = circuit.extend(msm_affine_circuit);

    let multi_miller_circut = multi_miller_loop_groth16_montgomery_fast_circuit(
        msm_affine,
        proof_c,
        proof_a,
        -vk.gamma_g2,
        -vk.delta_g2,
        proof_b,
    );
    let f = circuit.extend(multi_miller_circut);

    let alpha_beta = ark_bn254::Bn254::final_exponentiation(ark_bn254::Bn254::multi_miller_loop(
        [vk.alpha_g1.into_group()],
        [-vk.beta_g2],
    ))
        .unwrap()
        .0
        .inverse()
        .unwrap();

    let final_exponentiation_circuit = final_exponentiation_montgomery_fast_circuit(f);
    let f = circuit.extend(final_exponentiation_circuit);

    let result_circuit = Fq12::equal_constant(f, Fq12::as_montgomery(alpha_beta));
    let result = circuit.extend(result_circuit);
    circuit.add_wires(result.clone());

    circuit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::bn254::fq::Fq;
    use crate::circuits::bn254::fq2::Fq2;
    use crate::circuits::bn254::g1::G1Affine;
    use crate::circuits::bn254::g2::G2Affine;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ff::{PrimeField, UniformRand};
    use ark_groth16::Groth16;
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::test_rng;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    pub fn groth16_verifier(
        public: Vec<ark_bn254::Fr>,
        proof: ark_groth16::Proof<ark_bn254::Bn254>,
        vk: ark_groth16::VerifyingKey<ark_bn254::Bn254>,
    ) -> bool {
        let scalars = [vec![ark_bn254::Fr::ONE], public.clone()].concat();
        let msm = ark_bn254::G1Projective::msm(&vk.gamma_abc_g1, &scalars).unwrap();
        let qap = ark_bn254::Bn254::multi_miller_loop(
            [msm, proof.c.into_group(), proof.a.into_group()],
            [-vk.gamma_g2, -vk.delta_g2, proof.b],
        );
        let alpha_beta = ark_bn254::Bn254::final_exponentiation(
            ark_bn254::Bn254::multi_miller_loop([vk.alpha_g1.into_group()], [-vk.beta_g2]),
        )
        .unwrap()
        .0
        .inverse()
        .unwrap();
        let f = ark_bn254::Bn254::final_exponentiation(qap).unwrap().0;
        f == alpha_beta
    }

    #[derive(Copy, Clone)]
    struct DummyCircuit<F: PrimeField> {
        pub a: Option<F>,
        pub b: Option<F>,
        pub num_variables: usize,
        pub num_constraints: usize,
    }

    impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.new_input_variable(|| {
                let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                Ok(a * b)
            })?;

            for _ in 0..(self.num_variables - 3) {
                let _ =
                    cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            }

            for _ in 0..self.num_constraints - 1 {
                cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            }

            cs.enforce_constraint(lc!(), lc!(), lc!())?;

            Ok(())
        }
    }

    #[test]
    fn test_groth16_verifier() {
        let k = 6;
        let mut rng = ChaCha12Rng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit::<<ark_bn254::Bn254 as Pairing>::ScalarField> {
            a: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
            b: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();

        let c = circuit.a.unwrap() * circuit.b.unwrap();

        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        assert!(groth16_verifier(vec![c], proof, vk));
    }

    #[test]
    fn test_groth16_verifier_evaluate_montgomery_v() {
        let k = 6;
        let mut rng = ChaCha12Rng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit::<<ark_bn254::Bn254 as Pairing>::ScalarField> {
            a: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
            b: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();

        let c = circuit.a.unwrap() * circuit.b.unwrap();

        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        assert!(groth16_verifier(vec![c], proof.clone(), vk.clone()));

        println!("proof is correct in rust");

        let public = Fr::wires_set(c);
        let proof_a = G1Affine::wires_set_montgomery(proof.a);
        let proof_b = G2Affine::wires_set_montgomery(proof.b);
        let proof_c = G1Affine::wires_set_montgomery(proof.c);

        let mut vk_data = Vec::new();
        vk.serialize_compressed(&mut vk_data).unwrap();
        let vk: super::VerifyingKey<ark_bn254::Bn254> =
            super::VerifyingKey::deserialize_compressed(&vk_data[..]).unwrap();

        let (result, gate_count) =
            groth16_verifier_evaluate_montgomery(public.clone(), proof_a.clone(), proof_b.clone(), proof_c.clone(), vk.clone(), false);
        gate_count.print();
        assert!(result.borrow().get_value());

        let circuit = groth16_verifier_montgomery_circuit(
            public, proof_a, proof_b, proof_c, vk, false,
        );
        let circuit_gate_count = circuit.gate_counts();
        assert_eq!(circuit_gate_count.total_gate_count(), gate_count.total_gate_count());
    }

    #[test]
    fn test_groth16_verifier_evaluate_montgomery_with_compressed_proof() {
        let k = 6;
        let mut rng = ChaCha12Rng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit::<<ark_bn254::Bn254 as Pairing>::ScalarField> {
            a: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
            b: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();

        let c = circuit.a.unwrap() * circuit.b.unwrap();

        let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        //assert!(groth16_verifier(vec![c], proof.clone(), vk.clone()));

        println!("proof is correct in rust");

        let public = Fr::wires_set(c);

        let proof_a_y_flag = new_wirex();
        let sy = (proof.a.y.square()).sqrt().unwrap();
        proof_a_y_flag.borrow_mut().set(sy == proof.a.y);

        let proof_b_y_flag = new_wirex();
        let sy = (proof.b.y.square()).sqrt().unwrap();
        proof_b_y_flag.borrow_mut().set(sy == proof.b.y);

        let proof_c_y_flag = new_wirex();
        let sy = (proof.c.y.square()).sqrt().unwrap();
        proof_c_y_flag.borrow_mut().set(sy == proof.c.y);

        let mut proof_a = Fq::wires_set_montgomery(proof.a.x);
        proof_a.push(proof_a_y_flag);
        let mut proof_b = Fq2::wires_set_montgomery(proof.b.x);
        proof_b.push(proof_b_y_flag);
        let mut proof_c = Fq::wires_set_montgomery(proof.c.x);
        proof_c.push(proof_c_y_flag);

        let mut vk_data = Vec::new();
        vk.serialize_compressed(&mut vk_data).unwrap();
        let vk: super::VerifyingKey<ark_bn254::Bn254> =
            super::VerifyingKey::deserialize_compressed(&vk_data[..]).unwrap();

        let (result, gate_count) =
            groth16_verifier_evaluate_montgomery(public, proof_a, proof_b, proof_c, vk, true);
        gate_count.print();
        assert!(result.borrow().get_value());
    }
}
