use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use soldering_host::BabeBundleBuilder;
use tracing::info;
use verifiable_circuit_babe::verifier::BABEVerifier;
use zkm_sdk::utils as sdk_utils;

const N_CC: usize = 4; // Number of C&C instances.

#[derive(Clone)]
struct TrivialCircuit;

impl ConstraintSynthesizer<Fr> for TrivialCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        cs.new_input_variable(|| Ok(Fr::from(1u64)))?;
        Ok(())
    }
}

fn setup_vk() -> (ark_groth16::VerifyingKey<Bn254>, Vec<Fr>) {
    let mut rng = rand::thread_rng();
    let (_, vk) = Groth16::<Bn254>::setup(TrivialCircuit, &mut rng).unwrap();
    (vk, vec![Fr::from(1u64)])
}

fn main() {
    sdk_utils::setup_logger();

    //  1. Setup VK and create N_CC instances
    let start = Instant::now();
    let (vk, public_inputs) = setup_vk();
    info!(elapsed = ?start.elapsed(), "VK setup done");

    let start = Instant::now();
    let verifier = BABEVerifier::new(N_CC, &vk, &public_inputs).expect("verifier setup failed");
    info!(elapsed = ?start.elapsed(), n_cc = N_CC, "BABEVerifier created");

    //  2. C&C commit and derive finalized indices
    let package = verifier.commit();
    let finalized_indices = vec![0, 1, 2, 3];

    //  3. Generate and verify soldering proof through the reusable host API.
    let start = Instant::now();
    let builder = BabeBundleBuilder::new();
    let bundle = builder
        .babe_verifier_open_and_solder(&verifier, &finalized_indices)
        .expect("open and solder failed");
    builder
        .babe_prover_verify_setup(&package, &bundle, &vk, &public_inputs)
        .expect("setup verification failed");
    info!(elapsed = ?start.elapsed(), "soldering proof generated and verified");
}
