use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use tracing::info;
use zkm_sdk::{include_elf, utils as sdk_utils, ProverClient, ZKMStdin};
use verifiable_circuit_babe::prover::BABEProver;
use verifiable_circuit_babe::soldering::{
    build_soldered_wires_input, SolderedLabelsData, SolderedWiresInput,
};
use verifiable_circuit_babe::verifier::BABEVerifier;

const ELF: &[u8] = include_elf!("soldering-guest");

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
    let (_, vk) =
        Groth16::<Bn254>::setup(TrivialCircuit, &mut rng).unwrap();
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

    //  3. Build SolderedWiresInput from finalized instances
    let start = Instant::now();
    let soldering_input = build_soldered_wires_input(&verifier, &finalized_indices);
    info!(elapsed = ?start.elapsed(), "SolderedWiresInput built");

    //  4. Feed input to zkVM guest 
    let mut stdin = ZKMStdin::new();
    stdin.write::<SolderedWiresInput>(&soldering_input);

    let client = ProverClient::new();

    let start = Instant::now();
    let (mut pub_val, report) = client.execute(ELF, &stdin).run().unwrap();
    info!(
        elapsed = ?start.elapsed(),
        cycles = report.total_instruction_count(),
        "guest executed"
    );

    let output = pub_val.read::<SolderedLabelsData>();

    //  5. Verify output matches CACSetupPackage commitments
    BABEProver::verify_soldering_output_match_commitment(&output, &package, &finalized_indices)
        .expect("soldering output verification failed");
    info!("commitment verification passed");

    //  6. Generate ZK proof 
    let start = Instant::now();
    let (pk, vk_proof) = client.setup(ELF);
    let proof = client.prove(&pk, stdin).compressed().run().unwrap();
    client.verify(&proof, &vk_proof).expect("proof verification failed");
    info!(elapsed = ?start.elapsed(), "soldering proof generated and verified");
}
