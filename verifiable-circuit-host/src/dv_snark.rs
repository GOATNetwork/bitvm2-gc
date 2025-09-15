use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::time::Instant;
use tracing::info;

use zkm_sdk::{ProverClient, ZKMProofWithPublicValues, ZKMStdin, include_elf, utils as sdk_utils};

use garbled_snark_verifier::circuits::dv_snark::dv_snark_verifier_circuit;
use garbled_snark_verifier::{
    bag::{Circuit, new_wirex},
    circuits::sect233k1::types::load_witness_from_files,
    core::utils::{SerializableCircuit, SerializableGate},
};

mod mem_fs;
mod utils;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("verifiable-circuit");

fn custom_dv_snark_circuit() -> Circuit {
    //read witness from files
    let witness = load_witness_from_files(
        "src/data/dv-proof",
        "src/data/public_inputs.bin",
        "src/data/trapdoor.bin",
    );

    let start = Instant::now();
    let mut circuit = dv_snark_verifier_circuit(&witness);
    let elapsed = start.elapsed();
    info!(step = "Gen circuit", elapsed = ?elapsed);

    let start = Instant::now();
    for gate in &mut circuit.1 {
        gate.evaluate();
    }
    assert!(circuit.0[0].borrow().get_value());

    let elapsed = start.elapsed();
    info!(step = "Eval circuit", elapsed = ?elapsed);

    circuit
}

fn split_circuit() {
    let mut circuit = custom_dv_snark_circuit();
    circuit.gate_counts().print();
    println!("Wires: {}", circuit.0.len());
    utils::gen_sub_circuits(&mut circuit, 1_000_000);
}

fn main() {
    // Setup logging.
    sdk_utils::setup_logger();

    let start_total = Instant::now();

    let start = Instant::now();
    split_circuit();
    let elapsed = start.elapsed();
    info!(elapsed = ?elapsed, "split circuit");

    // The input stream that the guest will read from using `zkm_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the guest.
    let mut stdin = ZKMStdin::new();

    //let ser_sc_0 = std::fs::read("garbled_0.bin").unwrap();
    let ser_sc_0 = mem_fs::MemFile::read("garbled_0.bin").unwrap();
    info!("ser_sc_0 size: {:?} bytes", ser_sc_0.len());

    // Write the read sub-circuit to a file for inspection or later use.
    std::fs::write("garbled_0.bin", &ser_sc_0)
        .expect("Failed to write sub-circuit to garbled_0.bin");
    info!("Saved sub-circuit to garbled_0.bin");

    // info!("Check guest");
    // check_guest(&ser_sc_0);

    stdin.write_vec(ser_sc_0);
    // Create a `ProverClient` method.
    let client = ProverClient::new();

    let start = Instant::now();
    // Execute the guest using the `ProverClient.execute` method, without generating a proof.
    let (_public_values, report) = client.execute(ELF, stdin.clone()).run().unwrap();

    let elapsed = start.elapsed();
    info!(elapsed = ?elapsed, "executed program with {} cycles", report.total_instruction_count());

    let start = Instant::now();
    // Generate the proof for the given guest and input.
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).compressed().run().unwrap();

    let elapsed = start.elapsed();
    info!(step = "generated proof", elapsed =? elapsed, "finish proof generation");

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client.verify(&deserialized_proof, &vk).expect("verification failed");

    info!("successfully generated and verified proof for the program!");
    let total_elapsed = start_total.elapsed();
    info!(elapsed = ?total_elapsed, "total time");
}
