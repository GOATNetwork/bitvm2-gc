mod mem_fs;
mod utils;

use std::time::Instant;
use ark_bn254::G1Affine;
use ark_ff::UniformRand;
use tracing::info;
use ark_ec::CurveGroup;

use zkm_sdk::{ProverClient, ZKMProofWithPublicValues, ZKMStdin, include_elf, utils as sdk_utils};

use garbled_snark_verifier::dv_bn254::dv_snark::{dv_snark_verifier_bench_circuit};
use garbled_snark_verifier::{bag::Circuit, dv_bn254::dv_ref::VerifierPayloadRef};
use garbled_snark_verifier::core::utils::reset_gid;
use garbled_snark_verifier::dv_bn254::fq::Fq;
use verifiable_circuit_babe::gc::compile_babe_gc;
use crate::utils::{gen_sub_circuits, SUB_CIRCUIT_MAX_GATES, SUB_INPUT_GATES_PARTS};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("garbled-circuit-guest");

fn random_g1_affine() -> G1Affine {
    let mut rng = rand::thread_rng();
    ark_bn254::G1Projective::rand(&mut rng).into_affine()
}

fn custom_babe_garbled_circuit() -> Circuit {

    let pi = random_g1_affine();
    let g = random_g1_affine();

    let witness: Vec<bool> = Fq::to_bits(pi.x)
        .into_iter()
        .chain(Fq::to_bits(pi.y).into_iter())
        .collect();
    info!("gen witness");

    // build circuit
    let start = Instant::now();
    reset_gid();
    let (bld, output_indices) = compile_babe_gc(g);
    let mut circuit = bld.build(&witness);
    let elapsed = start.elapsed();
    info!(step = "Gen circuit", elapsed = ?elapsed);

    let start = Instant::now();
    for gate in &mut circuit.1 {
        gate.evaluate();
    }
    let elapsed = start.elapsed();
    info!(step = "Eval circuit", elapsed = ?elapsed);

    circuit
}

fn split_circuit() {
    let mut circuit = custom_babe_garbled_circuit();
    circuit.gate_counts().print();
    println!("Wires: {}", circuit.0.len());
    gen_sub_circuits(&mut circuit, SUB_CIRCUIT_MAX_GATES, 4);
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

    let mut sub_gates: [Vec<u8>; SUB_INPUT_GATES_PARTS] =
        std::array::from_fn(|_| Vec::new());
    for part in 0..SUB_INPUT_GATES_PARTS {
        sub_gates[part] = mem_fs::MemFile::read(format!("babe_gates_{}.bin", part)).unwrap();
        // sub_gates[part] = std::fs::read(format!("babe_gates_{}.bin", part)).unwrap();
        info!("sub_gates part {} size: {:?} bytes", part, sub_gates[part].len());
    }
    let sub_wires = mem_fs::MemFile::read("babe_wires.bin").unwrap();
    // let sub_wires = std::fs::read("babe_wires.bin").unwrap();
    info!("sub_wires size: {:?} bytes", sub_wires.len());

    let sub_ciphertexts = mem_fs::MemFile::read("babe_ciphertexts.bin").unwrap();
    // let sub_ciphertexts = std::fs::read("babe_ciphertexts.bin").unwrap();
    info!("sub_ciphertexts size: {:?} bytes", sub_ciphertexts.len());

    // Write the read sub-circuit to a file for inspection or later use.
    for part in 0..SUB_INPUT_GATES_PARTS {
        std::fs::write(format!("babe_gates_{}.bin", part), &sub_gates[part])
            .expect("Failed to write sub-gate to babe_gates.bin");
    }
    std::fs::write("babe_wires.bin", &sub_wires)
        .expect("Failed to write sub-wires to babe_wires.bin");
    std::fs::write("babe_ciphertexts.bin", &sub_ciphertexts)
        .expect("Failed to write sub-ciphertexts to babe_ciphertexts.bin");
    info!("Saved sub-circuit to file");

    // info!("Check guest");
    // garbled_snark_verifier::core::utils::check_guest(&ser_sc_0);

    for i in 0..SUB_INPUT_GATES_PARTS {
        stdin.write_vec(sub_gates[i].clone());
    }
    stdin.write_vec(sub_wires);
    stdin.write_vec(sub_ciphertexts);
    // Create a `ProverClient` method.
    let client = ProverClient::new();

    let start = Instant::now();
    // Execute the guest using the `ProverClient.execute` method, without generating a proof.
    let (_public_values, report) = client.execute(ELF, &stdin).run().unwrap();

    let elapsed = start.elapsed();
    info!(elapsed = ?elapsed, "executed program with {} cycles", report.total_instruction_count());

    // let start = Instant::now();
    // // Generate the proof for the given guest and input.
    // let (pk, vk) = client.setup(ELF);
    // let proof = client.prove(&pk, stdin).compressed().run().unwrap();
    //
    // let elapsed = start.elapsed();
    // info!(step = "generated proof", elapsed =? elapsed, "finish proof generation");
    //
    // // Verify proof and public values
    // client.verify(&proof, &vk).expect("verification failed");
    //
    // // Test a round trip of proof serialization and deserialization.
    // proof.save("proof-with-pis.bin").expect("saving proof failed");
    // let deserialized_proof =
    //     ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");
    //
    // // Verify the deserialized proof.
    // client.verify(&deserialized_proof, &vk).expect("verification failed");
    //
    // info!("successfully generated and verified proof for the program!");
    // let total_elapsed = start_total.elapsed();
    // info!(elapsed = ?total_elapsed, "total time");
}