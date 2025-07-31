#![allow(dead_code)]
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use ark_ff::fields::Field;
use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{UniformRand, test_rng};
use garbled_snark_verifier::{
    bag::{Circuit, new_wirex},
    circuits::bn254::{fq2::Fq2, g2::G2Affine, pairing::deserialize_compressed_g2_circuit},
    core::utils::{SerializableCircuit, SerializableGate},
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::time::Instant;
use tracing::info;

use garbled_snark_verifier::circuits::bn254::fr::Fr;
use garbled_snark_verifier::circuits::bn254::g1::G1Affine;
use garbled_snark_verifier::circuits::groth16::{
    VerifyingKey, groth16_verifier_montgomery_circuit,
};
use zkm_sdk::{ProverClient, ZKMProofWithPublicValues, ZKMStdin, include_elf, utils};

mod dummy_circuit;
use crate::dummy_circuit::DummyCircuit;
mod mem_fs;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("verifiable-circuit");

fn custom_groth16_verifier_circuit() -> Circuit {
    let k = 6;
    let mut rng = ChaCha12Rng::seed_from_u64(test_rng().next_u64());
    let circuit = DummyCircuit::<<ark_bn254::Bn254 as Pairing>::ScalarField> {
        a: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
        b: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };
    let mut rng = ChaCha12Rng::seed_from_u64(test_rng().next_u64());
    let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
    let c = circuit.a.unwrap() * circuit.b.unwrap();
    let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

    let public = Fr::wires_set(c);
    let proof_a = G1Affine::wires_set_montgomery(proof.a);
    let proof_b = G2Affine::wires_set_montgomery(proof.b);
    let proof_c = G1Affine::wires_set_montgomery(proof.c);

    let mut vk_data = Vec::new();
    vk.serialize_compressed(&mut vk_data).unwrap();
    let vk: VerifyingKey<ark_bn254::Bn254> =
        VerifyingKey::deserialize_compressed(&vk_data[..]).unwrap();
    let start = Instant::now();
    let mut circuit =
        groth16_verifier_montgomery_circuit(public, proof_a, proof_b, proof_c, vk, false);
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

fn custom_deserialize_compressed_g2_circuit() -> Circuit {
    let p = G2Affine::random();
    let y_flag = new_wirex();
    let sy = (p.y.square()).sqrt().unwrap();
    y_flag.borrow_mut().set(sy == p.y);

    let wires = Fq2::wires_set_montgomery(p.x);
    let mut circuit = deserialize_compressed_g2_circuit(wires.clone(), y_flag);
    for gate in &mut circuit.1 {
        gate.evaluate();
    }

    //let x = Fq2::from_montgomery_wires(circuit.0[0..Fq2::N_BITS].to_vec());
    let y = Fq2::from_montgomery_wires(circuit.0[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec());
    assert_eq!(y, p.y);
    circuit
}

fn gen_sub_circuits(circuit: &mut Circuit, max_gates: usize) {
    let start = Instant::now();
    let mut garbled_gates = circuit.garbled_gates();
    let elapsed = start.elapsed();
    info!(step = "garble gates", elapsed =? elapsed, "garbled gates: {}", garbled_gates.len());

    let size = circuit.1.len().div_ceil(max_gates);

    let start = Instant::now();
    let _: Vec<_> = circuit
        .1
        .chunks(max_gates)
        .enumerate()
        .zip(garbled_gates.chunks_mut(max_gates))
        .map(|((i, w), garblings)| {
            info!(step = "gen_sub_circuits", "Split batch {i}/{size}");
            let out = SerializableCircuit {
                gates: w
                    .iter()
                    .map(|w| SerializableGate {
                        wire_a: w.wire_a.borrow().clone(),
                        wire_b: w.wire_b.borrow().clone(),
                        wire_c: w.wire_c.borrow().clone(),
                        gate_type: w.gate_type,
                        gid: w.gid,
                    })
                    .collect(),
                garblings: garblings.to_vec(),
            };
            let start = Instant::now();
            bincode::serialize_into(
                //std::fs::File::create(format!("garbled_{i}.bin")).unwrap(),
                mem_fs::MemFile::create(format!("garbled_{i}.bin")).unwrap(),
                &out,
            )
            .unwrap();
            let elapsed = start.elapsed();
            info!(step = "gen_sub_circuits", elapsed = ?elapsed, "Writing garbled_{i}.bin");
        })
        .collect();
    let elapsed = start.elapsed();
    info!(step = "gen_sub_circuits", elapsed =? elapsed, "total time");
}

fn split_circuit() {
    let mut circuit = custom_groth16_verifier_circuit();
    circuit.gate_counts().print();
    println!("Wires: {}", circuit.0.len());
    gen_sub_circuits(&mut circuit, 7_000_000);
}

fn main() {
    // Setup logging.
    utils::setup_logger();

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

    // Note that this output is read from values committed to in the guest using
    // `zkm_zkvm::io::commit`.
    // let gates = public_values.read::<u32>();
    // println!("gates: {}", gates);
    // let gb0 = public_values.read::<[u8; 32]>();
    // println!("gates: {:?}", gb0);
    // let gb0_ = public_values.read::<[u8; 32]>();
    // println!("gates: {:?}", gb0_);

    let start = Instant::now();
    // Generate the proof for the given guest and input.
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).run().unwrap();

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
