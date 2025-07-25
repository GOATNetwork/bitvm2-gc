use std::io::Read;
use std::time::Instant;

use ark_ff::fields::Field;
use garbled_snark_verifier::circuits::bigint::utils::biguint_from_wires;
use garbled_snark_verifier::{
    bag::{Circuit, new_wirex},
    circuits::{
        basic::half_adder,
        bigint::{U254, utils::random_biguint_n_bits},
        bn254::{
            fp254impl::Fp254Impl, fq::Fq, fq2::Fq2, g2::G2Affine,
            pairing::deserialize_compressed_g2_circuit,
        },
    },
    core::utils::{SerializableCircuit, check_guest, gen_sub_circuits},
};
use num_bigint::BigUint;
use std::str::FromStr;
use tracing::{info, instrument};

use garbled_snark_verifier::circuits::bigint::utils::biguint_from_bits;
use zkm_sdk::{
    ProverClient, ZKMProofWithPublicValues, ZKMPublicValues, ZKMStdin, include_elf, utils,
};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("verifiable-circuit");

#[instrument]
fn split_circuit() -> Vec<SerializableCircuit> {
    let start_total = Instant::now();

    let start = Instant::now();

    let p = G2Affine::random();
    //use ark_ec::CurveGroup;
    //let p = (p - p).into_affine();
    let y_flag = new_wirex();
    let sy = (p.y.square()).sqrt().unwrap();
    y_flag.borrow_mut().set(sy == p.y);

    let wires = Fq2::wires_set_montgomery(p.x);

    let mut circuit = deserialize_compressed_g2_circuit(wires.clone(), y_flag);

    let elapsed = start.elapsed();
    info!(step = "generate circuit", elapsed = ?elapsed, "finish circuit generation");

    circuit.gate_counts().print();

    let start = Instant::now();
    for gate in &mut circuit.1 {
        gate.evaluate();
    }

    //let x = Fq2::from_montgomery_wires(circuit.0[0..Fq2::N_BITS].to_vec());
    let y = Fq2::from_montgomery_wires(circuit.0[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec());
    assert_eq!(y, p.y);

    /*
    let power = 133;
    let a = random_biguint_n_bits(254);
    let b = random_biguint_n_bits(254);
    let mut circuit = U254::mul_by_constant_modulo_power_two(
        U254::wires_set_from_number(&a),
        b.clone(),
        power,
    );
    let c = &a * &b % BigUint::from_str("2").unwrap().pow(power as u32);
    circuit.gate_counts().print();

    for gate in &mut circuit.1 {
        gate.evaluate();
    }

    let result = biguint_from_bits(
        circuit.0.iter().map(|output_wire| output_wire.borrow().get_value()).collect(),
    );
    assert_eq!(result, c);
    */

    let elapsed = start.elapsed();
    info!(step = "evaluate circuit", elapsed = ?elapsed, "finish circuit evaluation");

    let start = Instant::now();
    let garbled = gen_sub_circuits(&mut circuit, 2_000_000);
    // split the GC into sub-circuits
    info!("garbled:{:?}", garbled.len());
    //garbled.iter().enumerate().for_each(|(i, c)| {
    //    bincode::serialize_into(std::fs::File::create(format!("garbled_{i}.bin")).unwrap(), c)
    //        .unwrap();
    //});
    let elapsed = start.elapsed();
    info!(step = "gen sub-circuits", elapsed = ?elapsed, "finish circuit garbling");

    let total_elapsed = start_total.elapsed();
    info!(elapsed = ?total_elapsed, "total time");

    garbled
}

fn main() {
    // Setup logging.
    utils::setup_logger();

    let start_total = Instant::now();

    let garbled_sub_circuits = split_circuit();

    // The input stream that the guest will read from using `zkm_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the guest.
    let mut stdin = ZKMStdin::new();

    let sc_0 = &garbled_sub_circuits[0];
    let ser_sc_0 = bincode::serialize(sc_0).unwrap();
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

    return;
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
