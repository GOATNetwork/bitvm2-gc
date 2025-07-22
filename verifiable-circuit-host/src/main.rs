use std::io::Read;

use garbled_snark_verifier::{
    bag::Circuit, circuits::bn254::{fp254impl::Fp254Impl, fq::Fq}, core::utils::{check_guest, gen_sub_circuits, SerializableCircuit}
};
use zkm_sdk::{include_elf, utils, ProverClient, ZKMProofWithPublicValues, ZKMPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("verifiable-circuit");

fn split_circuit() {
    let a = Fq::random();
    let mut circuit = Fq::div6(Fq::wires_set(a));
    circuit.gate_counts().print();
    for gate in &mut circuit.1 {
        gate.evaluate();
    }

    let c = Fq::from_wires(circuit.0.clone());
    assert_eq!(c + c + c + c + c + c, a);

    let garbled = gen_sub_circuits(&mut circuit, 1);
    // split the GC into sub-circuits
    println!("garbled:{:?}", garbled.len());
    garbled.iter().enumerate().for_each(|(i, c)| {
        if i > 0 {
            return;
        } 
        bincode::serialize_into(std::fs::File::create(format!("garbled_{i}.bin")).unwrap(), c)
            .unwrap();
    });
}

fn main() {
    // Setup logging.
    utils::setup_logger();

    split_circuit();

    // The input stream that the guest will read from using `zkm_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the guest.
    let mut stdin = ZKMStdin::new();
    // TODO: load the corresponding gabled file
    let mut file = std::fs::File::open("garbled_0.bin").unwrap();
    let mut buf = Vec::new();
    let sz = file.read_to_end(&mut buf).unwrap();

    println!("check guest");
    check_guest(&buf);

    println!("file size: {}", sz);
    stdin.write_vec(buf);
    // Create a `ProverClient` method.
    let client = ProverClient::new();

    // Execute the guest using the `ProverClient.execute` method, without generating a proof.
    let (mut public_values, report) = client.execute(ELF, stdin.clone()).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    // Note that this output is read from values committed to in the guest using
    // `zkm_zkvm::io::commit`.
    let gates = public_values.read::<u32>();
    println!("gates: {}", gates);
    let gb0 = public_values.read::<[u8; 32]>();
    println!("gates: {:?}", gb0);
    let gb0_ = public_values.read::<[u8; 32]>();
    println!("gates: {:?}", gb0_);
    return;

    // Generate the proof for the given guest and input.
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).run().unwrap();

    println!("generated proof");

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
