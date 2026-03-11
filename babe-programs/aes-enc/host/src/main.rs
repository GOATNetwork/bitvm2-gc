use zkm_sdk::{include_elf, utils, ProverClient, ZKMStdin};
use garbled_snark_verifier::bag::S;

const ELF: &[u8] = include_elf!("aes-guest");

fn main() {
    utils::setup_logger();
    let stdin = ZKMStdin::new();

    // Create a `ProverClient` method.
    let client = ProverClient::new();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (mut pub_val, report) = client.execute(ELF, &stdin).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());
    // Read and verify the output.
    //
    // Note that this output is read from values committed to in the program using
    // `zkm_zkvm::io::commit`.
    let public_input = pub_val.read::<[u8; 32]>();
    println!("public input: {:?}", public_input);

    // // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).run().unwrap();
    println!("generated proof");

    let tmp = ark_bn254::Fq::from(20_u64);
    let key = &[0u8; 16];
    let out = verifiable_circuit_babe::gc::utils::aes_enc(&tmp, &key);
    println!("expected output: {:?}", out);
}
