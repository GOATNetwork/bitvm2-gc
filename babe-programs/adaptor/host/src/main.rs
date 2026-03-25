use ark_bn254::{Fq, Fr, G1Affine};
use ark_ff::{UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use garbled_snark_verifier::core::s::S;
use garbled_snark_verifier::core::utils::NON_CAC_DELTA;
use rand::thread_rng;
use sha2::{Digest, Sha256};
use zkm_sdk::{include_elf, utils, ProverClient, ZKMStdin};

use verifiable_circuit_babe::dre::{L, N};
use verifiable_circuit_babe::dre::utils::sample_rhos;
use verifiable_circuit_babe::gc::SparseAdaptorTable;

const ELF: &[u8] = include_elf!("adaptor-guest");

fn fq_to_bytes(fq: &Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    fq.serialize_uncompressed(&mut out[..]).unwrap();
    out
}

fn g1affine_to_bytes(pt: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&fq_to_bytes(&pt.x));
    out[32..].copy_from_slice(&fq_to_bytes(&pt.y));
    out
}

fn main() {
    utils::setup_logger();
    let mut rng = thread_rng();

    // ── 1. Sample inputs ─────────────────────────────────────────────────────

    let r = Fr::rand(&mut rng);

    let labels: Vec<[u8; 16]> = (0..L)
        .flat_map(|_| {
            let l0 = S::random();
            let l1 = l0 ^ NON_CAC_DELTA;
            [l0.0, l1.0]
        })
        .collect();

    let rhos: Vec<G1Affine> = sample_rhos(&mut rng);

    let deltas: Vec<Fq> = (0..N)
        .map(|_| loop {
            let d = Fq::rand(&mut rng);
            if !d.is_zero() { break d; }
        })
        .collect();

    // ── 2. Serialize inputs for ZKMStdin ─────────────────────────────────────

    let r_bits: Vec<u8> = garbled_snark_verifier::dv_bn254::fr::Fr::to_bits(r)
        .iter()
        .map(|&b| b as u8)
        .collect();

    let rhos_flat: Vec<u8> = rhos.iter().flat_map(|p| g1affine_to_bytes(p)).collect();

    let deltas_raw: Vec<[u8; 32]> = deltas.iter().map(|d| fq_to_bytes(d)).collect();

    let mut stdin = ZKMStdin::new();
    stdin.write::<Vec<[u8; 16]>>(&labels);
    stdin.write::<Vec<u8>>(&r_bits);
    stdin.write::<Vec<u8>>(&rhos_flat);
    stdin.write::<Vec<[u8; 32]>>(&deltas_raw);

    // ── 3. Compute expected commitments on the host ───────────────────────────

    let expected_r_hash: [u8; 32] = Sha256::digest(&r_bits[..]).into();

    let mut lh = Sha256::new();
    for b in &labels { lh.update(b); }
    let expected_labels_hash: [u8; 32] = lh.finalize().into();

    let table = SparseAdaptorTable::build_in_zkvm(&labels, &r_bits, &rhos, &deltas);
    let mut th = Sha256::new();
    for entry in &table.entries {
        for ct in &entry.x.cts { th.update(ct); }
        for ct in &entry.y.cts { th.update(ct); }
        for ct in &entry.z.cts { th.update(ct); }
    }
    let expected_table_hash: [u8; 32] = th.finalize().into();

    // ── 4. Execute guest and verify outputs match ─────────────────────────────

    let client = ProverClient::new();
    let (mut pub_val, report) = client.execute(ELF, &stdin).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    let r_commit    = pub_val.read::<[u8; 32]>();
    let labels_hash = pub_val.read::<[u8; 32]>();
    let table_hash  = pub_val.read::<[u8; 32]>();

    assert_eq!(r_commit,    expected_r_hash,      "r commitment mismatch");
    assert_eq!(labels_hash, expected_labels_hash,  "labels hash mismatch");
    assert_eq!(table_hash,  expected_table_hash,   "table hash mismatch");

    println!("r SHA-256:      {}", hex::encode(r_commit));
    println!("labels SHA-256: {}", hex::encode(labels_hash));
    println!("table  SHA-256: {}", hex::encode(table_hash));
    println!("all commitments verified ✓");

    // ── 5. Generate proof ─────────────────────────────────────────────────────

    // let (pk, vk) = client.setup(ELF);
    // let mut proof = client.prove(&pk, stdin).run().unwrap();
    // client.verify(&proof, &vk).expect("proof verification failed");
    // println!("proof verified");
}