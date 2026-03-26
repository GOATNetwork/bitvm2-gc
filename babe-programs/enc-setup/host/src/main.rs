// Host program: prepares enc_setup inputs, executes the guest inside the ZKM,
// and verifies the committed outputs match the natively computed values.
//
// Circuit being proved: enc_setup of the BABE verifier.
//   ct2 = r · [delta]_2
//   rY  = e(alpha_g1, r·beta_g2) + e(vk_x, r·gamma_g2)
//   ct3 = blake3(rY) ⊕ msg
//
// Public outputs (committed by guest):
//   ct2_bytes, ct3, h_msg, h_vk, h_public_inputs

use std::time::Instant;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::Groth16;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tracing::info;
use zkm_sdk::{include_elf, utils as sdk_utils, ProverClient, ZKMStdin};
use verifiable_circuit_babe::babe::DummyMulCircuit;

const ELF: &[u8] = include_elf!("enc-setup-guest");

// ── Serialization helpers (raw LE bytes, matching guest deserialization) ──────

/// Serialize Fq as 32 LE bytes.
fn fq_to_le(fq: &Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    fq.serialize_uncompressed(&mut out[..]).unwrap();
    out
}

/// Serialize Fr as 32 LE bytes.
fn fr_to_le(fr: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    fr.serialize_uncompressed(&mut out[..]).unwrap();
    out
}

/// Serialize G1Affine as 64 raw LE bytes: x‖y.
fn g1_to_bytes(pt: &G1Affine) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&fq_to_le(&pt.x));
    out.extend_from_slice(&fq_to_le(&pt.y));
    out
}

/// Serialize G2Affine as 128 raw LE bytes: x.c0‖x.c1‖y.c0‖y.c1.
fn g2_to_bytes(pt: &G2Affine) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&fq_to_le(&pt.x.c0));
    out.extend_from_slice(&fq_to_le(&pt.x.c1));
    out.extend_from_slice(&fq_to_le(&pt.y.c0));
    out.extend_from_slice(&fq_to_le(&pt.y.c1));
    out
}

// ── Native enc_setup computation (for expected-value verification) ────────────

fn compute_enc_setup(
    vk: &ark_groth16::VerifyingKey<Bn254>,
    public_inputs: &[Fr],
    r: Fr,
    msg: &[u8; 32],
) -> (Vec<u8>, [u8; 32]) {
    // vk_x = gamma_abc_g1[0] + Σ gamma_abc_g1[i+1] · public_inputs[i]
    let mut vk_x = vk.gamma_abc_g1[0].into_group();
    for (i, inp) in public_inputs.iter().enumerate() {
        vk_x += vk.gamma_abc_g1[i + 1].into_group() * *inp;
    }

    // ct2 = r · delta_g2 (compressed G2 bytes)
    let r_delta = (vk.delta_g2.into_group() * r).into_affine();
    let mut ct2_bytes = Vec::new();
    r_delta.serialize_compressed(&mut ct2_bytes).unwrap();

    // rY = e(alpha_g1, r·beta_g2) + e(vk_x, r·gamma_g2)
    let r_beta  = (vk.beta_g2.into_group()  * r).into_affine();
    let r_gamma = (vk.gamma_g2.into_group() * r).into_affine();
    let t1 = Bn254::pairing(vk.alpha_g1, r_beta);
    let t2 = Bn254::pairing(vk_x.into_affine(), r_gamma);
    let r_y = t1 + t2;

    // ct3 = blake3(rY) ⊕ msg
    let mut ry_bytes = Vec::new();
    r_y.serialize_compressed(&mut ry_bytes).unwrap();
    let mask = verifiable_circuit_babe::babe::h(&ry_bytes);
    let ct3: [u8; 32] = core::array::from_fn(|i| msg[i] ^ mask[i]);

    (ct2_bytes, ct3)
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    sdk_utils::setup_logger();
    let mut rng = rand::thread_rng();

    // ── 1. Groth16 setup: a × b = c ──────────────────────────────────────────
    let start = Instant::now();
    let a = Fr::from(3u64);
    let b = Fr::from(7u64);
    let (_, vk) = Groth16::<Bn254>::setup(
        DummyMulCircuit { a: Some(a), b: Some(b) },
        &mut rng,
    )
    .expect("groth16 setup");
    let public_inputs = vec![a * b]; // c = 21
    info!(elapsed = ?start.elapsed(), "Groth16 setup");

    // ── 2. Sample private witnesses ───────────────────────────────────────────
    let r = Fr::rand(&mut rng);
    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);

    // ── 3. Native enc_setup (reference values for post-execution check) ───────
    let start = Instant::now();
    let (expected_ct2, expected_ct3) = compute_enc_setup(&vk, &public_inputs, r, &msg);
    let expected_h_msg: [u8; 32] = Sha256::digest(&msg).into();
    info!(elapsed = ?start.elapsed(), "enc_setup computed natively");

    // ── 4. Serialize VK components as flat byte vectors ───────────────────────
    let r_bytes      = fr_to_le(&r);
    let alpha_g1_raw = g1_to_bytes(&vk.alpha_g1);
    let beta_g2_raw  = g2_to_bytes(&vk.beta_g2);
    let gamma_g2_raw = g2_to_bytes(&vk.gamma_g2);
    let delta_g2_raw = g2_to_bytes(&vk.delta_g2);

    // gamma_abc_g1: flat array of (n+1) × 64 bytes
    let gamma_abc_raw: Vec<u8> = vk.gamma_abc_g1
        .iter()
        .flat_map(|pt| g1_to_bytes(pt))
        .collect();

    // public inputs: flat array of n × 32 bytes
    let public_inputs_raw: Vec<u8> = public_inputs
        .iter()
        .flat_map(|fr| fr_to_le(fr))
        .collect();

    // ── 5. Compute expected commitments ───────────────────────────────────────
    let mut vk_hasher = Sha256::new();
    vk_hasher.update(&alpha_g1_raw);
    vk_hasher.update(&beta_g2_raw);
    vk_hasher.update(&gamma_g2_raw);
    vk_hasher.update(&delta_g2_raw);
    vk_hasher.update(&gamma_abc_raw);
    let expected_h_vk: [u8; 32] = vk_hasher.finalize().into();

    let expected_h_public_inputs: [u8; 32] = Sha256::digest(&public_inputs_raw).into();

    // ── 6. Write inputs to ZKMStdin ───────────────────────────────────────────
    let mut stdin = ZKMStdin::new();

    // private witnesses
    stdin.write::<[u8; 32]>(&r_bytes);
    stdin.write::<[u8; 32]>(&msg);

    // VK components (as flat Vec<u8>)
    stdin.write_vec(alpha_g1_raw);
    stdin.write_vec(beta_g2_raw);
    stdin.write_vec(gamma_g2_raw);
    stdin.write_vec(delta_g2_raw);
    stdin.write_vec(gamma_abc_raw);

    // public inputs
    stdin.write_vec(public_inputs_raw);

    // ── 7. Execute guest ──────────────────────────────────────────────────────
    let client = ProverClient::new();
    let start = Instant::now();
    let (mut pub_val, report) = client.execute(ELF, &stdin).run().unwrap();
    info!(
        elapsed = ?start.elapsed(),
        cycles = report.total_instruction_count(),
        "guest executed"
    );

    // ── 8. Read and verify committed outputs ──────────────────────────────────
    let ct2_out   = pub_val.read::<Vec<u8>>();
    let ct3_out   = pub_val.read::<[u8; 32]>();
    let h_msg_out = pub_val.read::<[u8; 32]>();
    let h_vk_out  = pub_val.read::<[u8; 32]>();
    let h_pi_out  = pub_val.read::<[u8; 32]>();

    assert_eq!(ct2_out,   expected_ct2,             "ct2 mismatch");
    assert_eq!(ct3_out,   expected_ct3,             "ct3 mismatch");
    assert_eq!(h_msg_out, expected_h_msg,           "h_msg mismatch");
    assert_eq!(h_vk_out,  expected_h_vk,            "h_vk mismatch");
    assert_eq!(h_pi_out,  expected_h_public_inputs, "h_public_inputs mismatch");

    println!("ct2:             {}", hex::encode(&ct2_out));
    println!("ct3:             {}", hex::encode(ct3_out));
    println!("h_msg:           {}", hex::encode(h_msg_out));
    println!("h_vk:            {}", hex::encode(h_vk_out));
    println!("h_public_inputs: {}", hex::encode(h_pi_out));
    println!("all enc_setup outputs verified ✓");

    // ── 9. (Optional) Generate ZK proof ──────────────────────────────────────
    // let (pk, vk_proof) = client.setup(ELF);
    // let proof = client.prove(&pk, stdin).compressed().run().unwrap();
    // client.verify(&proof, &vk_proof).expect("proof verification failed");
    // proof.save("proof.bin").expect("saving proof failed");
    // println!("proof verified ✓");
}
