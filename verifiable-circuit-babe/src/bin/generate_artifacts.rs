/// One-time binary to compile, compact, and write the garbled circuit artifacts.
///
/// Produces 8 artifact files:
///   fgc_gates.bin + fgc_out_indices.bin             (FGC original — for read_flat_original_gc)
///   fgc_compact_gates.bin + fgc_compact_out_indices.bin  (FGC compact — for read_compact_gc)
///   sgc_gates.bin + sgc_out_indices.bin             (SGC original — for read_flat_original_gc)
///   sgc_compact_gates.bin + sgc_compact_out_indices.bin  (SGC compact — for read_compact_gc)
///
/// Output paths are controlled by env vars (defaults shown):
///   FGC_GATES_PATH=./fgc_gates.bin
///   FGC_OUT_INDICES_PATH=./fgc_out_indices.bin
///   FGC_COMPACT_GATES_PATH=./fgc_compact_gates.bin
///   FGC_COMPACT_OUT_INDICES_PATH=./fgc_compact_out_indices.bin
///   SGC_GATES_PATH=./sgc_gates.bin
///   SGC_OUT_INDICES_PATH=./sgc_out_indices.bin
///   SGC_COMPACT_GATES_PATH=./sgc_compact_gates.bin
///   SGC_COMPACT_OUT_INDICES_PATH=./sgc_compact_out_indices.bin
///
/// Run with:
///   cargo run --release --bin generate_artifacts
use ark_bn254::Fr;
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use rand::SeedableRng;
use verifiable_circuit_babe::babe::DummyMulCircuit;
use verifiable_circuit_babe::gc::generate_compact_artifacts;
use verifiable_circuit_babe::prover::GROTH_16_SEED;

// Todo: in practice, the vk should be generated differently / read from file.
fn main() {
    // Use the same VK as all tests so the artifacts are compatible.
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(GROTH_16_SEED);
    let a = Fr::from(3u64);
    let b = Fr::from(7u64);

    println!("Setting up Groth16 VK (seed={GROTH_16_SEED})...");
    let (_pk, vk) = ark_groth16::Groth16::<ark_bn254::Bn254>::setup(
        DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) },
        &mut rng,
    ).expect("groth16 setup");
    
    let l2_point = vk.gamma_abc_g1[2];

    generate_compact_artifacts(l2_point);
}
