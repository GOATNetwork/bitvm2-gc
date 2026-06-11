use ark_bn254::{Fr, G1Affine};
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use serde::{Deserialize, Serialize};
use crate::babe::WeKnownPi1SetupCt;
use crate::instance::commit::CACInstanceCommit;
use crate::gc::{gc_ciphertexts_commit, SparseAdaptorTable, SGC_PART1_CONSTANT_SIZE};
use garbled_snark_verifier::bag::S;
use rand::Rng;
use rand_chacha::ChaCha12Rng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use garbled_snark_verifier::dv_bn254::fq::Fq;
use crate::instance::CACInstance;
use crate::utils::{deserialize_g1affine, h_256, serialize_g1affine};
use crate::verifier::BATCH_SIZE;

/// What the Verifier sends to the Prover during the C&C commit phase.
#[derive(Clone, Serialize, Deserialize)]
pub struct CACSetupPackage {
    pub commits: Vec<CACInstanceCommit>,
}

/// Derive the finalized instance indices deterministically from the committed values.
/// Note that in practice, prover doesnt need to use this. Instead, he can generate indices
/// using random.
// TODO: fold a session nonce into this hash once Bitcoin transaction integration is complete,
// to prevent replay across protocol runs that share the same CACSetupPackage.
pub fn cac_finalize_indices(package: &CACSetupPackage, m_cc: usize) -> Vec<usize> {
    let n_cc = package.commits.len();
    assert!(m_cc <= n_cc, "m_cc ({m_cc}) must be <= n_cc ({n_cc})");

    let mut hasher = Sha256::new();
    for commit in &package.commits {
        for wire_pair in &commit.epk {
            hasher.update(wire_pair[0]);
            hasher.update(wire_pair[1]);
        }
        for wire_pair in &commit.constant_commits_0 {
            hasher.update(wire_pair[0]);
            hasher.update(wire_pair[1]);
        }
        for wire_pair in &commit.constant_commits_1 {
            hasher.update(wire_pair[0]);
            hasher.update(wire_pair[1]);
        }
        hasher.update(commit.b_blind_commit);
        hasher.update(commit.h_msg);
        hasher.update(commit.h_ct_setup);
        hasher.update(commit.com_adaptor[0]);
        hasher.update(commit.com_adaptor[1]);
        hasher.update(commit.com_gc[0]);
        hasher.update(commit.com_gc[1]);
        hasher.update(commit.com_gc[2]);
    }
    let seed: [u8; 32] = hasher.finalize().into();
    let mut rng = ChaCha12Rng::from_seed(seed);

    let mut seen = std::collections::HashSet::new();
    let mut indices = Vec::with_capacity(m_cc);
    while indices.len() < m_cc {
        let idx = rng.gen_range(0..n_cc);
        if seen.insert(idx) {
            indices.push(idx);
        }
    }
    indices
}

/// GC data the Verifier reveals for each finalized (kept) instance.
#[derive(Serialize, Deserialize)]
pub struct FinalizedInstanceData {
    pub index: usize,
    pub ciphertext_sets: [Vec<Option<S>>; 3],
    pub adaptor_tables: [SparseAdaptorTable; 2],
    pub ct_setup: WeKnownPi1SetupCt,
    /// [0-label of wire-0 (constant false), 1-label of wire-1 (constant true)].
    pub constant_labels_0: [S; 2],
    /// value-based labels. Length must be `SGC_PART1_CONSTANT_SIZE` (510).
    pub constant_labels_1: Vec<S>,
    #[serde(serialize_with = "serialize_g1affine", deserialize_with = "deserialize_g1affine")]
    pub b: G1Affine,
}


pub fn verify_opened_instances(
    package: &CACSetupPackage,
    opened: &[(usize, u64)],
    vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
    static_public_inputs: Fr,
) -> Result<(), String> {
    use p3_maybe_rayon::prelude::*;
    
    let n_cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
    let batch_size = std::env::var("CAC_BATCH_SIZE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(BATCH_SIZE)
        .min(n_cores)
        .min(opened.len().max(1));

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(batch_size)
        .build()
        .map_err(|e| e.to_string())?;

    for batch in opened.chunks(batch_size) {
        // Process up to BATCH_SIZE instances in parallel. commit_from_seed stream-hashes
        // ciphertexts and adaptor tables without materializing them
        let results: Vec<Result<(), String>> = pool.install(|| {
            batch
                .par_iter()
                .map(|&(idx, seed)| {
                    let (recomputed, _secrets) =
                        CACInstance::commit_from_seed(seed, vk, static_public_inputs)?;
                    let committed = &package.commits[idx];

                    if recomputed.epk != committed.epk {
                        return Err(format!("instance {idx}: input_commits mismatch"));
                    }
                    if recomputed.constant_commits_0 != committed.constant_commits_0
                        || recomputed.constant_commits_1 != committed.constant_commits_1
                    {
                        return Err(format!("instance {idx}: constant_commits mismatch"));
                    }
                    if recomputed.b_blind_commit != committed.b_blind_commit {
                        return Err(format!("instance {idx}: b_bind_commit mismatch"));
                    }
                    if recomputed.h_msg != committed.h_msg {
                        return Err(format!("instance {idx}: h_msg mismatch"));
                    }
                    if recomputed.h_ct_setup != committed.h_ct_setup {
                        return Err(format!("instance {idx}: ct_setup mismatch"));
                    }
                    if recomputed.com_adaptor != committed.com_adaptor {
                        return Err(format!("instance {idx}: com_adaptor mismatch"));
                    }
                    if recomputed.com_gc != committed.com_gc {
                        return Err(format!("instance {idx}: com_gc mismatch"));
                    }
                    Ok(())
                })
                .collect()
        });

        for result in results {
            result?;
        }
    }
    Ok(())
}

pub fn verify_finalized_instances(
    package: &CACSetupPackage,
    finalized: &[FinalizedInstanceData],
) -> Result<(), String> {
    for data in finalized {
        let idx = data.index;
        let committed = &package.commits[idx];

        if data.constant_labels_1.len() != SGC_PART1_CONSTANT_SIZE
            || committed.constant_commits_1.len() != SGC_PART1_CONSTANT_SIZE {
            return Err(format!(
                "instance {idx}: constant_labels_1/constant_commits_1 must have length {SGC_PART1_CONSTANT_SIZE}"
            ));
        }

        for i in 0..3 {
            if gc_ciphertexts_commit(&data.ciphertext_sets[i]) != committed.com_gc[i] {
                return Err(format!("instance {idx}: gc_ciphertexts do not match com_gc"));
            }
        }

        if data.adaptor_tables[0].commit() != committed.com_adaptor[0]
            || data.adaptor_tables[1].commit() != committed.com_adaptor[1] {
            return Err(format!("instance {idx}: adaptor_table does not match com_adaptor"));
        }

        // verify constant labels
        if h_256(&data.constant_labels_0[0].0) != committed.constant_commits_0[0][0] ||
            h_256(&data.constant_labels_0[1].0) != committed.constant_commits_0[1][1] ||
            h_256(&data.constant_labels_1[0].0) != committed.constant_commits_1[0][0] ||
            h_256(&data.constant_labels_1[1].0) != committed.constant_commits_1[1][1] {
            return Err(format!("instance {idx}: constant_commits do not match"));
        }
        let x_bits = Fq::to_bits(Fq::as_montgomery(data.b.x));
        let y_bits = Fq::to_bits(Fq::as_montgomery(data.b.y));
        for (i, bit) in x_bits.iter().enumerate() {
            if h_256(&data.constant_labels_1[i + 2].0) != committed.constant_commits_1[i + 2][*bit as usize] {
                return Err(format!("instance {idx}: constant_commits do not match"));
            }
        }
        for (i, bit) in y_bits.iter().enumerate() {
            if h_256(&data.constant_labels_1[i + 2 + 254].0) != committed.constant_commits_1[i + 2 + 254][*bit as usize] {
                return Err(format!("instance {idx}: constant_commits do not match"));
            }
        }

        let mut ct_bytes = Vec::new();
        ct_bytes.extend_from_slice(&data.ct_setup.ct2_r_delta_g2);
        ct_bytes.extend_from_slice(&data.ct_setup.ct3_masked_msg);
        if h_256(&ct_bytes) != committed.h_ct_setup {
            return Err(format!("instance {idx}: ct_setup does not match h_ct_setup"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use rand::SeedableRng;
    use crate::babe::DummyMulCircuit;
    use crate::prover::GROTH_16_SEED;
    use crate::verifier::BABEVerifier;

    const TEST_N_CC: usize = 5;
    const TEST_M_CC: usize = 2;

    #[test]
    fn test_cac_commit_open_verify() {
        let mut rng = ChaCha12Rng::seed_from_u64(GROTH_16_SEED);

        let a = Fr::from(3u64);
        let b = Fr::from(7u64);
        let (_, vk) = ark_groth16::Groth16::<ark_bn254::Bn254>::setup(
            DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) }, &mut rng,
        ).expect("groth16 setup");
        let static_public_inputs = a * b;
        let _dynamic_public_inputs = a * a;

        // Verifier creates TEST_N_CC instances and commits.
        let now = std::time::Instant::now();
        let verifier = BABEVerifier::new(TEST_N_CC, &vk, static_public_inputs)
            .expect("BABEVerifier::new failed");
        let elapsed = now.elapsed();
        println!("Verifier setup for {TEST_N_CC} instances took {elapsed:.2?}");

        let now = std::time::Instant::now();
        let package = verifier.commit();
        assert_eq!(package.commits.len(), TEST_N_CC);
        let elapsed = now.elapsed();
        println!("Verifier commit for {TEST_N_CC} instances took {elapsed:.2?}");

        // Replaced by random in practice
        let finalized_indices = cac_finalize_indices(&package, TEST_M_CC);

        // Verifier opens: seeds for the rest, GC data for finalized.
        let now = std::time::Instant::now();
        let (opened, finalized) = verifier.open(&finalized_indices).expect("verifier open failed");
        assert_eq!(opened.len(), TEST_N_CC - TEST_M_CC);
        assert_eq!(finalized.len(), TEST_M_CC);
        let elapsed = now.elapsed();
        println!("Verifier open for {TEST_N_CC} instances (finalizing {TEST_M_CC}) took {elapsed:.2?}");

        let now = std::time::Instant::now();
        // Prover verifies opened instances by re-deriving from seed.
        verify_opened_instances(&package, &opened, &vk, static_public_inputs)
            .expect("opened instance verification failed");
        let elapsed = now.elapsed();
        println!("Prover verification of opened instances took {elapsed:.2?}");

        // Prover verifies finalized instances via com_gc / com_adaptor.
        let now = std::time::Instant::now();
        verify_finalized_instances(&package, &finalized)
            .expect("finalized instance verification failed");
        let elapsed = now.elapsed();
        println!("Prover verification of finalized instances took {elapsed:.2?}");
    }
}
