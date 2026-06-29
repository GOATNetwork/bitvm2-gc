use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Proof as Groth16Proof, VerifyingKey as Groth16VerifyingKey};

use ark_serialize::CanonicalSerialize;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use serde::{Deserialize, Serialize};
use ark_ec::pairing::Pairing;
use garbled_snark_verifier::bag::S;
use crate::cac::{
    CACSetupPackage, FinalizedInstanceData,
};

use crate::wots::{wots96_verify, Wots96, Wots96PublicKey, Wots96Secret};
use crate::utils::pi1_xd_to_wots96_msg;
use bitvm::signatures::Wots;
use crate::dre::N;
use crate::prover::BABEProver;
use crate::soldering::SolderingData;
use crate::transactions::{ChallengeAssertWitnessRaw, TxAssertWitness, TxChallengeAssertOutputLock, TxChallengeAssertWitness, TxDepositLock, TxWronglyChallengedWitness};
pub use crate::utils::{derive_hashlock, g1_from_ser_checked, g1_project_to_ser, g2_from_ser_checked, g2_project_to_ser, groth16_vk_x, h_256, ro_from_pairing_bytes};
use crate::verifier::BABEVerifier;

// ─── Constants ────────────────────────────────────────────────────────────────
/// Total number of C&C instances the Verifier creates and commits to.
/// In practice, N_CC = 181.
pub const N_CC: usize = 4;

/// Number of instances the Prover finalizes (keeps hidden); rest are opened.
/// In practice, M_CC = 7.
pub const M_CC: usize = 2;

/// Number of real GC input wires: pi1.x + pi1.y + x_d, each `dre::N` bits.
pub const GC_INPUT_WIRES: usize = 3 * N;

/// `GC_INPUT_WIRES` padded with 6 dummy wires (2 after each `dre::N`-bit group).
pub const PADDED_INPUT_WIRES: usize = GC_INPUT_WIRES + 6;

/// Byte size of a Bitcoin signature placeholder (64 bytes in production).
pub const BTC_SIG_BYTES: usize = 32;

/// Byte size of the secret message.
pub const MSG_BYTES: usize = 32;

// ─── Bitcoin key stubs ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcPk(pub [u8; 33]);

/// Named Bitcoin signature placeholders (64-byte Schnorr in production).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BabeBtcSig {
    ProverPresigChallengeAssert,
    ProverPresigNoWithdraw,
    VerifierPresigAssert,
    VerifierPresigWithdraw,
    ProverLiveSig,
    VerifierLiveSig,
}

// ─── Encoding Key Public ──────────────────────────────────────────────────────

/// epk[i][b] = sha256(label_i_b), for i in 0..LAMPORT_N, b ∈ {0, 1}.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodingKeyPublic(pub Vec<[[u8; 20]; 2]>);

pub fn compute_epk_with_delta(encoding_keys: &[S], delta: S) -> EncodingKeyPublic {
    let pairs = encoding_keys
        .iter()
        .map(|&key| [derive_hashlock(&key.0), derive_hashlock(&(key ^ delta).0)])
        .collect();
    EncodingKeyPublic(pairs)
}

// ─── Presig structs ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProverPresigs {
    pub sig_challenge_assert: BabeBtcSig,
    pub sig_no_withdraw: BabeBtcSig,
}

#[derive(Debug, Clone)]
pub struct VerifierPresigs {
    pub sig_assert: BabeBtcSig,
    pub sig_withdraw: BabeBtcSig,
}

// ─── WE ciphertext types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeKnownPi1SetupCt {
    pub ct2_r_delta_g2: Vec<u8>,
    pub ct3_masked_msg: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeKnownPi1ProveCt {
    pub ct1_r_pi1: Vec<u8>,
    pub ct1_prime: Vec<u8>, // r * Q
}

// ─── Setup state ─────────────────────────────────────────────────────────────

/// Everything the Prover stores after completing the setup phase.
/// In practice, prover has the commitment of input labels from the Verifier Txn skeletons.
pub struct ProverSetupState {
    pub wots_sk_p: Wots96Secret,
    pub finalized: Vec<FinalizedInstanceData>,
    pub soldering: SolderingData,
    /// h_msg per finalized instance, in finalized-index order.
    pub h_msgs: Vec<[u8; 20]>,
    pub presigs_v: VerifierPresigs,
}

/// Everything the Verifier stores after completing the setup phase.
pub struct VerifierSetupState {
    pub verifier: BABEVerifier,
    pub finalized_indices: Vec<usize>,
    pub wots_pk_p: Wots96PublicKey,
    pub presigs_p: ProverPresigs,
}

/// Result of the C&C e2e happy path.
pub struct BabeCACE2ERun {
    pub deposit_lock: TxDepositLock,
    pub assert_witness: TxAssertWitness,
    pub challenge_assert_witness: TxChallengeAssertWitness,
    pub wrongly_challenged_witness: TxWronglyChallengedWitness,
}

// ─── Setup phase ─────────────────────────────────────────────────────────────

/// Verifier: create N_CC instances and commit. Returns the verifier (retains all private state)
/// and the public `CACSetupPackage` to send to the Prover.
// TODO: bind a session nonce into CACSetupPackage and cac_finalize_indices hash once
// Bitcoin transaction integration is complete, to prevent replay of a previous protocol run.
pub fn babe_verifier_cac_setup(
    vk: &Groth16VerifyingKey<Bn254>,
    static_public_inputs: Fr,
) -> (BABEVerifier, CACSetupPackage) {
    let verifier = BABEVerifier::new(N_CC, vk, static_public_inputs).expect("verifier CAC setup failed");
    tracing::info!("Verifier: committing all instances..");
    let package = verifier.commit();
    (verifier, package)
}

// ─── Presign exchange ─────────────────────────────────────────────────────────

pub fn babe_prover_presign() -> ProverPresigs {
    ProverPresigs {
        sig_challenge_assert: BabeBtcSig::ProverPresigChallengeAssert,
        sig_no_withdraw: BabeBtcSig::ProverPresigNoWithdraw,
    }
}

pub fn babe_verifier_presign() -> VerifierPresigs {
    VerifierPresigs {
        sig_assert: BabeBtcSig::VerifierPresigAssert,
        sig_withdraw: BabeBtcSig::VerifierPresigWithdraw,
    }
}

pub fn babe_verify_verifier_presigs(presigs_v: &VerifierPresigs) -> bool {
    presigs_v.sig_assert == BabeBtcSig::VerifierPresigAssert
        && presigs_v.sig_withdraw == BabeBtcSig::VerifierPresigWithdraw
}

pub fn babe_verify_prover_presigs(
    prover_presigs: &ProverPresigs,
    challenge_assert_outlock: &TxChallengeAssertOutputLock,
    prover_pkey: &BtcPk,
    verifier_pkey: &BtcPk,
    package: &CACSetupPackage,
    finalized_indices: &[usize],
) -> bool {
    let presigs_valid = prover_presigs.sig_challenge_assert
        == BabeBtcSig::ProverPresigChallengeAssert
        && prover_presigs.sig_no_withdraw == BabeBtcSig::ProverPresigNoWithdraw;

    // This is hardcoded, let check after
    let keys_valid = challenge_assert_outlock.pk_p == *prover_pkey
        && challenge_assert_outlock.pk_v == *verifier_pkey;

    // check that the h_msg is correct.
    let h_msgs_valid = challenge_assert_outlock.h_msgs.len() == finalized_indices.len()
        && challenge_assert_outlock
            .h_msgs
            .iter()
            .zip(finalized_indices.iter())
            .all(|(&h_msg, &idx)| h_msg == package.commits[idx].h_msg);

    presigs_valid && keys_valid && h_msgs_valid
}

// ─── Deposit phase ────────────────────────────────────────────────────────────

pub fn babe_build_deposit_lock(pk_p: BtcPk, pk_v: BtcPk, amount: u64) -> TxDepositLock {
    TxDepositLock { pk_p, pk_v, amount }
}

// ─── Assert phase (Prover posts π₁ and x_d) ─────────────────────────────────────────

/// Prover: sign π₁ and x_d with wots_sk_P and build the assert witness.
/// π₂ and π₃ are serialized (compressed) into the witness for the Verifier to recover.
pub fn babe_prover_assert(proof: &Groth16Proof<Bn254>, wots_sk: &Wots96Secret, x_d: ark_bn254::Fr) -> TxAssertWitness {
    let pi1 = proof.a;
    let msg = pi1_xd_to_wots96_msg(&pi1, x_d);
    let wots_sig = Wots96::sign(wots_sk, &msg);
    let mut pi2 = Vec::new();
    proof.b.serialize_compressed(&mut pi2).expect("serialize π₂");
    let mut pi3 = Vec::new();
    proof.c.serialize_compressed(&mut pi3).expect("serialize π₃");
    TxAssertWitness { wots_sig: wots_sig.to_vec(), pi2, pi3 }
}

// ─── ChallengeAssert phase (Verifier reveals base-instance labels) ────────────

pub fn build_ca_outlock(
    pk_p: &BtcPk,
    pk_v: &BtcPk,
    h_msgs: Vec<[u8; 20]>,
) -> TxChallengeAssertOutputLock {
    TxChallengeAssertOutputLock { pk_p: pk_p.clone(), pk_v: pk_v.clone(), h_msgs }
}

/// Verifier: verify Wots96 sig in assert_witness, then compute input labels for π₁ and x_d
/// from the base finalized instance and return them in the ChallengeAssert witness.
pub fn babe_verifier_challenge_assert_cac(
    assert_witness: &TxAssertWitness,
    verifier_state: &VerifierSetupState,
) -> Option<TxChallengeAssertWitness> {
    // Simulate Bitcoin script: validate Wots96 sig length and verify against the operator pubkey.
    let arr_sig: [[u8; 21]; Wots96::TOTAL_DIGIT_LEN as usize] =
        assert_witness.wots_sig.clone().try_into().ok()?;
    let msg = Wots96::signature_to_message(&arr_sig);
    tracing::info!("Verifier: Checking Wots96 signature in tx_Assert...");
    if !wots96_verify(&verifier_state.wots_pk_p, &msg, &arr_sig) {
        return None;
    }

    Some(build_challenge_assert_witness(
        &verifier_state.verifier,
        assert_witness,
        verifier_state.finalized_indices[0],
    ))
}

/// Interleave 6 dummy entries into the [`GC_INPUT_WIRES`]-sized
/// `pi1_x | pi1_y | x_d` layout to produce the [`PADDED_INPUT_WIRES`]-sized
/// padded layout: `pi1_x | dummy x2 | pi1_y | dummy x2 | x_d | dummy x2`.
pub fn interleave_dummy_positions<T: Clone>(pi1_x: &[T], pi1_y: &[T], x_d: &[T], dummy: T) -> Vec<T> {
    assert_eq!(pi1_x.len(), N);
    assert_eq!(pi1_y.len(), N);
    assert_eq!(x_d.len(), N);
    pi1_x.iter().cloned()
        .chain([dummy.clone(), dummy.clone()])
        .chain(pi1_y.iter().cloned())
        .chain([dummy.clone(), dummy.clone()])
        .chain(x_d.iter().cloned())
        .chain([dummy.clone(), dummy.clone()])
        .collect()
}

/// Inverse of [`interleave_dummy_positions`]
pub fn deinterleave_dummy_positions<T: Clone>(padded: &[T]) -> (Vec<T>, Vec<T>, Vec<T>) {
    assert_eq!(padded.len(), PADDED_INPUT_WIRES);
    let pi1_x = padded[..N].to_vec();
    let pi1_y = padded[N + 2..2 * N + 2].to_vec();
    let x_d = padded[2 * N + 4..3 * N + 4].to_vec();
    (pi1_x, pi1_y, x_d)
}

/// Build the ChallengeAssert witness from a pre-validated Assert witness.
/// Caller is responsible for verifying the Wots96 signature before invoking this.
pub fn build_challenge_assert_witness(
    verifier: &BABEVerifier,
    assert_witness: &TxAssertWitness,
    base_idx: usize,
) -> TxChallengeAssertWitness {
    let arr_sig: [[u8; 21]; Wots96::TOTAL_DIGIT_LEN as usize] =
        assert_witness.wots_sig.clone().try_into()
            .expect("caller must ensure wots_sig has the correct length");
    let msg = Wots96::signature_to_message(&arr_sig);
    let labels = verifier.compute_labels_from_bytes(base_idx, &msg);
    let input_labels: Vec<[u8; 16]> = labels.into_iter().map(|s| s.0).collect();
    TxChallengeAssertWitness {
        witness: ChallengeAssertWitnessRaw { input_labels, wots_sig: arr_sig.to_vec() },
        sig_v: BabeBtcSig::VerifierLiveSig,
        sig_p: BabeBtcSig::ProverPresigChallengeAssert,
    }
}

// ─── WronglyChallenged phase (Prover decrypts msg via C&C) ───────────────────

/// Prover: given the labels from TxChallengeAssert, evaluate the GC across all finalized
/// instances (base first, then non-base via soldering deltas) and decrypt the msg.
pub fn babe_prover_wrongly_challenged_cac(
    vk: &Groth16VerifyingKey<Bn254>,
    dyn_pubin: Fr,
    challenge_witness: &TxChallengeAssertWitness,
    proof: &Groth16Proof<Bn254>,
    prover_state: &ProverSetupState,
) -> Option<(TxWronglyChallengedWitness, usize)> {
    let base_input_labels: Vec<S> = challenge_witness.witness.input_labels.iter().map(|&b| S(b)).collect();
    // Drop the MSB-slot labels at positions 254-255, 510-511, 766-767 (always 0 for valid fields).
    // The GC currently takes only the 254 real bits per coordinate; Step 2 removes this strip.
    let (pi1_x_labels, pi1_y_labels, x_d_labels) = deinterleave_dummy_positions(&base_input_labels);
    let pi1_labels: Vec<S> = pi1_x_labels.into_iter().chain(pi1_y_labels).collect();
    let mut prover = BABEProver::new(vk.clone(), proof.clone(), dyn_pubin);
    let found = prover.check_compute_msg(
        &prover_state.finalized,
        &pi1_labels,
        &x_d_labels,
        &prover_state.soldering,
        &prover_state.h_msgs,
    );

    found.then(|| {
        (
            TxWronglyChallengedWitness {
                sig_p: BabeBtcSig::ProverLiveSig,
                msg: prover.valid_msg.unwrap(),
            },
            prover.valid_finalized_id.unwrap(),
        )
    })
}

/// Dec*(vk, ctsetup, ctprove, c1', π₂, π₃):
///   Q_blind = e(c1', γ)  where c1' = r·P_D + r·B (DSGC output)
///   mask = e(r·π₁, π₂) - e(π₃, r·δ) - Q_blind  =  Y_S^r - e(r·B, γ)
pub fn we_known_pi1_dec(
    vk: &Groth16VerifyingKey<Bn254>,
    ct_setup: &WeKnownPi1SetupCt,
    ct_prove: &WeKnownPi1ProveCt,
    pi2: ark_bn254::G2Projective,
    pi3: ark_bn254::G1Projective,
) -> Option<Vec<u8>> {
    let ct1 = g1_from_ser_checked(&ct_prove.ct1_r_pi1)?;
    let ct1_prime = g1_from_ser_checked(&ct_prove.ct1_prime)?;
    let ct2 = g2_from_ser_checked(&ct_setup.ct2_r_delta_g2)?;

    let r_y = Bn254::pairing(ct1, pi2) - Bn254::pairing(pi3, ct2);
    let q_blind = Bn254::pairing(ct1_prime, vk.gamma_g2);
    let mask_gt = r_y - q_blind;

    let mut mask_bytes = Vec::new();
    mask_gt.serialize_compressed(&mut mask_bytes).ok()?;
    let mask = ro_from_pairing_bytes(&mask_bytes, ct_setup.ct3_masked_msg.len());
    Some(ct_setup.ct3_masked_msg.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect())
}

// ─── Shared test circuit ──────────────────────────────────────────────────────

#[derive(Copy, Clone)]
pub struct DummyMulCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyMulCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| Ok(self.a.unwrap() * self.b.unwrap()))?;
        let d = cs.new_input_variable(|| Ok(self.a.unwrap() * self.a.unwrap()))?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + a, lc!() + d)?;
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use ark_bn254::G1Affine;
    use super::*;
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use crate::wots::{wots96_verify, Wots96};
    use bitvm::signatures::Wots;

    #[test]
    fn hashlock_roundtrip() {
        let secret = b"hello-babe";
        let h_msg = derive_hashlock(secret);
        assert_eq!(derive_hashlock(secret), h_msg);
        assert_ne!(derive_hashlock(b"other"), h_msg);
    }

    #[test]
    fn wots96_sign_verify_roundtrip() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(2);
        let pi1 = G1Affine::from(ark_bn254::G1Projective::rand(&mut rng));
        let x_d = ark_bn254::Fr::rand(&mut rng);

        let sk = Wots96::generate_secret_key();
        let pk = Wots96::generate_public_key(&sk);
        let msg = pi1_xd_to_wots96_msg(&pi1, x_d);
        let sig = Wots96::sign(&sk, &msg).to_vec();

        assert_eq!(sig.len(), Wots96::TOTAL_DIGIT_LEN as usize);
        let arr_sig: [[u8; 21]; Wots96::TOTAL_DIGIT_LEN as usize] = sig.clone().try_into().unwrap();

        assert!(wots96_verify(&pk, &msg, &arr_sig));

        // Wrong pi1 must fail.
        let pi1_other = G1Affine::from(ark_bn254::G1Projective::rand(&mut rng));
        let msg_other = pi1_xd_to_wots96_msg(&pi1_other, x_d);
        assert!(!wots96_verify(&pk, &msg_other, &arr_sig));

        // Wrong x_d must fail.
        let x_d_other = ark_bn254::Fr::rand(&mut rng);
        let msg_xd_other = pi1_xd_to_wots96_msg(&pi1, x_d_other);
        assert!(!wots96_verify(&pk, &msg_xd_other, &arr_sig));
    }
}
