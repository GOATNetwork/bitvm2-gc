use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Proof as Groth16Proof, VerifyingKey as Groth16VerifyingKey};
use ark_groth16::ProvingKey as Groth16ProvingKey;

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
use crate::prover::BABEProver;
use crate::soldering::SolderingData;
use crate::transactions::{TxAssertWitness, TxChallengeAssertOutputLock, TxChallengeAssertWitness, TxDepositLock, TxWronglyChallengedWitness};
pub use crate::utils::{derive_hashlock, g1_from_ser_checked, g1_to_ser, g2_from_ser_checked, g2_to_ser, groth16_vk_x, h_256, ro_from_pairing_bytes};
use crate::verifier::BABEVerifier;

// ─── Constants ────────────────────────────────────────────────────────────────
/// Total number of C&C instances the Verifier creates and commits to.
/// In practice, N_CC = 181.
pub const N_CC: usize = 4;

/// Number of instances the Prover finalizes (keeps hidden); rest are opened.
/// In practice, M_CC = 4.
pub const M_CC: usize = 2;

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

pub fn compute_epk(encoding_keys: &[S]) -> EncodingKeyPublic {
    use garbled_snark_verifier::core::utils::NON_CAC_DELTA;
    compute_epk_with_delta(encoding_keys, NON_CAC_DELTA)
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
/// (Verifier just need to commit the base instance input labels)
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
    pub package: CACSetupPackage,
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
    println!("Verifier: committing all instances..");
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
pub fn babe_prover_assert(proof: &Groth16Proof<Bn254>, wots_sk: &Wots96Secret, x_d: ark_bn254::Fr) -> TxAssertWitness {
    let pi1 = proof.a;
    let msg = pi1_xd_to_wots96_msg(&pi1, x_d);
    let wots_sig = Wots96::sign(wots_sk, &msg);
    TxAssertWitness { wots_sig }
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
    sig_p_presig: BabeBtcSig,
) -> Option<TxChallengeAssertWitness> {
    let (pi1, x_d) = assert_witness.recover_pi1_xd_without_verify()?;

    let msg = pi1_xd_to_wots96_msg(&pi1, x_d);
    println!("Verifier: Checking Wots96 signature in tx_Assert against pi1, x_d and wots_pk_p...");
    if !wots96_verify(&verifier_state.wots_pk_p, &msg, &assert_witness.wots_sig) {
        return None;
    }

    // Derive labels from the base instance (finalized_indices[0]).
    let base_idx = verifier_state.finalized_indices[0];

    // compute_pi1_labels returns 508 labels: [0..254] for pi1.x, [254..508] for pi1.y.
    // compute_x_d_labels returns 254 labels.
    // Interleave 6 dummy labels at the 2 MSB padding positions of each 256-bit field:
    //   pi1.x[254] | dummy[2] | pi1.y[254] | dummy[2] | x_d[254] | dummy[2] = 768
    // Dummy value [0u8; 16] is consistent: derive_hashlock(&[0u8; 16]) == epk[i][0] for
    // the dummy EPK entries computed in compute_epk_with_delta. Note that Prover & Verifier should
    // embed this hashlock in the challengeAssert script in order to make the check passed.
    let pi1_labels = verifier_state.verifier.compute_pi1_labels(base_idx, pi1);
    let x_d_labels = verifier_state.verifier.compute_x_d_labels(base_idx, x_d);
    let dummy = S([0u8; 16]);
    let input_labels: Vec<[u8; 16]> = pi1_labels[..254].iter()
        .chain([dummy, dummy].iter())
        .chain(pi1_labels[254..].iter())
        .chain([dummy, dummy].iter())
        .chain(x_d_labels.iter())
        .chain([dummy, dummy].iter())
        .map(|s| s.0)
        .collect();

    Some(TxChallengeAssertWitness {
        input_labels,
        wots_sig: assert_witness.wots_sig,
        sig_v: BabeBtcSig::VerifierLiveSig,
        sig_p: sig_p_presig,
    })
}

// ─── WronglyChallenged phase (Prover decrypts msg via C&C) ───────────────────

/// Prover: given the labels from TxChallengeAssert, evaluate the GC across all finalized
/// instances (base first, then non-base via soldering deltas) and decrypt the msg.
pub fn babe_prover_wrongly_challenged_cac(
    pk: &Groth16ProvingKey<Bn254>,
    dyn_pubin: Fr,
    challenge_witness: &TxChallengeAssertWitness,
    proof: &Groth16Proof<Bn254>,
    prover_state: &ProverSetupState,
) -> Option<(TxWronglyChallengedWitness, usize)> {
    let base_input_labels: Vec<S> = challenge_witness.input_labels.iter().map(|&b| S(b)).collect();
    assert_eq!(base_input_labels.len(), 768);
    // Layout: pi1.x[0..254] | dummy[254..256] | pi1.y[256..510] | dummy[510..512]
    //       | x_d[512..766] | dummy[766..768]
    // Strip the 6 dummy labels before passing to the GC (which has 762 real wires).
    let pi1_labels: Vec<S> = base_input_labels[..254].iter()
        .chain(base_input_labels[256..510].iter())
        .copied()
        .collect();
    let x_d_labels: Vec<S> = base_input_labels[512..766].to_vec();
    let mut prover = BABEProver::new(pk.clone(), proof.clone(), dyn_pubin);
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
        let sig = Wots96::sign(&sk, &msg);

        assert!(wots96_verify(&pk, &msg, &sig));

        // Wrong pi1 must fail.
        let pi1_other = G1Affine::from(ark_bn254::G1Projective::rand(&mut rng));
        let msg_other = pi1_xd_to_wots96_msg(&pi1_other, x_d);
        assert!(!wots96_verify(&pk, &msg_other, &sig));

        // Wrong x_d must fail.
        let x_d_other = ark_bn254::Fr::rand(&mut rng);
        let msg_xd_other = pi1_xd_to_wots96_msg(&pi1, x_d_other);
        assert!(!wots96_verify(&pk, &msg_xd_other, &sig));
    }
}
