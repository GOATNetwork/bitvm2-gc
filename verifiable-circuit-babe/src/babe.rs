use ark_bn254::{Bn254, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::{Proof as Groth16Proof, VerifyingKey as Groth16VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use garbled_snark_verifier::bag::S;
use crate::cac::{
    cac_finalize_indices, verify_finalized_instances, verify_opened_instances,
    CACSetupPackage, FinalizedInstanceData,
};
use crate::lamport::{lamport_keygen, lamport_sign, lamport_verify, LamportPk, LamportSk};
use crate::prover::BABEProver;
use crate::soldering::{build_soldered_wires_input, soldering_guest_compute, SolderingData, SolderingProof};
use crate::transactions::{OnchainSize, TxAssertWitness, TxChallengeAssertOutputLock, TxChallengeAssertWitness, TxDepositLock, TxNoWithdrawWitness, TxWithdrawWitness, TxWronglyChallengedWitness};
use crate::utils::{derive_hashlock, g1_from_ser_checked, g1_to_ser, g2_from_ser_checked, g2_to_ser, groth16_vk_x, h, ro_from_pairing_bytes};
use crate::verifier::BABEVerifier;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Number of bits in π₁ (G1Affine): 254 bits for x + 254 bits for y.
pub const LAMPORT_N: usize = 508;

/// Total number of C&C instances the Verifier creates and commits to.
/// In practice, N_CC = 181.
pub const N_CC: usize = 10;

/// Number of instances the Prover finalizes (keeps hidden); rest are opened.
pub const M_CC: usize = 4;

/// Byte size of a Lamport signature on-chain: LAMPORT_N revealed 16-byte secrets.
pub const LAMPORT_SIG_BYTES: usize = LAMPORT_N * 16;

/// Byte size of a Bitcoin signature placeholder (64 bytes in production).
pub const BTC_SIG_BYTES: usize = 32;

/// Byte size of a compressed G1Affine point (π₁).
pub const PI1_BYTES: usize = 33;

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
pub struct EncodingKeyPublic(pub Vec<[[u8; 32]; 2]>);

pub fn compute_epk_with_delta(encoding_keys: &[S], delta: S) -> EncodingKeyPublic {
    let pairs = encoding_keys.iter().map(|&key| [h(&key.0), h(&(key ^ delta).0)]).collect();
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
}

// ─── Setup state ─────────────────────────────────────────────────────────────

/// Everything the Prover stores after completing the setup phase.
pub struct ProverSetupState {
    pub lsk_p: LamportSk,
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
    pub lpk_p: LamportPk,
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
pub fn babe_verifier_cac_setup(
    vk: &Groth16VerifyingKey<Bn254>,
    public_inputs: &[Fr],
) -> (BABEVerifier, CACSetupPackage) {
    let verifier = BABEVerifier::new(N_CC, vk, public_inputs).expect("verifier CAC setup failed");
    println!("Verifier: committing all instances..");
    let package = verifier.commit();
    (verifier, package)
}

/// Verifier: open non-finalized instances (reveal seeds) and generate the ZK-soldering proof
/// for the finalized instances.
pub fn babe_verifier_open_and_solder(
    verifier: &BABEVerifier,
    finalized_indices: &[usize],
) -> (Vec<(usize, u64)>, Vec<FinalizedInstanceData>, SolderingData) {
    let (opened, finalized) = verifier.open(finalized_indices);

    // Note that this part will be replaced by generating soldering proof in production.
    let soldered_input = build_soldered_wires_input(verifier, finalized_indices);
    let soldered_output = soldering_guest_compute(&soldered_input);

    let constant_labels: Vec<[S; 2]> = finalized_indices.iter().map(|&idx| {
        let inst = &verifier.instances[idx];
        [inst.secrets.constant_0labels[0], inst.secrets.constant_0labels[1] ^ inst.secrets.delta]
    }).collect();

    let soldering = SolderingData {
        finalized_indices: finalized_indices.to_vec(),
        soldering_proof: SolderingProof { soldered_output, _proof: PhantomData },
        constant_labels,
    };

    (opened, finalized, soldering)
}

/// Prover: verify the opened instances, the finalized instances, and the soldering proof.
pub fn babe_prover_verify_setup(
    package: &CACSetupPackage,
    opened: &[(usize, u64)],
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
    vk: &Groth16VerifyingKey<Bn254>,
    public_inputs: &[Fr],
) -> Result<(), String> {
    verify_opened_instances(package, opened, vk, public_inputs)?;
    verify_finalized_instances(package, finalized)?;
    BABEProver::verify_soldering_output(package, soldering)?;
    Ok(())
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
    let presigs_valid = prover_presigs.sig_challenge_assert == BabeBtcSig::ProverPresigChallengeAssert
        && prover_presigs.sig_no_withdraw == BabeBtcSig::ProverPresigNoWithdraw;

    // This is hardcoded, let check after
    let keys_valid = challenge_assert_outlock.pk_p == *prover_pkey
        && challenge_assert_outlock.pk_v == *verifier_pkey;

    let h_msgs_valid = challenge_assert_outlock.h_msgs.len() == finalized_indices.len()
        && challenge_assert_outlock.h_msgs.iter().zip(finalized_indices.iter()).all(|(&h_msg, &idx)| {
            h_msg == package.commits[idx].h_msg
        });

    presigs_valid && keys_valid && h_msgs_valid
}

// ─── Deposit phase ────────────────────────────────────────────────────────────

pub fn babe_build_deposit_lock(pk_p: BtcPk, pk_v: BtcPk, amount: u64) -> TxDepositLock {
    TxDepositLock { pk_p, pk_v, amount }
}

// ─── Assert phase (Prover posts π₁) ─────────────────────────────────────────

/// Prover: sign π₁ with lsk_P and build the assert witness.
pub fn babe_prover_assert(proof: &Groth16Proof<Bn254>, lsk_p: &LamportSk) -> TxAssertWitness {
    let pi1 = proof.a;
    let mut pi1_bytes = Vec::new();
    pi1.serialize_compressed(&mut pi1_bytes).expect("serialize π₁");
    let lamport_sig = lamport_sign(lsk_p, &pi1);
    TxAssertWitness { pi1: pi1_bytes, lamport_sig }
}

// ─── ChallengeAssert phase (Verifier reveals base-instance labels) ────────────

pub fn build_ca_outlock(
    pk_p: &BtcPk,
    pk_v: &BtcPk,
    h_msgs: Vec<[u8; 20]>,
) -> TxChallengeAssertOutputLock {
    TxChallengeAssertOutputLock {
        pk_p: pk_p.clone(),
        pk_v: pk_v.clone(),
        h_msgs,
    }
}

/// Verifier: verify Lamport sig in assert_witness, then compute input labels for π₁
/// from the base finalized instance and return them in the ChallengeAssert witness.
pub fn babe_verifier_challenge_assert_cac(
    assert_witness: &TxAssertWitness,
    verifier_state: &VerifierSetupState,
    sig_p_presig: BabeBtcSig,
) -> Option<TxChallengeAssertWitness> {
    let pi1 = G1Affine::deserialize_compressed(assert_witness.pi1.as_slice()).ok()?;

    println!("Verifier: Checking the Lamport signature in tx_Assert witness against pi1 and lpk_P...");
    if !lamport_verify(&verifier_state.lpk_p, &pi1, &assert_witness.lamport_sig) {
        return None;
    }

    // Derive labels from the base instance (finalized_indices[0]).
    let base_idx = verifier_state.finalized_indices[0];
    let base_inst = &verifier_state.verifier.instances[base_idx];
    let all_labels = base_inst.compute_pi1_labels_based_on_value(pi1);
    // all_labels[0..2] are constant-wire labels; [2..] are π₁ input labels.
    let input_labels: Vec<[u8; 16]> = all_labels[2..].iter().map(|s| s.0).collect();

    Some(TxChallengeAssertWitness {
        input_labels,
        lamport_sig: assert_witness.lamport_sig.clone(),
        sig_v: BabeBtcSig::VerifierLiveSig,
        sig_p: sig_p_presig,
    })
}

// ─── WronglyChallenged phase (Prover decrypts msg via C&C) ───────────────────

/// Prover: given the labels from TxChallengeAssert, evaluate the GC across all finalized
/// instances (base first, then non-base via soldering deltas) and decrypt the msg.
pub fn babe_prover_wrongly_challenged_cac(
    challenge_witness: &TxChallengeAssertWitness,
    proof: &Groth16Proof<Bn254>,
    prover_state: &ProverSetupState,
) -> Option<(TxWronglyChallengedWitness, usize)> {
    let base_input_labels: Vec<S> = challenge_witness.input_labels.iter().map(|&b| S(b)).collect();

    let mut prover = BABEProver::new(proof.clone());
    let found = prover.check_compute_msg(
        &prover_state.finalized,
        &base_input_labels,
        &prover_state.soldering,
        &prover_state.h_msgs,
    );

    found.then(|| (TxWronglyChallengedWitness {
        sig_p: BabeBtcSig::ProverLiveSig,
        msg: prover.valid_msg.unwrap(),
    }, prover.valid_finalized_id.unwrap()))
}

// ─── No-withdraw / Withdraw phases ───────────────────────────────────────────

pub fn babe_verifier_no_withdraw(sig_p_presig: BabeBtcSig) -> TxNoWithdrawWitness {
    TxNoWithdrawWitness {
        input0_sig_p: sig_p_presig,
        input0_sig_v: BabeBtcSig::VerifierLiveSig,
        input1_sig_v: BabeBtcSig::VerifierLiveSig,
    }
}

pub fn babe_prover_withdraw(sig_v_presig: BabeBtcSig) -> TxWithdrawWitness {
    TxWithdrawWitness {
        input0_sig_p: BabeBtcSig::ProverLiveSig,
        input0_sig_v: sig_v_presig.clone(),
        input1_sig_p: BabeBtcSig::ProverLiveSig,
        input1_sig_v: sig_v_presig,
    }
}

// ─── Enc_ functions ────────────────────────────────────────────────────────

/// Encsetup(crs, x, msg; r): ctsetup = (r·[delta]_2, RO(rY) ⊕ msg).
pub fn we_known_pi1_encsetup(
    vk: &Groth16VerifyingKey<Bn254>,
    public_inputs: &[Fr],
    msg: &[u8],
    r_bytes: [u8; 32],
) -> Option<WeKnownPi1SetupCt> {
    let r = Fr::from_le_bytes_mod_order(&r_bytes);
    let vk_x = groth16_vk_x(vk, public_inputs)?;
    let r_delta = vk.delta_g2.into_group() * r;

    let t1 = Bn254::pairing(vk.alpha_g1, vk.beta_g2.into_group() * r);
    let t2 = Bn254::pairing(vk_x, vk.gamma_g2.into_group() * r);
    let r_y = t1 + t2;

    let mut ry_bytes = Vec::new();
    r_y.serialize_compressed(&mut ry_bytes).ok()?;
    let mask = ro_from_pairing_bytes(&ry_bytes, msg.len());
    let ct3 = msg.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect();

    Some(WeKnownPi1SetupCt { ct2_r_delta_g2: g2_to_ser(r_delta), ct3_masked_msg: ct3 })
}

/// Encprove(crs, π₁; r): ctprove = r·π₁.
pub fn we_known_pi1_encprove(pi1: ark_bn254::G1Projective, r_bytes: [u8; 32]) -> WeKnownPi1ProveCt {
    let r = Fr::from_le_bytes_mod_order(&r_bytes);
    WeKnownPi1ProveCt { ct1_r_pi1: g1_to_ser(pi1 * r) }
}

/// Dec(ctsetup, ctprove, π₂, π₃): msg = ct3 ⊕ RO(e(ct1,π₂) - e(π₃,ct2)).
pub fn we_known_pi1_dec(
    ctsetup: &WeKnownPi1SetupCt,
    ctprove: &WeKnownPi1ProveCt,
    pi2: ark_bn254::G2Projective,
    pi3: ark_bn254::G1Projective,
) -> Option<Vec<u8>> {
    let ct1 = g1_from_ser_checked(&ctprove.ct1_r_pi1)?;
    let ct2 = g2_from_ser_checked(&ctsetup.ct2_r_delta_g2)?;
    let r_y = Bn254::pairing(ct1, pi2) - Bn254::pairing(pi3, ct2);

    let mut ry_bytes = Vec::new();
    r_y.serialize_compressed(&mut ry_bytes).ok()?;
    let mask = ro_from_pairing_bytes(&ry_bytes, ctsetup.ct3_masked_msg.len());
    Some(ctsetup.ct3_masked_msg.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect())
}

// ─── BABE C&C Soldering E2E flow ─────────────────────────────────────────────────────
pub fn run_babe_e2e_cac() -> BabeCACE2ERun {
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
    let a = Fr::from(7u64);
    let b = Fr::from(9u64);

    let (groth16_pk, vk) = ark_groth16::Groth16::<Bn254>::setup(
        DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) }, &mut rng,
    ).expect("groth16 setup");
    let proof = ark_groth16::Groth16::<Bn254>::prove(
        &groth16_pk,
        DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) },
        &mut rng,
    ).expect("groth16 prove");
    let public_inputs = vec![a * b];

    // ── Setup phase ───────────────────────────────────────────────────────────

    // Prover sends pk_p to Verifier.
    let pk_p = BtcPk([0u8; 33]);
    // let (lsk_p, lpk_p) = babe_prover_keygen(&mut rng);
    println!("Prover: generating BTC keys and sending pk_p to Verifier");

    // Verifier creates N_CC instances and sends CACSetupPackage.
    println!("Verifier generating BTC keys");
    let pk_v = BtcPk([1u8; 33]);
    println!("Verifier: building {} instances...", N_CC);
    let (verifier, package) = babe_verifier_cac_setup(&vk, &public_inputs);
    // Verifier sends vk and package to Prover
    println!("Verifier: sending pk_v and {} instance commitment to Prover", N_CC);

    // Prover samples M_CC finalized indices (Fiat-Shamir over all commits).
    // Todo: can be replace by randomize.
    let finalized_indices = cac_finalize_indices(&package, M_CC);
    println!("Prover: finalized indices = {:?}", &finalized_indices);

    // Verifier opens non-finalized instances and generates soldering proof.
    println!("Verifier: opening and soldering...");
    let (opened, finalized, soldering) = babe_verifier_open_and_solder(&verifier, &finalized_indices);

    println!("Prover: verifying opening and soldering proof...");
    // Prover verifies everything.
    babe_prover_verify_setup(&package, &opened, &finalized, &soldering, &vk, &public_inputs)
        .expect("prover setup verification failed");

    println!("Prover: generating Lamport signature...");
    let (lsk_p, lpk_p) = lamport_keygen(&mut rng);

    // ── Create Txn Set and Presign ──────────────────────────────────────────────────
    println!("Prover: creating Tx Set and pre sign...");
    let h_msgs_p: Vec<[u8; 20]> = finalized_indices.iter().map(|&idx| package.commits[idx].h_msg).collect();
    let tx_challenge_assert_outlock_p = build_ca_outlock(
        &pk_p,
        &pk_v,
        h_msgs_p,
    );
    let prover_presigs = babe_prover_presign();
    println!("Prover: sending lpk_p, presigs_p to Verifier");
    println!("Verifier: verifying presigs_p...");
    let check = babe_verify_prover_presigs(
        &prover_presigs,
        &tx_challenge_assert_outlock_p,
        &pk_p,
        &pk_v,
        &package,
        &finalized_indices
    );
    assert!(check, "Prover verification presigs failed");

    println!("Verifier: creating Tx Set and pre sign...");
    // same as above, no need to implement
    let verifier_presigs = babe_verifier_presign();
    println!("Verifier: sending presigs_v to Verifier...");

    println!("Prover: verifying presigs_p...");
    assert!(babe_verify_verifier_presigs(&verifier_presigs), "verifier presigs invalid");

    // ── Deposit ───────────────────────────────────────────────────────────────

    println!("Prover: submitting Deposit Txn...");
    let deposit_lock = babe_build_deposit_lock(pk_p, pk_v, 100_000);
    // Both parties persist their setup state.
    let prover_state = ProverSetupState {
        lsk_p,
        finalized,
        soldering,
        h_msgs: tx_challenge_assert_outlock_p.h_msgs,
        presigs_v: verifier_presigs,
    };
    let verifier_state = VerifierSetupState {
        verifier,
        package,
        finalized_indices,
        lpk_p,
        presigs_p: prover_presigs,
    };

    // ── Proving phase ─────────────────────────────────────────────────────────

    // Assert: Prover posts π₁ + Lamport sig on-chain.
    let assert_witness = babe_prover_assert(&proof, &prover_state.lsk_p);
    println!("Prover: posting tx_Assert...");
    println!("tx_Assert witness:            {} bytes", assert_witness.size_bytes());

    // ChallengeAssert: Verifier verifies Lamport sig and reveals base-instance labels.
    let challenge_witness = babe_verifier_challenge_assert_cac(
        &assert_witness,
        &verifier_state,
        verifier_state.presigs_p.sig_challenge_assert.clone(),
    ).expect("Lamport sig invalid in assert witness");
    println!("Verifier: posting tx_ChallengeAssert...");
    println!("tx_ChallengeAssert witness:   {} bytes", challenge_witness.size_bytes());

    println!("Script: checking the valid of Verifier labels...");
    // WronglyChallenged: Prover evaluates GC (base first, then non-base if needed).
    println!("Prover: Finding msg...");
    let (wc_witness, instance_id) = babe_prover_wrongly_challenged_cac(
        &challenge_witness,
        &proof,
        &prover_state,
    ).expect("failed to find valid msg");
    println!("Prover: posting tx_WronglyChallenged...");
    println!("tx_WronglyChallenged witness: {} bytes", wc_witness.size_bytes());

    // Sanity: msg must satisfy the on-chain hashlock.
    let finalized_id = prover_state.finalized.iter().position(|d| d.index == instance_id).unwrap();
    assert_eq!(
        derive_hashlock(&wc_witness.msg),
        prover_state.h_msgs[finalized_id],
        "decrypted msg does not match h_msg"
    );

    BabeCACE2ERun { deposit_lock, assert_witness, challenge_assert_witness: challenge_witness, wrongly_challenged_witness: wc_witness }
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
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr};
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ff::UniformRand;
    use rand::SeedableRng;

    #[test]
    fn hashlock_roundtrip() {
        let secret = b"hello-babe";
        let h_msg = derive_hashlock(secret);
        assert_eq!(derive_hashlock(secret), h_msg);
        assert_ne!(derive_hashlock(b"other"), h_msg);
    }

    #[test]
    fn lamport_sign_verify_roundtrip() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);
        let pi1 = G1Affine::from(ark_bn254::G1Projective::rand(&mut rng));
        let (lsk, lpk) = lamport_keygen(&mut rng);
        let sig = lamport_sign(&lsk, &pi1);
        assert!(lamport_verify(&lpk, &pi1, &sig));
        let pi1_other = G1Affine::from(ark_bn254::G1Projective::rand(&mut rng));
        assert!(!lamport_verify(&lpk, &pi1_other, &sig));
    }

    #[test]
    fn we_encsetup_dec_roundtrip() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let a = Fr::from(3u64);
        let b = Fr::from(7u64);
        let (pk, vk) = ark_groth16::Groth16::<Bn254>::setup(
            DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) }, &mut rng,
        ).unwrap();
        let proof = ark_groth16::Groth16::<Bn254>::prove(
            &pk,
            DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) },
            &mut rng,
        ).unwrap();
        let public_inputs = vec![a * b];
        let secret = b"test-secret-32by";
        let r_bytes = h(b"r-test");

        let ct_setup = we_known_pi1_encsetup(&vk, &public_inputs, secret, r_bytes).unwrap();
        let ctprove = we_known_pi1_encprove(proof.a.into_group(), r_bytes);
        let decrypted = we_known_pi1_dec(&ct_setup, &ctprove, proof.b.into_group(), proof.c.into_group()).unwrap();
        assert_eq!(decrypted, secret);
    }
}