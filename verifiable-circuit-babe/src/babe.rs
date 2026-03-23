use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_groth16::{Proof as Groth16Proof, VerifyingKey as Groth16VerifyingKey};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Number of bits in π₁ (G1Affine): 254 bits for x + 254 bits for y.
pub const LAMPORT_N: usize = 508;

/// Byte size of a Lamport signature on-chain: LAMPORT_N revealed 16-byte secrets.
pub const LAMPORT_SIG_BYTES: usize = LAMPORT_N * 16; // 8,128 bytes

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
/// Using named variants enforces that the right sig goes in the right field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BabeBtcSig {
    /// σ_ChallengeAssert^P — Prover presigs, sent to Verifier at setup
    ProverPresigChallengeAssert,
    /// σ_NoWithdraw^P — Prover presigs, sent to Verifier at setup
    ProverPresigNoWithdraw,
    /// σ_Assert^V — Verifier presigs, verified off-chain by Prover before depositing
    VerifierPresigAssert,
    /// σ_Withdraw^V — Verifier presigs, sent to Prover at setup
    VerifierPresigWithdraw,
    /// Live signature from the Prover when posting a transaction
    ProverLiveSig,
    /// Live signature from the Verifier when posting a transaction
    VerifierLiveSig,
}

// ─── Lamport Signature Scheme ─────────────────────────────────────────────────

/// Lamport signing key: LAMPORT_N pairs of 16-byte secrets.
/// Each secret has the same width as a GC input label.
#[derive(Debug, Clone)]
pub struct LamportSk(pub Vec<[[u8; 16]; 2]>);

/// Lamport verification key: pk[i][b] = SHA256(sk[i][b]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LamportPk(pub Vec<[[u8; 32]; 2]>);

/// Lamport signature: sig[i] = sk[i][bit_i(π₁)], for i in 0..LAMPORT_N.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LamportSig(pub Vec<[u8; 16]>);

pub fn lamport_keygen(rng: &mut impl RngCore) -> (LamportSk, LamportPk) {
    let mut sk_entries = Vec::with_capacity(LAMPORT_N);
    let mut pk_entries = Vec::with_capacity(LAMPORT_N);
    for _ in 0..LAMPORT_N {
        let mut s0 = [0u8; 16];
        let mut s1 = [0u8; 16];
        rng.fill_bytes(&mut s0);
        rng.fill_bytes(&mut s1);
        pk_entries.push([sha256_bytes(&s0), sha256_bytes(&s1)]);
        sk_entries.push([s0, s1]);
    }
    (LamportSk(sk_entries), LamportPk(pk_entries))
}

/// Commitment to the full Lamport pk: blake3 of all entries.
pub fn lamport_pk_commit(pk: &LamportPk) -> [u8; 32] {
    let mut buf = b"babe:lamport-pk".to_vec();
    for pair in &pk.0 {
        buf.extend_from_slice(&pair[0]);
        buf.extend_from_slice(&pair[1]);
    }
    h(&buf)
}

/// Sign π₁: reveal sk[i][bit_i(π₁)] for each bit.
pub fn lamport_sign(sk: &LamportSk, pi1: &G1Affine) -> LamportSig {
    let bits = pi1_to_bits(pi1);
    LamportSig(bits.iter().enumerate().map(|(i, &b)| sk.0[i][b as usize]).collect())
}

/// Verify a Lamport signature against lpk_P and π₁.
pub fn lamport_verify(pk: &LamportPk, pi1: &G1Affine, sig: &LamportSig) -> bool {
    if sig.0.len() != LAMPORT_N {
        return false;
    }
    let bits = pi1_to_bits(pi1);
    bits.iter().enumerate().all(|(i, &b)| sha256_bytes(&sig.0[i]) == pk.0[i][b as usize])
}

fn pi1_to_bits(pi1: &G1Affine) -> Vec<bool> {
    use garbled_snark_verifier::dv_bn254::fq::Fq as GcFq;
    GcFq::to_bits(pi1.x).into_iter().chain(GcFq::to_bits(pi1.y)).collect()
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

// ─── Encoding Key Public (lpk_V in the paper) ────────────────────────────────

/// Commitment to the verifier's GC encoding key labels.
/// epk[i][b] = blake3(label_i_b), for i in 0..LAMPORT_N, b ∈ {0, 1}.
/// Published as h_ek = blake3(flatten(epk)) in tx_Assert output 1 script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodingKeyPublic(pub Vec<[[u8; 32]; 2]>);

impl EncodingKeyPublic {
    /// h_ek: single commitment to all label hashes.
    pub fn commit(&self) -> [u8; 32] {
        let mut buf = b"babe:h-ek".to_vec();
        for pair in &self.0 {
            buf.extend_from_slice(&pair[0]);
            buf.extend_from_slice(&pair[1]);
        }
        h(&buf)
    }
}

/// Compute epk from the verifier's private 0-labels (encoding_keys).
#[cfg(feature = "garbled")]
pub fn compute_epk(encoding_keys: &[garbled_snark_verifier::bag::S]) -> EncodingKeyPublic {
    // Todo: change to use own delta instead of NON_CAC_DELTA
    use garbled_snark_verifier::core::utils::NON_CAC_DELTA;
    let pairs = encoding_keys.iter().map(|&key| {
        let label_0 = key.0;
        let label_1 = (key ^ NON_CAC_DELTA).0;
        [h(&label_0), h(&label_1)]
    }).collect();
    EncodingKeyPublic(pairs)
}

// ─── Transaction locking script ───────────────────────────────────────────────

/// Constants embedded in the locking script of tx_Deposit output 0.
/// Script: CheckSig(pk_P) ∧ CheckSig(pk_V)
#[derive(Debug, Clone)]
pub struct TxDepositLock {
    pub pk_p: BtcPk,
    pub pk_v: BtcPk,
    pub amount: u64,
}

// ─── Transaction witnesses (on-chain data) ────────────────────────────────────

/// tx_Assert — witness for input 0.
/// Input spends a UTXO with: CheckLampSig(lpk_P)
/// Script verifies: SHA256(μ[i]) == lpk_P[i][bit_i(π₁)] for all i.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxAssertWitness {
    /// Compressed G1Affine, 33 bytes — the asserted proof element.
    pub pi1: Vec<u8>,
    /// μ₁…μ_ℓ — Lamport signature, LAMPORT_N × 16 bytes.
    pub lamport_sig: LamportSig,
}

/// tx_ChallengeAssert — witness for input 0.
/// Input spends tx_Assert output 1: CheckLampSigsMatch(lpk_P, lpk_V) ∧ CheckSig(pk_V) ∧ CheckSig(pk_P)
/// Script verifies:
///   (a) SHA256(μ[i]) == lpk_P[i][bit_i]     — μ is a valid Lamport sig for some π₁
///   (b) blake3(L[i]) == lpk_V[i][bit_i]     — L[i] is the correct GC label for bit_i under epk
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxChallengeAssertWitness {
    /// L₁…L_ℓ — one GC input label per π₁ bit, LAMPORT_N × 16 bytes.
    pub input_labels: Vec<[u8; 16]>,
    /// μ₁…μ_ℓ — Lamport sig re-posted to bind L to π₁.
    pub lamport_sig: LamportSig,
    /// VerifierLiveSig
    pub sig_v: BabeBtcSig,
    /// ProverPresigChallengeAssert
    pub sig_p: BabeBtcSig,
}

/// tx_WronglyChallenged — witness for input 0.
/// Input spends tx_ChallengeAssert output 0: HashLock(h_msg) ∧ CheckSig(pk_P)
/// Script verifies: SHA256(msg) == h_msg.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxWronglyChallengedWitness {
    /// ProverLiveSig
    pub sig_p: BabeBtcSig,
    /// Decrypted secret — preimage of h_msg = SHA256(msg).
    pub msg: [u8; 32],
}

/// tx_NoWithdraw — witnesses for inputs 0 and 1.
/// Input 0 spends tx_Assert output 0:          CheckSig(pk_P) ∧ CheckSig(pk_V)
/// Input 1 spends tx_ChallengeAssert output 0: RelTimelock(Δ₁) ∧ CheckSig(pk_V)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxNoWithdrawWitness {
    /// ProverPresigNoWithdraw — for input 0
    pub input0_sig_p: BabeBtcSig,
    /// VerifierLiveSig — for input 0
    pub input0_sig_v: BabeBtcSig,
    /// VerifierLiveSig — for input 1, after RelTimelock(Δ₁)
    pub input1_sig_v: BabeBtcSig,
}

/// tx_Withdraw — witnesses for inputs 0 and 1.
/// Input 0 spends tx_Deposit output 0: CheckSig(pk_P) ∧ CheckSig(pk_V)
/// Input 1 spends tx_Assert output 0:  RelTimelock(Δ₂) ∧ CheckSig(pk_P) ∧ CheckSig(pk_V)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxWithdrawWitness {
    /// ProverLiveSig — for input 0
    pub input0_sig_p: BabeBtcSig,
    /// VerifierPresigWithdraw — for input 0
    pub input0_sig_v: BabeBtcSig,
    /// ProverLiveSig — for input 1, after RelTimelock(Δ₂)
    pub input1_sig_p: BabeBtcSig,
    /// VerifierPresigWithdraw — for input 1
    pub input1_sig_v: BabeBtcSig,
}

// ─── OnchainSize trait ────────────────────────────────────────────────────────

pub trait OnchainSize {
    fn size_bytes(&self) -> usize;
}

impl OnchainSize for TxAssertWitness {
    fn size_bytes(&self) -> usize {
        PI1_BYTES           // pi1:         33 bytes
        + LAMPORT_SIG_BYTES // lamport_sig: 8,128 bytes
        // total: 8,161 bytes
    }
}

impl OnchainSize for TxChallengeAssertWitness {
    fn size_bytes(&self) -> usize {
        LAMPORT_N * 16      // input_labels: 8,128 bytes
        + LAMPORT_SIG_BYTES // lamport_sig:  8,128 bytes
        + BTC_SIG_BYTES     // sig_v:           32 bytes
        + BTC_SIG_BYTES     // sig_p:           32 bytes
        // total: 16,320 bytes
    }
}

impl OnchainSize for TxWronglyChallengedWitness {
    fn size_bytes(&self) -> usize {
        BTC_SIG_BYTES // sig_p: 32 bytes
        + MSG_BYTES   // msg:   32 bytes
        // total: 64 bytes
    }
}

impl OnchainSize for TxNoWithdrawWitness {
    fn size_bytes(&self) -> usize {
        BTC_SIG_BYTES * 3 // 3 sigs × 32 bytes = 96 bytes
    }
}

impl OnchainSize for TxWithdrawWitness {
    fn size_bytes(&self) -> usize {
        BTC_SIG_BYTES * 4 // 4 sigs × 32 bytes = 128 bytes
    }
}

// ─── Presig structs ───────────────────────────────────────────────────────────

/// Prover presigns tx_ChallengeAssert and tx_NoWithdraw — sent to Verifier at setup.
#[derive(Debug, Clone)]
pub struct ProverPresigs {
    /// → TxChallengeAssertWitness.sig_p
    pub sig_challenge_assert: BabeBtcSig,
    /// → TxNoWithdrawWitness.input0_sig_p
    pub sig_no_withdraw: BabeBtcSig,
}

/// Verifier presigns tx_Assert (off-chain) and tx_Withdraw — sent to Prover at setup.
#[derive(Debug, Clone)]
pub struct VerifierPresigs {
    /// Verified off-chain by Prover before depositing (not in any on-chain witness).
    pub sig_assert: BabeBtcSig,
    /// → TxWithdrawWitness.input0_sig_v and input1_sig_v
    pub sig_withdraw: BabeBtcSig,
}

// ─── Setup packages ───────────────────────────────────────────────────────────

/// What the Verifier sends to the Prover during setup.
pub struct VerifierSetupPackage {
    /// (r·[delta]_2, RO(rY) ⊕ msg) — WE ciphertext setup component.
    pub ct_setup: WeKnownPi1SetupCt,
    /// Garbled gate ciphertexts — published once, used by Prover during WronglyChallenged.
    #[cfg(feature = "garbled")]
    pub gc_ciphertexts: Vec<Option<garbled_snark_verifier::bag::S>>,
    /// DRE adaptor table — maps GC output labels to r-encoded field elements.
    #[cfg(feature = "garbled")]
    pub adaptor_table: crate::gc::SparseAdaptorTable,
    /// lpk_V in the paper: blake3 hashes of input labels.
    pub epk: EncodingKeyPublic,
    /// blake3(flatten(epk)) — embedded in tx_Assert output 1 script.
    pub h_ek: [u8; 32],
    /// SHA256(secret_msg) — embedded in tx_ChallengeAssert output 0 script.
    pub h_msg: [u8; 32],
    /// Actual labels for constant wires 0 and 1.
    /// constant_labels[0] = label for wire 0 (value=false)
    /// constant_labels[1] = label for wire 1 (value=true)
    #[cfg(feature = "garbled")]
    pub constant_labels: [[u8; 16]; 2],
    /// Garbled circuit structure (labels and values cleared after reset).
    /// Stored here so the Prover does not need to recompute it.
    #[cfg(feature = "garbled")]
    pub circuit: garbled_snark_verifier::bag::Circuit,
    /// Indices into `circuit.0` that correspond to the GC output wires.
    #[cfg(feature = "garbled")]
    pub gc_output_indices: Vec<usize>,
}

/// What the Prover sends to the Verifier during setup.
#[derive(Debug, Clone)]
pub struct ProverSetupPackage {
    /// Lamport verification key — Verifier embeds lpk_P into transaction scripts.
    pub lpk_p: LamportPk,
    /// blake3(flatten(lpk_p)) — used in scripts as a compact commitment.
    pub lpk_p_commit: [u8; 32],
    /// Prover's Bitcoin pubkey.
    pub pk_p: BtcPk,
}

/// What the Verifier keeps private after setup.
/// Todo: Will change to contains secret of each Instance later.
pub struct BabeVerifierPrivate {
    /// The WE scalar r.
    pub r: Fr,
    /// The 32-byte secret whose SHA256 is h_msg.
    pub msg: [u8; 32],
    /// 0-labels for GC input wires (size LAMPORT_N).
    #[cfg(feature = "garbled")]
    pub encoding_keys: Vec<garbled_snark_verifier::bag::S>,
    /// 0-labels for constant GC wires (index 0 = false wire, 1 = true wire).
    #[cfg(feature = "garbled")]
    pub constant_0labels: [garbled_snark_verifier::bag::S; 2],
    #[cfg(feature = "garbled")]
    pub delta: garbled_snark_verifier::bag::S,
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

// ─── E2E run result ───────────────────────────────────────────────────────────

pub struct BabeE2ERun {
    pub session_id: [u8; 32],
    pub deposit_lock: TxDepositLock,
    pub prover_setup_pkg: ProverSetupPackage,
    pub h_ek: [u8; 32],
    pub h_msg: [u8; 32],
    pub prover_presigs: ProverPresigs,
    pub verifier_presigs: VerifierPresigs,
    /// Happy path: Prover asserted a valid proof.
    pub assert_witness: TxAssertWitness,
    /// Happy path: Verifier challenged by revealing labels.
    pub challenge_assert_witness: TxChallengeAssertWitness,
    /// Happy path: Prover decrypted msg and posted it (valid proof wins).
    pub wrongly_challenged_witness: TxWronglyChallengedWitness,
}

// ─── Lamport phase functions ──────────────────────────────────────────────────

/// Prover: generate Lamport keypair and build ProverSetupPackage.
pub fn babe_prover_keygen(rng: &mut impl RngCore, pk_p: BtcPk) -> (LamportSk, ProverSetupPackage) {
    let (lsk_p, lpk_p) = lamport_keygen(rng);
    let lpk_p_commit = lamport_pk_commit(&lpk_p);
    let pkg = ProverSetupPackage { lpk_p, lpk_p_commit, pk_p };
    (lsk_p, pkg)
}

// ─── Setup phase ─────────────────────────────────────────────────────────────

/// Verifier: enc_setup + garble circuit + build adaptor table + compute epk.
#[cfg(feature = "garbled")]
pub fn babe_verifier_setup(
    vk: &Groth16VerifyingKey<Bn254>,
    public_inputs: &[Fr],
) -> (VerifierSetupPackage, BabeVerifierPrivate) {
    use crate::verifier::BABEInstance;
    use garbled_snark_verifier::core::utils::reset_gid;

    reset_gid();
    let start = std::time::Instant::now();
    let mut verifier = BABEInstance::new_from_seed(rand::random());
    verifier.enc_setup(vk, public_inputs).expect("enc_setup failed");
    let elapsed = start.elapsed();
    println!("Verifier setup (enc_setup + garble + adaptor table) completed in {:.2?}", elapsed);

    let gc_ciphertexts = std::mem::take(&mut verifier.ciphertexts);

    // Constant wire labels: wire 0 = false → 0-label; wire 1 = true → 1-label.
    let const_label_0 = verifier.secrets.constant_0labels[0].0;
    let const_label_1 = (verifier.secrets.constant_0labels[1] ^ verifier.secrets.delta).0;

    let start = std::time::Instant::now();
    let epk = compute_epk(&verifier.secrets.encoding_keys);
    let h_ek = epk.commit();
    let h_msg = derive_hashlock(&verifier.secrets.msg);

    let elapsed = start.elapsed();
    println!("Computed epk and h_ek in {:.2?}", elapsed);

    let mut circuit = verifier.garbled_circuit;
    circuit.reset_circuit_except_constants();
    let gc_output_indices = verifier.gc_output_indices;

    let pkg = VerifierSetupPackage {
        ct_setup: verifier.ct_setup.clone(),
        gc_ciphertexts,
        adaptor_table: verifier.adaptor_table,
        epk,
        h_ek,
        h_msg,
        constant_labels: [const_label_0, const_label_1],
        circuit,
        gc_output_indices,
    };

    let private = BabeVerifierPrivate {
        r: verifier.secrets.r,
        msg: verifier.secrets.msg,
        encoding_keys: verifier.secrets.encoding_keys,
        constant_0labels: verifier.secrets.constant_0labels,
        delta: verifier.secrets.delta,
    };

    (pkg, private)
}

// ─── Presign exchange ─────────────────────────────────────────────────────────

/// Prover presigns tx_ChallengeAssert and tx_NoWithdraw.
/// In production: BTC Schnorr Sign(sk_P, tx_skeleton).
pub fn babe_prover_presign() -> ProverPresigs {
    ProverPresigs {
        sig_challenge_assert: BabeBtcSig::ProverPresigChallengeAssert,
        sig_no_withdraw: BabeBtcSig::ProverPresigNoWithdraw,
    }
}

/// Verifier presigns tx_Assert (given to Prover for off-chain verification)
/// and tx_Withdraw (given to Prover for the happy path).
pub fn babe_verifier_presign() -> VerifierPresigs {
    VerifierPresigs {
        sig_assert: BabeBtcSig::VerifierPresigAssert,
        sig_withdraw: BabeBtcSig::VerifierPresigWithdraw,
    }
}

/// Prover verifies the Verifier's presigs before posting tx_Deposit.
/// In production: Sig_BTC.Verify(pk_V, tx_skeleton, sig).
pub fn babe_verify_verifier_presigs(presigs_v: &VerifierPresigs) -> bool {
    presigs_v.sig_assert == BabeBtcSig::VerifierPresigAssert
        && presigs_v.sig_withdraw == BabeBtcSig::VerifierPresigWithdraw
}

/// Verifier verifies the Prover's presigs before completing setup.
/// In production: Sig_BTC.Verify(pk_P, tx_skeleton, sig).
pub fn babe_verify_prover_presigs(presigs_p: &ProverPresigs) -> bool {
    presigs_p.sig_challenge_assert == BabeBtcSig::ProverPresigChallengeAssert
        && presigs_p.sig_no_withdraw == BabeBtcSig::ProverPresigNoWithdraw
}


// ─── Deposit phase ───────────────────────────────────────────────────────────

pub fn babe_build_deposit_lock(pk_p: BtcPk, pk_v: BtcPk, amount: u64) -> TxDepositLock {
    TxDepositLock { pk_p, pk_v, amount }
}

// ─── Assert phase (Prover posts π₁) ─────────────────────────────────────────

/// Prover signs π₁ with lsk_P → satisfies CheckLampSig(lpk_P) on the input UTXO.
pub fn babe_prover_assert(proof: &Groth16Proof<Bn254>, lsk_p: &LamportSk) -> TxAssertWitness {
    let pi1 = proof.a;
    let mut pi1_bytes = Vec::new();
    pi1.serialize_compressed(&mut pi1_bytes).expect("serialize π₁");
    let lamport_sig = lamport_sign(lsk_p, &pi1);
    TxAssertWitness { pi1: pi1_bytes, lamport_sig }
}

// ─── ChallengeAssert phase (Verifier reveals labels L) ───────────────────────

/// Verifier: verify Lamport sig in assert_witness, compute input labels L for π₁.
/// Returns None if the Lamport signature is invalid.
#[cfg(feature = "garbled")]
pub fn babe_verifier_challenge_assert(
    assert_witness: &TxAssertWitness,
    lpk_p: &LamportPk,
    verifier_private: &BabeVerifierPrivate,
    sig_p_presig: BabeBtcSig,
) -> Option<TxChallengeAssertWitness> {
    let pi1 = G1Affine::deserialize_compressed(assert_witness.pi1.as_slice()).ok()?;

    // This verification happens locally. On-chain, the script Assert already checked this.
    if !lamport_verify(lpk_p, &pi1, &assert_witness.lamport_sig) {
        return None;
    }

    let bits = pi1_to_bits(&pi1);
    let delta = verifier_private.delta;
    let input_labels: Vec<[u8; 16]> = bits.iter().enumerate().map(|(i, &b)| {
        let key = verifier_private.encoding_keys[i];
        if b { (key ^ delta).0 } else { key.0 }
    }).collect();

    Some(TxChallengeAssertWitness {
        input_labels,
        lamport_sig: assert_witness.lamport_sig.clone(),
        sig_v: BabeBtcSig::VerifierLiveSig,
        sig_p: sig_p_presig,
    })
}

// ─── WronglyChallenged phase (Prover evaluates GC, decrypts msg) ─────────────

/// Prover: evaluate GC with labels L → adaptor table → r·π₁ → decrypt msg.
/// Satisfies HashLock(h_msg) ∧ CheckSig(pk_P) on tx_ChallengeAssert output 0.
#[cfg(feature = "garbled")]
pub fn babe_prover_wrongly_challenged(
    challenge_witness: &TxChallengeAssertWitness,
    proof: &Groth16Proof<Bn254>,
    verifier_pkg: &mut VerifierSetupPackage,
) -> TxWronglyChallengedWitness {
    use ark_ff::{One, Zero};
    use garbled_snark_verifier::bag::S;
    use crate::dre::matrices::u_bar_vec;
    use ark_bn254::G1Projective;

    let pi1 = proof.a;
    let pi2 = proof.b.into_group();
    let pi3 = proof.c.into_group();

    // 1. Use the pre-built circuit from verifier_pkg (already reset after verifier setup).
    let circuit = &mut verifier_pkg.circuit;
    if !circuit.is_fresh() {
        circuit.reset_circuit_except_constants();
    }

    let gc_output_indices = &verifier_pkg.gc_output_indices;

    // 2. Set constant wire labels from verifier's setup package.
    circuit.0[0].borrow_mut().label = Some(S(verifier_pkg.constant_labels[0]));
    circuit.0[1].borrow_mut().label = Some(S(verifier_pkg.constant_labels[1]));

    // 3. Set input wire labels from the challenge witness (L from verifier).
    for (i, &label) in challenge_witness.input_labels.iter().enumerate() {
        circuit.0[2 + i].borrow_mut().label = Some(S(label));
    }

    // 4. Set witness values (π₁ bits) and evaluate all gates.
    let bits = pi1_to_bits(&pi1);
    circuit.set_witness_value(&bits);
    for gate in &mut circuit.1 {
        gate.evaluate();
    }

    // 5. Garbled evaluation: propagate labels through encrypted gate tables.
    circuit.garbled_evaluate_without_delta(&verifier_pkg.gc_ciphertexts);

    // 6. Collect output labels for all L output wires.
    let output_labels: Vec<[u8; 16]> = gc_output_indices.iter().map(|i| {
        circuit.0[*i].borrow().get_label().0
    }).collect();

    // 7. Compute ū(π₁) and decrypt adaptor table entries.
    let u_bar = u_bar_vec(&pi1);
    let decrypted_encodings = verifier_pkg.adaptor_table.eval(&output_labels, &u_bar);

    // 8. Decode DRE: weighted sum ∑ 2^i · f_i = r·π₁.
    let mut sum = G1Projective::zero();
    let mut weight = ark_bn254::Fr::one();
    for decoding in decrypted_encodings {
        let (x, y, z) = decoding.f_i;
        sum += G1Projective::new(x, y, z) * weight;
        weight += weight;
    }

    // 9. Decrypt: msg = ct3 ⊕ h(e(ct1, π₂) - e(π₃, ct2)).
    //    BABEInstance::enc_setup uses blake3(rY) as the mask (babe::h), so we must use
    //    the same function here rather than we_known_pi1_dec (which uses ro_from_pairing_bytes).
    use ark_serialize::CanonicalSerialize as _;
    let ct1_affine = sum.into_affine();
    let ct2_affine = G2Affine::deserialize_compressed(
        verifier_pkg.ct_setup.ct2_r_delta_g2.as_slice()
    ).expect("deserialize ct2");
    let r_y = Bn254::pairing(ct1_affine, pi2) - Bn254::pairing(pi3, ct2_affine.into_group());
    let mut ry_bytes = Vec::new();
    r_y.serialize_compressed(&mut ry_bytes).expect("serialize rY");
    let mask = h(&ry_bytes);
    let mut msg = [0u8; 32];
    for (i, byte) in verifier_pkg.ct_setup.ct3_masked_msg.iter().enumerate() {
        msg[i] = byte ^ mask[i];
    }

    TxWronglyChallengedWitness { sig_p: BabeBtcSig::ProverLiveSig, msg }
}

// ─── NoWithdraw phase (Verifier blocks withdrawal) ───────────────────────────

pub fn babe_verifier_no_withdraw(sig_p_presig: BabeBtcSig) -> TxNoWithdrawWitness {
    TxNoWithdrawWitness {
        input0_sig_p: sig_p_presig,
        input0_sig_v: BabeBtcSig::VerifierLiveSig,
        input1_sig_v: BabeBtcSig::VerifierLiveSig,
    }
}

// ─── Withdraw phase (Prover withdraws after RelTimelock(Δ₂)) ─────────────────

pub fn babe_prover_withdraw(sig_v_presig: BabeBtcSig) -> TxWithdrawWitness {
    TxWithdrawWitness {
        input0_sig_p: BabeBtcSig::ProverLiveSig,
        input0_sig_v: sig_v_presig.clone(),
        input1_sig_p: BabeBtcSig::ProverLiveSig,
        input1_sig_v: sig_v_presig,
    }
}

// ─── Utility functions (WE primitives) ───────────────────────────────────────

pub fn h(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// h_msg = SHA256(secret_msg) — the hashlock value.
pub fn derive_hashlock(secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.finalize().into()
}

fn groth16_vk_x(
    vk: &Groth16VerifyingKey<Bn254>,
    public_inputs: &[Fr],
) -> Option<ark_bn254::G1Projective> {
    if vk.gamma_abc_g1.len() != public_inputs.len() + 1 {
        return None;
    }
    let mut acc = vk.gamma_abc_g1[0].into_group();
    for (i, x) in public_inputs.iter().enumerate() {
        acc += vk.gamma_abc_g1[i + 1].into_group() * *x;
    }
    Some(acc)
}

fn g1_to_ser(p: ark_bn254::G1Projective) -> Vec<u8> {
    let mut out = Vec::new();
    p.into_affine().serialize_compressed(&mut out).expect("serialize g1");
    out
}

fn g2_to_ser(p: ark_bn254::G2Projective) -> Vec<u8> {
    let mut out = Vec::new();
    p.into_affine().serialize_compressed(&mut out).expect("serialize g2");
    out
}

fn g1_from_ser_checked(v: &[u8]) -> Option<ark_bn254::G1Projective> {
    let a = G1Affine::deserialize_compressed(v).ok()?;
    if a.is_zero() || !a.is_on_curve() || !a.is_in_correct_subgroup_assuming_on_curve() {
        return None;
    }
    Some(a.into_group())
}

fn g2_from_ser_checked(v: &[u8]) -> Option<ark_bn254::G2Projective> {
    let a = G2Affine::deserialize_compressed(v).ok()?;
    if a.is_zero() || !a.is_on_curve() || !a.is_in_correct_subgroup_assuming_on_curve() {
        return None;
    }
    Some(a.into_group())
}

fn derive_stream_xor_keyed(key: [u8; 32], nonce: [u8; 12], msg_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; msg_len];
    let mut ctr: u32 = 0;
    let mut off = 0usize;
    while off < msg_len {
        let mut blk = b"babe-we-stream".to_vec();
        blk.extend_from_slice(&key);
        blk.extend_from_slice(&nonce);
        blk.extend_from_slice(&ctr.to_le_bytes());
        let hblk = h(&blk);
        let take = core::cmp::min(32, msg_len - off);
        out[off..off + take].copy_from_slice(&hblk[..take]);
        ctr += 1;
        off += take;
    }
    out
}

fn ro_from_pairing_bytes(seed: &[u8], msg_len: usize) -> Vec<u8> {
    let key = h(seed);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&h(&[b"babe-we-known-pi1-ro-nonce".as_slice(), seed].concat())[..12]);
    derive_stream_xor_keyed(key, nonce, msg_len)
}

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

// ─── Full e2e harness ─────────────────────────────────────────────────────────

#[derive(Copy, Clone)]
struct DummyMulCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyMulCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            Ok(self.a.ok_or(SynthesisError::AssignmentMissing)?
                * self.b.ok_or(SynthesisError::AssignmentMissing)?)
        })?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        Ok(())
    }
}

/// Run the full BABE e2e happy path:
/// Setup → Deposit → Assert → ChallengeAssert → WronglyChallenged.
#[cfg(feature = "garbled")]
pub fn run_babe_e2e_with_one_instance() -> BabeE2ERun {
    let session_id = h(b"babe:e2e:session");
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);

    // 1. Groth16 setup and prove: a * b = c.
    let a = Fr::from(7u64);
    let b = Fr::from(9u64);
    let circ = DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) };
    let (groth16_pk, vk) = ark_groth16::Groth16::<Bn254>::setup(circ, &mut rng).expect("groth16 setup");
    let proof = ark_groth16::Groth16::<Bn254>::prove(
        &groth16_pk,
        DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) },
        &mut rng,
    ).expect("groth16 prove");
    let public_inputs = vec![a * b];

    // 2. Verifier setup: enc_setup + garble + adaptor table + epk.
    let (mut verifier_pkg, verifier_private) =
        babe_verifier_setup(&vk, &public_inputs);

    // Verifier setup package sizes.
    // {
    //     let ct_setup_bytes = verifier_pkg.ct_setup.ct2_r_delta_g2.len()
    //         + verifier_pkg.ct_setup.ct3_masked_msg.len();
    //
    //     let gc_ct_bytes = verifier_pkg.gc_ciphertexts.iter()
    //         .filter(|c| c.is_some()).count() * 16;
    //
    //     // Each SparseAdaptorEntry: (x.len + y.len + z.len) nonzero cols × 1 ct × 32 bytes/ct
    //     //                        + 3 rows × 1 offset (Fq = 32 bytes) per row
    //     let adaptor_bytes = if let Some(entry) = verifier_pkg.adaptor_table.entries.first() {
    //         let cts_per_entry = entry.x.cts.len() + entry.y.cts.len() + entry.z.cts.len();
    //         let n_entries = verifier_pkg.adaptor_table.entries.len();
    //         n_entries * cts_per_entry * 32   // ciphertexts: 1 × 32 bytes each
    //         + n_entries * 3 * 32             // offsets: 3 Fq per entry, 32 bytes each
    //     } else { 0 };
    //
    //     let epk_bytes = verifier_pkg.epk.0.len() * 2 * 32;
    //
    //     // Circuit in-memory sizes (64-bit):
    //     let circuit_bytes_after_reset = verifier_pkg.circuit.size_in_bytes();
    //
    //     println!("--- VerifierSetupPackage sizes ---");
    //     println!("  ct_setup:        {:>10} bytes ({:.2} KB)", ct_setup_bytes, ct_setup_bytes as f64 / 1024.0);
    //     println!("  gc_ciphertexts:  {:>10} bytes ({:.2} MB)", gc_ct_bytes, gc_ct_bytes as f64 / 1_048_576.0);
    //     println!("  adaptor_table:   {:>10} bytes ({:.2} MB)", adaptor_bytes, adaptor_bytes as f64 / 1_048_576.0);
    //     println!("  epk:             {:>10} bytes ({:.2} KB)", epk_bytes, epk_bytes as f64 / 1024.0);
    //     println!("  h_ek + h_msg:    {:>10} bytes", 64);
    //     println!("  constant_labels: {:>10} bytes", 32);
    //     println!("  circuit struct:  {:>10} bytes ({:.2} MB)  after reset",
    //         circuit_bytes_after_reset, circuit_bytes_after_reset as f64 / 1_048_576.0);
    //     let total = ct_setup_bytes + gc_ct_bytes + adaptor_bytes + epk_bytes + 64 + 32 + circuit_bytes_after_reset;
    //     println!("  TOTAL:           {:>10} bytes ({:.2} MB)", total, total as f64 / 1_048_576.0);
    // }

    // 3. Prover setup: generate Lamport keypair.
    let pk_p = BtcPk([0u8; 33]); // stub BTC pubkey
    let (lsk_p, prover_pkg) = babe_prover_keygen(&mut rng, pk_p.clone());

    // // Prover setup package sizes.
    // {
    //     // lpk_p: LAMPORT_N entries, each [[u8;32];2] = 2×32 bytes.
    //     let lpk_bytes = prover_pkg.lpk_p.0.len() * 2 * 32;
    //     // lpk_p_commit: [u8;32]
    //     let commit_bytes = 32;
    //     // pk_p: BtcPk([u8;33])
    //     let pk_p_bytes = 33;
    //     let total = lpk_bytes + commit_bytes + pk_p_bytes;
    //     println!("--- ProverSetupPackage sizes ---");
    //     println!("  lpk_p:           {:>10} bytes ({:.2} KB)", lpk_bytes, lpk_bytes as f64 / 1024.0);
    //     println!("  lpk_p_commit:    {:>10} bytes", commit_bytes);
    //     println!("  pk_p:            {:>10} bytes", pk_p_bytes);
    //     println!("  TOTAL:           {:>10} bytes ({:.2} KB)", total, total as f64 / 1024.0);
    // }

    // 4. Presign exchange.
    let pk_v = BtcPk([1u8; 33]); // stub BTC pubkey
    let prover_presigs = babe_prover_presign();
    let verifier_presigs = babe_verifier_presign();

    // 5. Both parties verify the other's presigs before depositing.
    assert!(babe_verify_verifier_presigs(&verifier_presigs), "verifier presigs invalid");
    assert!(babe_verify_prover_presigs(&prover_presigs), "prover presigs invalid");

    // 6. Deposit.
    let deposit_lock = babe_build_deposit_lock(pk_p, pk_v, 100_000);

    // Proving phase

    // 7. Assert: Prover posts π₁ + Lamport sig. Script Assert checks Lamport sig against lpk_P and π₁.
    let assert_witness = babe_prover_assert(&proof, &lsk_p);
    println!("tx_Assert witness:            {} bytes", assert_witness.size_bytes());

    // 8. ChallengeAssert: Verifier reveals labels L for π₁.
    // ChallengeAssert script check L against prover lamport sig.
    let challenge_witness = babe_verifier_challenge_assert(
        &assert_witness,
        &prover_pkg.lpk_p,
        &verifier_private,
        prover_presigs.sig_challenge_assert.clone(),
    ).expect("Lamport sig invalid in assert witness");
    println!("tx_ChallengeAssert witness:   {} bytes", challenge_witness.size_bytes());

    // 9. WronglyChallenged: Prover evaluates GC and decrypts msg.
    let wc_witness = babe_prover_wrongly_challenged(
        &challenge_witness,
        &proof,
        &mut verifier_pkg,
    );
    println!("tx_WronglyChallenged witness: {} bytes", wc_witness.size_bytes());

    // 10. Verify: msg must satisfy the hashlock.
    assert_eq!(
        derive_hashlock(&wc_witness.msg),
        verifier_pkg.h_msg,
        "decrypted msg does not match h_msg"
    );

    BabeE2ERun {
        session_id,
        deposit_lock,
        prover_setup_pkg: prover_pkg,
        h_ek: verifier_pkg.h_ek,
        h_msg: verifier_pkg.h_msg,
        prover_presigs,
        verifier_presigs,
        assert_witness,
        challenge_assert_witness: challenge_witness,
        wrongly_challenged_witness: wc_witness,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ff::UniformRand;

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
        let pi1 = {
            use ark_ff::UniformRand;
            G1Affine::from(ark_bn254::G1Projective::rand(&mut rng))
        };
        let (lsk, lpk) = lamport_keygen(&mut rng);
        let sig = lamport_sign(&lsk, &pi1);
        assert!(lamport_verify(&lpk, &pi1, &sig));

        // Wrong pi1 must fail.
        let pi1_other = G1Affine::from(ark_bn254::G1Projective::rand(&mut rng));
        assert!(!lamport_verify(&lpk, &pi1_other, &sig));
    }

    #[test]
    fn onchain_sizes() {
        assert_eq!(LAMPORT_SIG_BYTES, 508 * 16);

        // Construct minimal witnesses to call size_bytes().
        let dummy_sig = BabeBtcSig::ProverLiveSig;
        let dummy_lamport = LamportSig(vec![[0u8; 16]; LAMPORT_N]);

        let assert_w = TxAssertWitness {
            pi1: vec![0u8; PI1_BYTES],
            lamport_sig: dummy_lamport.clone(),
        };
        assert_eq!(assert_w.size_bytes(), 8161);

        let challenge_w = TxChallengeAssertWitness {
            input_labels: vec![[0u8; 16]; LAMPORT_N],
            lamport_sig: dummy_lamport,
            sig_v: dummy_sig.clone(),
            sig_p: dummy_sig.clone(),
        };
        assert_eq!(challenge_w.size_bytes(), 16320);

        let wc_w = TxWronglyChallengedWitness { sig_p: dummy_sig.clone(), msg: [0u8; 32] };
        assert_eq!(wc_w.size_bytes(), 64);

        let nw_w = TxNoWithdrawWitness {
            input0_sig_p: dummy_sig.clone(),
            input0_sig_v: dummy_sig.clone(),
            input1_sig_v: dummy_sig.clone(),
        };
        assert_eq!(nw_w.size_bytes(), 96);

        let wd_w = TxWithdrawWitness {
            input0_sig_p: dummy_sig.clone(),
            input0_sig_v: dummy_sig.clone(),
            input1_sig_p: dummy_sig.clone(),
            input1_sig_v: dummy_sig,
        };
        assert_eq!(wd_w.size_bytes(), 128);
    }

    #[test]
    fn we_encsetup_dec_roundtrip() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
        let a = Fr::from(3u64);
        let b = Fr::from(7u64);
        let (pk, vk) = ark_groth16::Groth16::<Bn254>::setup(
            DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) },
            &mut rng,
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
