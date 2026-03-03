use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof as Groth16Proof, VerifyingKey as Groth16VerifyingKey};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const BABE_POLICY_DOMAIN_SEP: &[u8] = b"babe-policy";
pub const BABE_ASSERT_DOMAIN_SEP: &[u8] = b"babe-assert";
pub const BABE_WE_FINAL_DOMAIN_SEP: &[u8] = b"babe-we-final";
pub const BABE_PHASE_DOMAIN_SEP: &[u8] = b"babe-phase";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePathNode {
    pub sibling: [u8; 32],
    pub sibling_is_left: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BabePhase {
    DepositCommitted = 0,
    WithdrawAsserted = 1,
    DisproveChallenged = 2,
    Settled = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabePhaseState {
    pub session_id: [u8; 32],
    pub assert_commit_root: [u8; 32],
    pub phase: BabePhase,
    pub step: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabePolicyInputs {
    pub session_id: [u8; 32],
    pub vk_hash: [u8; 32],
    pub relation_id: [u8; 32],
    pub we_params_hash: [u8; 32],
    pub gc_small_params_hash: [u8; 32],
    pub timeout_assert_blocks: u32,
    pub timeout_challenge_blocks: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeAssertInputs {
    pub session_id: [u8; 32],
    pub vk_hash: [u8; 32],
    pub public_input_hash: [u8; 32],
    pub proof_binding_hash: [u8; 32],
    pub root_babe_setup: [u8; 32],
    pub root_babe_instance: [u8; 32],
    pub babe_hashlock: [u8; 32],
    pub pi1_binding_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeChallengeReveal {
    pub assert_commit_root: [u8; 32],
    pub session_id: [u8; 32],
    pub babe_hashlock: [u8; 32],
    pub revealed_secret: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeDisproveWitness {
    pub reveal: BabeChallengeReveal,
    pub reveal_commit: [u8; 32],
    pub root_babe_setup: [u8; 32],
    pub hmsg_leaf: Vec<u8>,
    pub hmsg_leaf_proof: Vec<MerklePathNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeSetupArtifacts {
    pub ct_setup: Vec<u8>,
    pub ctgc_small: Vec<u8>,
    pub ek_commit: [u8; 32],
    pub setup_gc_binding_commit: [u8; 32],
    pub hmsg: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeProtocolBundle {
    pub policy: BabePolicyInputs,
    pub policy_commit: [u8; 32],
    pub setup: BabeSetupArtifacts,
    pub assert_inputs: BabeAssertInputs,
    pub assert_commit_root: [u8; 32],
    pub disprove_witness: BabeDisproveWitness,
    pub phase_trace: Vec<BabePhaseState>,
}

#[derive(Debug, Clone)]
pub struct BabeE2ERun {
    pub statement_hash: [u8; 32],
    pub hmsg: [u8; 32],
    pub protocol_bundle: BabeProtocolBundle,
    pub ct_setup: WeKnownPi1SetupCt,
    pub ctprove: WeKnownPi1ProveCt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Groth16RelationBinding {
    pub vk_hash: [u8; 32],
    pub proof_binding_hash: [u8; 32],
    pub public_input_hash: [u8; 32],
    pub relation_id: [u8; 32],
    pub statement_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeKnownPi1SetupCt {
    pub ct2_r_delta_g2: Vec<u8>,
    pub ct3_masked_msg: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeKnownPi1ProveCt {
    pub ct1_r_pi1: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeNoCatScriptArtifacts {
    pub assert_script_pseudo: String,
    pub disprove_script_pseudo: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverCtSetupPackage {
    pub statement_hash: [u8; 32],
    pub hmsg: [u8; 32],
    pub ct_setup: WeKnownPi1SetupCt,
    pub ctprove: WeKnownPi1ProveCt,
    pub pi1: Vec<u8>,
    pub pi2: Vec<u8>,
    pub pi3: Vec<u8>,
    pub paper_we_commit: [u8; 32],
    pub ek_commit: [u8; 32],
    pub setup_gc_binding_commit: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedCtSetup {
    pub statement_hash: [u8; 32],
    pub hmsg: [u8; 32],
    pub ct_setup: WeKnownPi1SetupCt,
    pub ctprove: WeKnownPi1ProveCt,
    pub pi1_binding_hash: [u8; 32],
    pub gc_small_params_hash: [u8; 32],
    pub paper_we_commit: [u8; 32],
    pub setup_artifacts: BabeSetupArtifacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositCommitments {
    pub policy: BabePolicyInputs,
    pub policy_commit: [u8; 32],
    pub root_babe_setup: [u8; 32],
    pub root_babe_instance: [u8; 32],
    pub assert_inputs: BabeAssertInputs,
    pub assert_commit_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BabeSetupVerifyError {
    StatementHashMismatch,
    HashlockMismatch,
    PaperWeCommitMismatch,
    PaperWeDecryptFailed,
    SetupGcBindingInvalid,
}

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
            let av = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let bv = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(av * bv)
        })?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        Ok(())
    }
}

pub fn h(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

fn hash_leaf(leaf_data: &[u8]) -> [u8; 32] {
    let mut buf = b"leaf".to_vec();
    buf.extend_from_slice(leaf_data);
    h(&buf)
}

fn hash_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut buf = b"node".to_vec();
    buf.extend_from_slice(&left);
    buf.extend_from_slice(&right);
    h(&buf)
}

pub fn merkle_root_from_leaves(leaves: &[Vec<u8>]) -> [u8; 32] {
    if leaves.is_empty() {
        return h(b"empty-merkle");
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| hash_leaf(leaf)).collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty level");
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hash_node(pair[0], pair[1]));
        }
        level = next;
    }
    level[0]
}

pub fn merkle_root_and_proof(
    leaves: &[Vec<u8>],
    leaf_index: usize,
) -> Option<([u8; 32], Vec<MerklePathNode>)> {
    if leaves.is_empty() || leaf_index >= leaves.len() {
        return None;
    }
    let mut proof = Vec::<MerklePathNode>::new();
    let mut index = leaf_index;
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| hash_leaf(leaf)).collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty level");
            level.push(last);
        }
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        let sibling_is_left = sibling_index < index;
        proof.push(MerklePathNode { sibling: level[sibling_index], sibling_is_left });

        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hash_node(pair[0], pair[1]));
        }
        index /= 2;
        level = next;
    }
    Some((level[0], proof))
}

pub fn merkle_verify_path(
    leaf_data: &[u8],
    proof: &[MerklePathNode],
    expected_root: [u8; 32],
) -> bool {
    let mut acc = hash_leaf(leaf_data);
    for node in proof {
        acc = if node.sibling_is_left {
            hash_node(node.sibling, acc)
        } else {
            hash_node(acc, node.sibling)
        };
    }
    acc == expected_root
}

pub fn derive_hashlock(secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    let out = hasher.finalize();
    let mut v = [0u8; 32];
    v.copy_from_slice(&out);
    v
}

fn hex_bytes(v: &[u8]) -> String {
    v.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn btc_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn btc_hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut buf = b"leaf".to_vec();
    buf.extend_from_slice(data);
    btc_sha256(&buf)
}

fn btc_hash_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut buf = b"node".to_vec();
    buf.extend_from_slice(&left);
    buf.extend_from_slice(&right);
    btc_sha256(&buf)
}

pub fn build_babe_scripts_nocat(
    assert_commit_root: [u8; 32],
    session_id: [u8; 32],
    policy_commit: [u8; 32],
    root_babe_setup: [u8; 32],
    root_babe_instance: [u8; 32],
    babe_hashlock: [u8; 32],
    reveal_commit: [u8; 32],
    secret_sha256: [u8; 32],
    hmsg_leaf: &[u8],
    sibling0: [u8; 32],
    sibling1: [u8; 32],
) -> BabeNoCatScriptArtifacts {
    // no-cat profile: all Merkle intermediate hashes are precomputed and supplied/checked
    // as fixed 32-byte values in witness/constants.
    let hmsg_leaf_hash_btc = btc_hash_leaf(hmsg_leaf);
    let parent = btc_hash_node(hmsg_leaf_hash_btc, sibling0);
    let root_btc = btc_hash_node(parent, sibling1);

    let assert_script_pseudo = format!(
        "# BABE assert script (no-cat)\n\
         # witness: assert_root session_id policy_commit root_setup root_instance hashlock\n\
         PUSH {}\nOP_EQUALVERIFY\n\
         PUSH {}\nOP_EQUALVERIFY\n\
         PUSH {}\nOP_EQUALVERIFY\n\
         PUSH {}\nOP_EQUALVERIFY\n\
         PUSH {}\nOP_EQUALVERIFY\n\
         PUSH {}\nOP_EQUAL\n",
        hex_bytes(&babe_hashlock),
        hex_bytes(&root_babe_instance),
        hex_bytes(&root_babe_setup),
        hex_bytes(&policy_commit),
        hex_bytes(&session_id),
        hex_bytes(&assert_commit_root),
    );

    let disprove_script_pseudo = format!(
        "# BABE disprove script (no-cat)\n\
         # witness: secret hashlock assert_root session_id hmsg_leaf_hash sib0 sib1 root_setup_btc reveal_commit\n\
         PUSH {}\nOP_EQUALVERIFY  # reveal_commit\n\
         PUSH {}\nOP_EQUALVERIFY  # root_setup_btc\n\
         PUSH {}\nOP_EQUALVERIFY  # sibling1\n\
         PUSH {}\nOP_EQUALVERIFY  # sibling0\n\
         PUSH {}\nOP_EQUALVERIFY  # hmsg_leaf_hash\n\
         PUSH {}\nOP_EQUALVERIFY  # session_id\n\
         PUSH {}\nOP_EQUALVERIFY  # assert_root\n\
         PUSH {}\nOP_EQUALVERIFY  # hashlock\n\
         OP_DUP OP_SHA256 PUSH {} OP_EQUALVERIFY\n\
         OP_SIZE 32 OP_NUMEQUALVERIFY\n\
         OP_DROP OP_TRUE\n",
        hex_bytes(&reveal_commit),
        hex_bytes(&root_btc),
        hex_bytes(&sibling1),
        hex_bytes(&sibling0),
        hex_bytes(&hmsg_leaf_hash_btc),
        hex_bytes(&session_id),
        hex_bytes(&assert_commit_root),
        hex_bytes(&babe_hashlock),
        hex_bytes(&secret_sha256),
    );

    BabeNoCatScriptArtifacts { assert_script_pseudo, disprove_script_pseudo }
}

pub fn verify_hashlock_reveal(revealed_secret: &[u8], babe_hashlock: [u8; 32]) -> bool {
    derive_hashlock(revealed_secret) == babe_hashlock
}

pub fn compute_challenge_reveal_commit(reveal: &BabeChallengeReveal) -> [u8; 32] {
    let mut buf = b"babe-challenge-reveal".to_vec();
    buf.extend_from_slice(&reveal.assert_commit_root);
    buf.extend_from_slice(&reveal.session_id);
    buf.extend_from_slice(&reveal.babe_hashlock);
    buf.extend_from_slice(&(reveal.revealed_secret.len() as u32).to_le_bytes());
    buf.extend_from_slice(&reveal.revealed_secret);
    h(&buf)
}

pub fn verify_challenge_reveal_binding(
    reveal: &BabeChallengeReveal,
    expected_assert_commit_root: [u8; 32],
    expected_session_id: [u8; 32],
) -> bool {
    reveal.assert_commit_root == expected_assert_commit_root
        && reveal.session_id == expected_session_id
}

pub fn verify_babe_disprove_witness(
    witness: &BabeDisproveWitness,
    expected_assert_commit_root: [u8; 32],
    expected_session_id: [u8; 32],
) -> bool {
    if !verify_challenge_reveal_binding(
        &witness.reveal,
        expected_assert_commit_root,
        expected_session_id,
    ) {
        return false;
    }
    if compute_challenge_reveal_commit(&witness.reveal) != witness.reveal_commit {
        return false;
    }
    if !verify_hashlock_reveal(&witness.reveal.revealed_secret, witness.reveal.babe_hashlock) {
        return false;
    }
    let mut expected_leaf = b"babe:hmsg".to_vec();
    expected_leaf.extend_from_slice(&witness.reveal.babe_hashlock);
    if witness.hmsg_leaf != expected_leaf {
        return false;
    }
    merkle_verify_path(&witness.hmsg_leaf, &witness.hmsg_leaf_proof, witness.root_babe_setup)
}

pub fn compute_babe_phase_state_commit(state: &BabePhaseState) -> [u8; 32] {
    let mut d = Vec::with_capacity(BABE_PHASE_DOMAIN_SEP.len() + 32 + 32 + 1 + 4);
    d.extend_from_slice(BABE_PHASE_DOMAIN_SEP);
    d.extend_from_slice(&state.session_id);
    d.extend_from_slice(&state.assert_commit_root);
    d.push(state.phase.clone() as u8);
    d.extend_from_slice(&state.step.to_le_bytes());
    h(&d)
}

pub fn verify_babe_phase_transition(prev: BabePhase, next: BabePhase) -> bool {
    matches!(
        (prev, next),
        (BabePhase::DepositCommitted, BabePhase::WithdrawAsserted)
            | (BabePhase::WithdrawAsserted, BabePhase::DisproveChallenged)
            | (BabePhase::WithdrawAsserted, BabePhase::Settled)
            | (BabePhase::DisproveChallenged, BabePhase::Settled)
    )
}

pub fn verify_babe_phase_trace(states: &[BabePhaseState]) -> bool {
    if states.is_empty() {
        return false;
    }
    if states[0].phase != BabePhase::DepositCommitted {
        return false;
    }
    for i in 1..states.len() {
        if states[i].session_id != states[0].session_id
            || states[i].assert_commit_root != states[0].assert_commit_root
            || states[i].step != states[i - 1].step + 1
            || !verify_babe_phase_transition(states[i - 1].phase.clone(), states[i].phase.clone())
        {
            return false;
        }
    }
    states.last().map(|s| s.phase == BabePhase::Settled).unwrap_or(false)
}

pub fn compute_babe_policy_commit(input: &BabePolicyInputs) -> [u8; 32] {
    let mut buf = Vec::with_capacity(BABE_POLICY_DOMAIN_SEP.len() + 32 * 5 + 4 + 4);
    buf.extend_from_slice(BABE_POLICY_DOMAIN_SEP);
    buf.extend_from_slice(&input.session_id);
    buf.extend_from_slice(&input.vk_hash);
    buf.extend_from_slice(&input.relation_id);
    buf.extend_from_slice(&input.we_params_hash);
    buf.extend_from_slice(&input.gc_small_params_hash);
    buf.extend_from_slice(&input.timeout_assert_blocks.to_le_bytes());
    buf.extend_from_slice(&input.timeout_challenge_blocks.to_le_bytes());
    h(&buf)
}

pub fn compute_babe_assert_root(input: &BabeAssertInputs) -> [u8; 32] {
    let mut buf = Vec::with_capacity(BABE_ASSERT_DOMAIN_SEP.len() + 32 * 8);
    buf.extend_from_slice(BABE_ASSERT_DOMAIN_SEP);
    buf.extend_from_slice(&input.session_id);
    buf.extend_from_slice(&input.vk_hash);
    buf.extend_from_slice(&input.public_input_hash);
    buf.extend_from_slice(&input.proof_binding_hash);
    buf.extend_from_slice(&input.root_babe_setup);
    buf.extend_from_slice(&input.root_babe_instance);
    buf.extend_from_slice(&input.babe_hashlock);
    buf.extend_from_slice(&input.pi1_binding_hash);
    h(&buf)
}

pub fn hash_public_inputs(inputs: &[ark_bn254::Fr]) -> [u8; 32] {
    let mut d = b"babe:groth16-public-inputs".to_vec();
    d.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
    for i in inputs {
        let le = i.into_bigint().to_bytes_le();
        let mut b = [0u8; 32];
        b.copy_from_slice(&le[..32]);
        d.extend_from_slice(&b);
    }
    h(&d)
}

pub fn hash_groth16_vk(vk: &Groth16VerifyingKey<ark_bn254::Bn254>) -> [u8; 32] {
    let mut out = Vec::new();
    vk.serialize_compressed(&mut out).expect("serialize vk");
    let mut d = b"babe:groth16-vk".to_vec();
    d.extend_from_slice(&out);
    h(&d)
}

pub fn hash_groth16_proof(proof: &Groth16Proof<ark_bn254::Bn254>) -> [u8; 32] {
    let mut out = Vec::new();
    proof.serialize_compressed(&mut out).expect("serialize proof");
    let mut d = b"babe:groth16-proof".to_vec();
    d.extend_from_slice(&out);
    h(&d)
}

pub fn derive_relation_id_from_vk(vk_hash: [u8; 32]) -> [u8; 32] {
    let mut d = b"babe:groth16-relation-id".to_vec();
    d.extend_from_slice(&vk_hash);
    h(&d)
}

pub fn derive_statement_hash_from_relation(
    relation_id: [u8; 32],
    public_input_hash: [u8; 32],
    proof_binding_hash: [u8; 32],
) -> [u8; 32] {
    let mut d = b"babe:groth16-statement".to_vec();
    d.extend_from_slice(&relation_id);
    d.extend_from_slice(&public_input_hash);
    d.extend_from_slice(&proof_binding_hash);
    h(&d)
}

pub fn bind_groth16_relation(
    vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
    proof: &Groth16Proof<ark_bn254::Bn254>,
    public_inputs: &[ark_bn254::Fr],
) -> Groth16RelationBinding {
    let vk_hash = hash_groth16_vk(vk);
    let proof_binding_hash = hash_groth16_proof(proof);
    let public_input_hash = hash_public_inputs(public_inputs);
    let relation_id = derive_relation_id_from_vk(vk_hash);
    let statement_hash =
        derive_statement_hash_from_relation(relation_id, public_input_hash, proof_binding_hash);
    Groth16RelationBinding {
        vk_hash,
        proof_binding_hash,
        public_input_hash,
        relation_id,
        statement_hash,
    }
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
    let a = ark_bn254::G1Affine::deserialize_compressed(v).ok()?;
    if a.is_zero() {
        return None;
    }
    if !a.is_on_curve() {
        return None;
    }
    if !a.is_in_correct_subgroup_assuming_on_curve() {
        return None;
    }
    Some(a.into_group())
}

fn g2_from_ser_checked(v: &[u8]) -> Option<ark_bn254::G2Projective> {
    let a = ark_bn254::G2Affine::deserialize_compressed(v).ok()?;
    if a.is_zero() {
        return None;
    }
    if !a.is_on_curve() {
        return None;
    }
    if !a.is_in_correct_subgroup_assuming_on_curve() {
        return None;
    }
    Some(a.into_group())
}

fn compute_pi1_binding_hash_from_ser(pi1_ser: &[u8]) -> [u8; 32] {
    let mut buf = b"babe:pi1-binding".to_vec();
    buf.extend_from_slice(pi1_ser);
    h(&buf)
}

fn groth16_vk_x(
    vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
    public_inputs: &[ark_bn254::Fr],
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

/// Paper primitive (Construction 1):
/// Encsetup(crs, x, msg; r): ctsetup = (r[delta]_2, RO(rY) + msg), where
/// Y = e([alpha]_1,[beta]_2) * e(vk_x,[gamma]_2).
pub fn we_known_pi1_encsetup(
    vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
    public_inputs: &[ark_bn254::Fr],
    msg: &[u8],
    r_bytes: [u8; 32],
) -> Option<WeKnownPi1SetupCt> {
    let r = ark_bn254::Fr::from_le_bytes_mod_order(&r_bytes);
    let vk_x = groth16_vk_x(vk, public_inputs)?;
    let r_delta = vk.delta_g2.into_group() * r;

    let t1 = ark_bn254::Bn254::pairing(vk.alpha_g1, vk.beta_g2.into_group() * r);
    let t2 = ark_bn254::Bn254::pairing(vk_x, vk.gamma_g2.into_group() * r);
    let r_y = t1 + t2;

    let mut ry_bytes = Vec::new();
    r_y.serialize_compressed(&mut ry_bytes).ok()?;
    let mask = ro_from_pairing_bytes(&ry_bytes, msg.len());
    let ct3 = msg.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect::<Vec<_>>();

    Some(WeKnownPi1SetupCt {
        ct2_r_delta_g2: g2_to_ser(r_delta),
        ct3_masked_msg: ct3,
    })
}

/// Paper primitive (Construction 1):
/// Encprove(crs, pi1; r): ctprove = r*pi1.
pub fn we_known_pi1_encprove(pi1: ark_bn254::G1Projective, r_bytes: [u8; 32]) -> WeKnownPi1ProveCt {
    let r = ark_bn254::Fr::from_le_bytes_mod_order(&r_bytes);
    WeKnownPi1ProveCt {
        ct1_r_pi1: g1_to_ser(pi1 * r),
    }
}

/// Paper primitive (Construction 1):
/// Dec(ctsetup, ctprove, pi2, pi3): msg = ct3 - RO(e(ct1,pi2)/e(pi3,ct2)).
pub fn we_known_pi1_dec(
    ctsetup: &WeKnownPi1SetupCt,
    ctprove: &WeKnownPi1ProveCt,
    pi2: ark_bn254::G2Projective,
    pi3: ark_bn254::G1Projective,
) -> Option<Vec<u8>> {
    let ct1 = g1_from_ser_checked(&ctprove.ct1_r_pi1)?;
    let ct2 = g2_from_ser_checked(&ctsetup.ct2_r_delta_g2)?;
    let left = ark_bn254::Bn254::pairing(ct1, pi2);
    let right = ark_bn254::Bn254::pairing(pi3, ct2);
    let r_y = left - right;

    let mut ry_bytes = Vec::new();
    r_y.serialize_compressed(&mut ry_bytes).ok()?;
    let mask = ro_from_pairing_bytes(&ry_bytes, ctsetup.ct3_masked_msg.len());
    Some(
        ctsetup
            .ct3_masked_msg
            .iter()
            .zip(mask.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>(),
    )
}

pub fn commit_we_known_pi1_ciphertexts(
    ctsetup: &WeKnownPi1SetupCt,
    ctprove: &WeKnownPi1ProveCt,
) -> [u8; 32] {
    let mut d = b"babe:we-known-pi1-ct-commit".to_vec();
    d.extend_from_slice(&(ctsetup.ct2_r_delta_g2.len() as u32).to_le_bytes());
    d.extend_from_slice(&ctsetup.ct2_r_delta_g2);
    d.extend_from_slice(&(ctsetup.ct3_masked_msg.len() as u32).to_le_bytes());
    d.extend_from_slice(&ctsetup.ct3_masked_msg);
    d.extend_from_slice(&(ctprove.ct1_r_pi1.len() as u32).to_le_bytes());
    d.extend_from_slice(&ctprove.ct1_r_pi1);
    h(&d)
}

pub fn compute_setup_gc_binding_commit(
    statement_hash: [u8; 32],
    hmsg: [u8; 32],
    ct_setup: &WeKnownPi1SetupCt,
    ctprove: &WeKnownPi1ProveCt,
    paper_we_commit: [u8; 32],
) -> [u8; 32] {
    let mut c = b"babe:setup-gc-binding".to_vec();
    c.extend_from_slice(&statement_hash);
    c.extend_from_slice(&hmsg);
    c.extend_from_slice(&paper_we_commit);
    c.extend_from_slice(&(ct_setup.ct2_r_delta_g2.len() as u32).to_le_bytes());
    c.extend_from_slice(&ct_setup.ct2_r_delta_g2);
    c.extend_from_slice(&(ct_setup.ct3_masked_msg.len() as u32).to_le_bytes());
    c.extend_from_slice(&ct_setup.ct3_masked_msg);
    c.extend_from_slice(&(ctprove.ct1_r_pi1.len() as u32).to_le_bytes());
    c.extend_from_slice(&ctprove.ct1_r_pi1);
    h(&c)
}

pub fn verify_setup_gc_binding(
    statement_hash: [u8; 32],
    hmsg: [u8; 32],
    ct_setup: &WeKnownPi1SetupCt,
    ctprove: &WeKnownPi1ProveCt,
    paper_we_commit: [u8; 32],
    expected_commit: [u8; 32],
) -> bool {
    compute_setup_gc_binding_commit(statement_hash, hmsg, ct_setup, ctprove, paper_we_commit)
        == expected_commit
}

pub fn build_babe_instance_root(statement_hash: [u8; 32], proof_binding_hash: [u8; 32]) -> [u8; 32] {
    let mut leaf_stmt = b"babe:statement_hash".to_vec();
    leaf_stmt.extend_from_slice(&statement_hash);
    let mut leaf_proof = b"babe:proof_binding_hash".to_vec();
    leaf_proof.extend_from_slice(&proof_binding_hash);
    merkle_root_from_leaves(&[leaf_stmt, leaf_proof])
}

pub fn prover_build_ct_setup(
    statement_hash: [u8; 32],
    hmsg: [u8; 32],
    vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
    public_inputs: &[ark_bn254::Fr],
    pi1: ark_bn254::G1Projective,
    pi2: ark_bn254::G2Projective,
    pi3: ark_bn254::G1Projective,
    r_we_bytes: [u8; 32],
    secret: &[u8],
    ek_commit: [u8; 32],
) -> Option<ProverCtSetupPackage> {
    // Strict-paper path: use WE for Groth16 with known pi1.
    let ct_setup = we_known_pi1_encsetup(vk, public_inputs, secret, r_we_bytes)?;
    let ctprove = we_known_pi1_encprove(pi1, r_we_bytes);
    let paper_we_commit = commit_we_known_pi1_ciphertexts(&ct_setup, &ctprove);
    let setup_gc_binding_commit = compute_setup_gc_binding_commit(
        statement_hash,
        hmsg,
        &ct_setup,
        &ctprove,
        paper_we_commit,
    );
    Some(ProverCtSetupPackage {
        statement_hash,
        hmsg,
        ct_setup,
        ctprove,
        pi1: g1_to_ser(pi1),
        pi2: g2_to_ser(pi2),
        pi3: g1_to_ser(pi3),
        paper_we_commit,
        ek_commit,
        setup_gc_binding_commit,
    })
}

pub fn evaluator_verify_ct_setup(
    pkg: &ProverCtSetupPackage,
    expected_statement_hash: [u8; 32],
    expected_hmsg: [u8; 32],
) -> Result<VerifiedCtSetup, BabeSetupVerifyError> {
    // Adversarial model: every field from prover is untrusted and must be checked.
    if pkg.statement_hash != expected_statement_hash {
        return Err(BabeSetupVerifyError::StatementHashMismatch);
    }
    if pkg.hmsg != expected_hmsg {
        return Err(BabeSetupVerifyError::HashlockMismatch);
    }
    if commit_we_known_pi1_ciphertexts(&pkg.ct_setup, &pkg.ctprove) != pkg.paper_we_commit {
        return Err(BabeSetupVerifyError::PaperWeCommitMismatch);
    }
    let pi2 = g2_from_ser_checked(&pkg.pi2).ok_or(BabeSetupVerifyError::PaperWeDecryptFailed)?;
    let pi3 = g1_from_ser_checked(&pkg.pi3).ok_or(BabeSetupVerifyError::PaperWeDecryptFailed)?;
    let msg = we_known_pi1_dec(&pkg.ct_setup, &pkg.ctprove, pi2, pi3)
        .ok_or(BabeSetupVerifyError::PaperWeDecryptFailed)?;
    if derive_hashlock(&msg) != expected_hmsg {
        return Err(BabeSetupVerifyError::PaperWeDecryptFailed);
    }
    if !verify_setup_gc_binding(
        expected_statement_hash,
        expected_hmsg,
        &pkg.ct_setup,
        &pkg.ctprove,
        pkg.paper_we_commit,
        pkg.setup_gc_binding_commit,
    ) {
        return Err(BabeSetupVerifyError::SetupGcBindingInvalid);
    }

    let setup_artifacts = BabeSetupArtifacts {
        ct_setup: bincode::serialize(&pkg.ct_setup).expect("serialize verified ct_setup"),
        ctgc_small: bincode::serialize(&pkg.ctprove).expect("serialize verified ctprove"),
        ek_commit: pkg.ek_commit,
        setup_gc_binding_commit: pkg.setup_gc_binding_commit,
        hmsg: expected_hmsg,
    };
    let pi1_binding_hash = compute_pi1_binding_hash_from_ser(&pkg.pi1);
    Ok(VerifiedCtSetup {
        statement_hash: expected_statement_hash,
        hmsg: expected_hmsg,
        ct_setup: pkg.ct_setup.clone(),
        ctprove: pkg.ctprove.clone(),
        pi1_binding_hash,
        gc_small_params_hash: h(b"paper-we-known-pi1"),
        paper_we_commit: pkg.paper_we_commit,
        setup_artifacts,
    })
}

pub fn deposit_commit_from_verified_setup(
    verified: &VerifiedCtSetup,
    session_id: [u8; 32],
    vk_hash: [u8; 32],
    relation_id: [u8; 32],
    public_input_hash: [u8; 32],
    proof_binding_hash: [u8; 32],
    we_params_hash: [u8; 32],
    timeout_assert_blocks: u32,
    timeout_challenge_blocks: u32,
) -> DepositCommitments {
    let root_babe_setup = compute_babe_setup_root(&verified.setup_artifacts);
    let root_babe_instance = build_babe_instance_root(verified.statement_hash, proof_binding_hash);
    let assert_inputs = BabeAssertInputs {
        session_id,
        vk_hash,
        public_input_hash,
        proof_binding_hash,
        root_babe_setup,
        root_babe_instance,
        babe_hashlock: verified.hmsg,
        pi1_binding_hash: verified.pi1_binding_hash,
    };
    let assert_commit_root = compute_babe_assert_root(&assert_inputs);
    let policy = BabePolicyInputs {
        session_id,
        vk_hash,
        relation_id,
        we_params_hash,
        gc_small_params_hash: verified.gc_small_params_hash,
        timeout_assert_blocks,
        timeout_challenge_blocks,
    };
    let policy_commit = compute_babe_policy_commit(&policy);
    DepositCommitments {
        policy,
        policy_commit,
        root_babe_setup,
        root_babe_instance,
        assert_inputs,
        assert_commit_root,
    }
}

pub fn build_babe_setup_leaves(art: &BabeSetupArtifacts) -> Vec<Vec<u8>> {
    let mut l0 = b"babe:ct_setup".to_vec();
    l0.extend_from_slice(&(art.ct_setup.len() as u32).to_le_bytes());
    l0.extend_from_slice(&art.ct_setup);

    let mut l1 = b"babe:ctgc_small".to_vec();
    l1.extend_from_slice(&(art.ctgc_small.len() as u32).to_le_bytes());
    l1.extend_from_slice(&art.ctgc_small);

    let mut l2 = b"babe:ek_commit+setup_gc_binding".to_vec();
    l2.extend_from_slice(&art.ek_commit);
    l2.extend_from_slice(&art.setup_gc_binding_commit);

    let mut l3 = b"babe:hmsg".to_vec();
    l3.extend_from_slice(&art.hmsg);

    vec![l0, l1, l2, l3]
}

pub fn compute_babe_setup_root(art: &BabeSetupArtifacts) -> [u8; 32] {
    merkle_root_from_leaves(&build_babe_setup_leaves(art))
}

pub fn verify_babe_protocol_bundle(bundle: &BabeProtocolBundle) -> bool {
    // Paper mapping: verify all protocol layers from policy -> setup -> assert -> disprove.
    if compute_babe_policy_commit(&bundle.policy) != bundle.policy_commit {
        return false;
    }
    if bundle.policy.session_id != bundle.assert_inputs.session_id {
        return false;
    }
    if bundle.policy.vk_hash != bundle.assert_inputs.vk_hash {
        return false;
    }
    if compute_babe_assert_root(&bundle.assert_inputs) != bundle.assert_commit_root {
        return false;
    }
    if bundle.assert_inputs.root_babe_setup != compute_babe_setup_root(&bundle.setup) {
        return false;
    }
    if !verify_babe_disprove_witness(
        &bundle.disprove_witness,
        bundle.assert_commit_root,
        bundle.assert_inputs.session_id,
    ) {
        return false;
    }
    if !verify_babe_phase_trace(&bundle.phase_trace) {
        return false;
    }

    let ct_setup: WeKnownPi1SetupCt = match bincode::deserialize(&bundle.setup.ct_setup) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let ctprove: WeKnownPi1ProveCt = match bincode::deserialize(&bundle.setup.ctgc_small) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let statement_hash = derive_statement_hash_from_relation(
        bundle.policy.relation_id,
        bundle.assert_inputs.public_input_hash,
        bundle.assert_inputs.proof_binding_hash,
    );
    if bundle.assert_inputs.root_babe_instance
        != build_babe_instance_root(statement_hash, bundle.assert_inputs.proof_binding_hash)
    {
        return false;
    }

    let paper_we_commit = bundle.policy.we_params_hash;
    if !verify_setup_gc_binding(
        statement_hash,
        bundle.setup.hmsg,
        &ct_setup,
        &ctprove,
        paper_we_commit,
        bundle.setup.setup_gc_binding_commit,
    ) {
        return false;
    }
    true
}

pub fn run_babe_e2e() -> BabeE2ERun {
    // End-to-end harness:
    // 1) build a real Groth16 relation object;
    // 2) run BABE setup/assert/disprove wiring;
    // 3) verify final bundle.
    let session_id = h(b"e2e:session");
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
    let a = ark_bn254::Fr::from(7u64);
    let b = ark_bn254::Fr::from(9u64);
    let c = a * b;
    let circ = DummyMulCircuit::<ark_bn254::Fr> { a: Some(a), b: Some(b) };
    let (pk, vk) = ark_groth16::Groth16::<ark_bn254::Bn254>::setup(circ, &mut rng).expect("setup");
    let proof = ark_groth16::Groth16::<ark_bn254::Bn254>::prove(
        &pk,
        DummyMulCircuit::<ark_bn254::Fr> { a: Some(a), b: Some(b) },
        &mut rng,
    )
    .expect("prove");
    let public_inputs = vec![c];
    let binding = bind_groth16_relation(&vk, &proof, &public_inputs);
    let vk_hash = binding.vk_hash;
    let relation_id = binding.relation_id;
    let statement_hash = binding.statement_hash;
    let public_input_hash = binding.public_input_hash;
    let proof_binding_hash = binding.proof_binding_hash;

    let secret = b"babe-e2e-secret".to_vec();
    let hmsg = derive_hashlock(&secret);

    let prover_pkg = prover_build_ct_setup(
        statement_hash,
        hmsg,
        &vk,
        &public_inputs,
        proof.a.into_group(),
        proof.b.into_group(),
        proof.c.into_group(),
        h(b"e2e:r-we"),
        &secret,
        h(b"e2e:ek"),
    )
    .expect("prover build");
    let verified = evaluator_verify_ct_setup(&prover_pkg, statement_hash, hmsg)
        .expect("evaluator verify");
    let we_params_hash = verified.paper_we_commit;
    let ct_setup = verified.ct_setup.clone();
    let ctprove = verified.ctprove.clone();
    let recovered = we_known_pi1_dec(&ct_setup, &ctprove, proof.b.into_group(), proof.c.into_group())
        .expect("paper dec in main flow");
    assert_eq!(recovered, secret);

    let setup = verified.setup_artifacts.clone();
    let root_babe_setup = compute_babe_setup_root(&setup);
    let dep = deposit_commit_from_verified_setup(
        &verified,
        session_id,
        vk_hash,
        relation_id,
        public_input_hash,
        proof_binding_hash,
        we_params_hash,
        144,
        72,
    );
    let assert_inputs = dep.assert_inputs.clone();
    let assert_commit_root = dep.assert_commit_root;

    let setup_leaves = build_babe_setup_leaves(&setup);
    let hmsg_leaf = setup_leaves[3].clone();
    let (_, hmsg_leaf_proof) = merkle_root_and_proof(&setup_leaves, 3).expect("proof");
    let reveal = BabeChallengeReveal {
        assert_commit_root,
        session_id,
        babe_hashlock: hmsg,
        revealed_secret: secret.clone(),
    };
    let disprove_witness = BabeDisproveWitness {
        reveal: reveal.clone(),
        reveal_commit: compute_challenge_reveal_commit(&reveal),
        root_babe_setup,
        hmsg_leaf,
        hmsg_leaf_proof,
    };
    assert!(verify_babe_disprove_witness(&disprove_witness, assert_commit_root, session_id));

    let policy = dep.policy.clone();
    let policy_commit = dep.policy_commit;
    let phase_trace = vec![
        BabePhaseState {
            session_id,
            assert_commit_root,
            phase: BabePhase::DepositCommitted,
            step: 0,
        },
        BabePhaseState {
            session_id,
            assert_commit_root,
            phase: BabePhase::WithdrawAsserted,
            step: 1,
        },
        BabePhaseState {
            session_id,
            assert_commit_root,
            phase: BabePhase::DisproveChallenged,
            step: 2,
        },
        BabePhaseState { session_id, assert_commit_root, phase: BabePhase::Settled, step: 3 },
    ];

    let bundle = BabeProtocolBundle {
        policy,
        policy_commit,
        setup,
        assert_inputs,
        assert_commit_root,
        disprove_witness,
        phase_trace,
    };
    assert!(verify_babe_protocol_bundle(&bundle));

    BabeE2ERun { statement_hash, hmsg, protocol_bundle: bundle, ct_setup, ctprove }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_path_roundtrip() {
        let leaves = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let (root, proof) = merkle_root_and_proof(&leaves, 2).expect("proof");
        assert!(merkle_verify_path(&leaves[2], &proof, root));
    }

    #[test]
    fn hashlock_roundtrip() {
        let secret = b"hello-babe";
        let lock = derive_hashlock(secret);
        assert!(verify_hashlock_reveal(secret, lock));
    }

    #[test]
    fn we_known_pi1_roundtrip() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(123);
        let a = ark_bn254::Fr::from(3u64);
        let b = ark_bn254::Fr::from(11u64);
        let c = a * b;
        let circuit = DummyMulCircuit::<ark_bn254::Fr> { a: Some(a), b: Some(b) };
        let (pk, vk) = ark_groth16::Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).expect("setup");
        let proof = ark_groth16::Groth16::<ark_bn254::Bn254>::prove(
            &pk,
            DummyMulCircuit::<ark_bn254::Fr> { a: Some(a), b: Some(b) },
            &mut rng,
        )
        .expect("prove");
        let public_inputs = vec![c];
        let msg = b"known-pi1-message".to_vec();
        let r = h(b"known-pi1-r");

        let ctsetup = we_known_pi1_encsetup(&vk, &public_inputs, &msg, r).expect("encsetup");
        let ctprove = we_known_pi1_encprove(proof.a.into_group(), r);
        let dec =
            we_known_pi1_dec(&ctsetup, &ctprove, proof.b.into_group(), proof.c.into_group())
                .expect("dec");
        assert_eq!(dec, msg);
    }

    #[test]
    fn phase_trace_accepts_valid_and_rejects_invalid_step() {
        let sid = [1u8; 32];
        let root = [2u8; 32];
        let trace = vec![
            BabePhaseState {
                session_id: sid,
                assert_commit_root: root,
                phase: BabePhase::DepositCommitted,
                step: 0,
            },
            BabePhaseState {
                session_id: sid,
                assert_commit_root: root,
                phase: BabePhase::WithdrawAsserted,
                step: 1,
            },
            BabePhaseState {
                session_id: sid,
                assert_commit_root: root,
                phase: BabePhase::Settled,
                step: 2,
            },
        ];
        assert!(verify_babe_phase_trace(&trace));
        let mut bad = trace.clone();
        bad[2].step = 4;
        assert!(!verify_babe_phase_trace(&bad));
    }

    #[test]
    fn full_e2e_and_tamper_detection() {
        let run = run_babe_e2e();
        assert!(verify_babe_protocol_bundle(&run.protocol_bundle));

        let mut bad_bundle = run.protocol_bundle.clone();
        let mut ctprove: WeKnownPi1ProveCt =
            bincode::deserialize(&bad_bundle.setup.ctgc_small).expect("deserialize");
        ctprove.ct1_r_pi1[0] ^= 1;
        bad_bundle.setup.ctgc_small = bincode::serialize(&ctprove).expect("serialize");
        assert!(!verify_babe_protocol_bundle(&bad_bundle));

        let mut bad_bundle2 = run.protocol_bundle.clone();
        bad_bundle2.disprove_witness.reveal.revealed_secret[0] ^= 1;
        bad_bundle2.disprove_witness.reveal_commit =
            compute_challenge_reveal_commit(&bad_bundle2.disprove_witness.reveal);
        assert!(!verify_babe_protocol_bundle(&bad_bundle2));
    }

    #[test]
    fn scripts_nocat_do_not_use_op_cat() {
        let hmsg_leaf = {
            let mut v = b"babe:hmsg".to_vec();
            v.extend_from_slice(&[3u8; 32]);
            v
        };
        let art = build_babe_scripts_nocat(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            [5u8; 32],
            [6u8; 32],
            [7u8; 32],
            [8u8; 32],
            &hmsg_leaf,
            [9u8; 32],
            [10u8; 32],
        );
        assert!(!art.assert_script_pseudo.contains("OP_CAT"));
        assert!(!art.disprove_script_pseudo.contains("OP_CAT"));
    }

    #[test]
    fn role_timeline_example_deposit_withdraw_disprove() {
        // Roles in this scenario:
        // - depositor/prover: commits policy and later submits withdraw(assert).
        // - evaluator/challenger: watches withdraw and can submit disprove.
        let run = run_babe_e2e();
        let bundle = run.protocol_bundle.clone();

        // Time anchors (block heights) for the protocol timeline.
        let deposit_height = 1000u32;
        let withdraw_height = 1010u32;
        let challenge_height = 1015u32;

        // 1) Deposit: constants are committed and locked.
        assert_eq!(
            bundle.phase_trace[0],
            BabePhaseState {
                session_id: bundle.assert_inputs.session_id,
                assert_commit_root: bundle.assert_commit_root,
                phase: BabePhase::DepositCommitted,
                step: 0
            }
        );
        assert!(withdraw_height > deposit_height);

        // 2) Withdraw(assert): prover opens assert path in challenge window.
        assert_eq!(
            bundle.phase_trace[1],
            BabePhaseState {
                session_id: bundle.assert_inputs.session_id,
                assert_commit_root: bundle.assert_commit_root,
                phase: BabePhase::WithdrawAsserted,
                step: 1
            }
        );
        assert!(challenge_height > withdraw_height);

        // 3) Challenger submits disprove witness before final settlement.
        assert!(verify_babe_disprove_witness(
            &bundle.disprove_witness,
            bundle.assert_commit_root,
            bundle.assert_inputs.session_id,
        ));
        assert_eq!(
            bundle.phase_trace[2],
            BabePhaseState {
                session_id: bundle.assert_inputs.session_id,
                assert_commit_root: bundle.assert_commit_root,
                phase: BabePhase::DisproveChallenged,
                step: 2
            }
        );
        assert_eq!(
            bundle.phase_trace[3],
            BabePhaseState {
                session_id: bundle.assert_inputs.session_id,
                assert_commit_root: bundle.assert_commit_root,
                phase: BabePhase::Settled,
                step: 3
            }
        );
        assert!(verify_babe_protocol_bundle(&bundle));

        // no-cat script artifacts derived from this timeline.
        let setup_leaves = build_babe_setup_leaves(&bundle.setup);
        let hmsg_leaf = setup_leaves[3].clone();
        let sibling0 = btc_hash_leaf(&setup_leaves[2]);
        let parent01 = btc_hash_node(btc_hash_leaf(&setup_leaves[0]), btc_hash_leaf(&setup_leaves[1]));
        let art = build_babe_scripts_nocat(
            bundle.assert_commit_root,
            bundle.assert_inputs.session_id,
            bundle.policy_commit,
            bundle.assert_inputs.root_babe_setup,
            bundle.assert_inputs.root_babe_instance,
            bundle.assert_inputs.babe_hashlock,
            bundle.disprove_witness.reveal_commit,
            derive_hashlock(&bundle.disprove_witness.reveal.revealed_secret),
            &hmsg_leaf,
            sibling0,
            parent01,
        );
        assert!(!art.assert_script_pseudo.is_empty());
        assert!(!art.disprove_script_pseudo.is_empty());
    }

    #[test]
    fn evaluator_rejects_malicious_ct_setup_package() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(7);
        let a = ark_bn254::Fr::from(5u64);
        let b = ark_bn254::Fr::from(13u64);
        let c = a * b;
        let circuit = DummyMulCircuit::<ark_bn254::Fr> { a: Some(a), b: Some(b) };
        let (pk, vk) = ark_groth16::Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).expect("setup");
        let proof = ark_groth16::Groth16::<ark_bn254::Bn254>::prove(
            &pk,
            DummyMulCircuit::<ark_bn254::Fr> { a: Some(a), b: Some(b) },
            &mut rng,
        )
        .expect("prove");
        let public_inputs = vec![c];
        let binding = bind_groth16_relation(&vk, &proof, &public_inputs);
        let statement_hash = binding.statement_hash;
        let secret = b"paper-only-test-secret".to_vec();
        let hmsg = derive_hashlock(&secret);

        let base_pkg = prover_build_ct_setup(
            statement_hash,
            hmsg,
            &vk,
            &public_inputs,
            proof.a.into_group(),
            proof.b.into_group(),
            proof.c.into_group(),
            h(b"test:r-we"),
            &secret,
            h(b"test:ek"),
        )
        .expect("prover build");
        assert!(evaluator_verify_ct_setup(&base_pkg, statement_hash, hmsg).is_ok());

        let mut bad1 = base_pkg.clone();
        bad1.paper_we_commit[0] ^= 1;
        assert_eq!(
            evaluator_verify_ct_setup(&bad1, statement_hash, hmsg),
            Err(BabeSetupVerifyError::PaperWeCommitMismatch)
        );

        let mut bad2 = base_pkg.clone();
        bad2.pi2[0] ^= 1;
        assert_eq!(
            evaluator_verify_ct_setup(&bad2, statement_hash, hmsg),
            Err(BabeSetupVerifyError::PaperWeDecryptFailed)
        );

        let mut bad3 = base_pkg.clone();
        bad3.setup_gc_binding_commit[0] ^= 1;
        assert_eq!(
            evaluator_verify_ct_setup(&bad3, statement_hash, hmsg),
            Err(BabeSetupVerifyError::SetupGcBindingInvalid)
        );
    }

    #[test]
    fn deposit_commit_binds_known_pi1_we_params() {
        let run = run_babe_e2e();
        // In run_babe_e2e we bind paper WE commit directly into policy.we_params_hash.
        assert!(verify_babe_protocol_bundle(&run.protocol_bundle));
        assert_eq!(
            run.protocol_bundle.policy.we_params_hash,
            commit_we_known_pi1_ciphertexts(&run.ct_setup, &run.ctprove)
        );
    }
}
