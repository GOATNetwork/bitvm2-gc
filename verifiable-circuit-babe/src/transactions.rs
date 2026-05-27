// ─── Transaction locking script ───────────────────────────────────────────────

use serde::{Deserialize, Serialize};
use crate::babe::{BabeBtcSig, BtcPk, BTC_SIG_BYTES, LAMPORT_SIG_BYTES, MSG_BYTES, WOTS64_SIG_BYTES};
use crate::utils::Wots64Sig;

/// Constants embedded in the locking script of tx_Deposit output 0.
/// Script: CheckSig(pk_P) ∧ CheckSig(pk_V)
#[derive(Debug, Clone)]
pub struct TxDepositLock {
    pub pk_p: BtcPk,
    pub pk_v: BtcPk,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct TxChallengeAssertOutputLock {
    pub pk_p: BtcPk,
    pub pk_v: BtcPk,
    pub h_msgs: Vec<[u8; 20]>,
}

// ─── Transaction witnesses (on-chain data) ────────────────────────────────────

/// tx_Assert — witness for input 0.
/// Input spends a UTXO with: CheckLampSig(lpk_P)
/// Script verifies: SHA256(μ[i]) == lpk_P[i][bit_i(π₁)] for all i.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxAssertWitness {
    /// Compressed G1Affine, 33 bytes — the asserted proof element.
    pub pi1: Vec<u8>,
    /// μ₁…μ_ℓ — Lamport signature, LAMPORT_N × 16 bytes.
    pub wots_sig: Wots64Sig,
}

/// tx_ChallengeAssert — witness for input 0.
/// Input spends tx_Assert output 1: CheckLampSigsMatch(lpk_P, lpk_V) ∧ CheckSig(pk_V) ∧ CheckSig(pk_P)
/// Script verifies:
///   (a) SHA256(μ[i]) == lpk_P[i][bit_i]     — μ is a valid Lamport sig for some π₁
///   (b) blake3(L[i]) == lpk_V[i][bit_i]     — L[i] is the correct GC label for bit_i under epk
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxChallengeAssertWitness {
    /// L₁…L_ℓ — one GC input label per π₁ bit, PADDED_LAMPORT_N × 16 bytes.
    pub input_labels: Vec<[u8; 16]>,
    /// μ₁…μ_ℓ — Lamport sig re-posted to bind L to π₁.
    pub wots_sig: Wots64Sig,
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
        WOTS64_SIG_BYTES
    }
}

impl OnchainSize for TxChallengeAssertWitness {
    fn size_bytes(&self) -> usize {
        WOTS64_SIG_BYTES      // wotsig
            + LAMPORT_SIG_BYTES // input_labels:
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

