// ─── Transaction skeletons. This will be replaced by real Txn in Bitvm2-node ─────────

use ark_bn254::{Fq, Fr, G1Affine};
use ark_serialize::CanonicalDeserialize;
use serde::{Deserialize, Serialize};
use crate::babe::{BabeBtcSig, BtcPk, BTC_SIG_BYTES, MSG_BYTES};
use crate::wots::Wots96;
use bitvm::signatures::Wots;

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
/// Input spends a UTXO with: CheckWotsSig(wots_pk_P)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxAssertWitness {
    /// Wots96 signature over the 96-byte message (π₁.x LE-32 ∥ π₁.y LE-32 ∥ x_d LE-32).
    pub wots_sig: Vec<[u8; 21]>,
}

impl TxAssertWitness {
    /// Extract π₁ and x_d from the digit values embedded in the Wots96 signature.
    /// The 96-byte message layout is: π₁.x (LE-32) ∥ π₁.y (LE-32) ∥ x_d (LE-32).
    /// Does NOT verify the signature — caller must call wots96_verify separately.
    pub fn recover_pi1_xd_without_verify(&self) -> Option<(G1Affine, Fr)> {
        // wrong length
        if self.wots_sig.len() != Wots96::TOTAL_DIGIT_LEN as usize {
            return None;
        }

        let arr_sig: [[u8; 21]; Wots96::TOTAL_DIGIT_LEN as usize] =
            self.wots_sig.clone().try_into().ok()?;
        let msg = Wots96::signature_to_message(&arr_sig);
        let x = Fq::deserialize_uncompressed(&msg[0..32]).ok()?;
        let y = Fq::deserialize_uncompressed(&msg[32..64]).ok()?;
        // return None if pi1 is not a valid point.
        let pi1 = G1Affine::new_unchecked(x, y);
        if !pi1.is_on_curve() {
            return None;
        }
        let x_d = Fr::deserialize_uncompressed(&msg[64..96]).ok()?;
        Some((pi1, x_d))
    }
}

/// tx_ChallengeAssert — witness for input 0.
/// Input spends tx_Assert output 1: CheckSigsConsistent(wots_pk_P, epk_V) ∧ CheckSig(pk_V) ∧ CheckSig(pk_P)
/// Script verifies:
///   (a) Wots96 sig is valid for some 96-byte message m — binds π₁ and x_d to the prover
///   (b) SHA256(L[i]) == epk_V[i][bit_i(m)]  — L[i] is the correct GC label for bit_i under epk
///   (c) Wots96 sig and epk labels are consistent over the same message m — both sign/encode the same bits

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeAssertWitnessRaw {
    /// L₁…L_M — one GC input label per bit of π₁ and x_d, LAMPORT_N × 16 bytes.
    pub input_labels: Vec<[u8; 16]>,
    /// Wots96 sig re-posted from TxAssertWitness to bind the labels to π₁ and x_d.
    pub wots_sig: Vec<[u8; 21]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxChallengeAssertWitness {
    pub witness: ChallengeAssertWitnessRaw,
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
        // Signature size
        Wots96::TOTAL_DIGIT_LEN as usize * 21
    }
}

impl OnchainSize for TxChallengeAssertWitness {
    fn size_bytes(&self) -> usize {
        self.witness.input_labels.len() * 16                 // LAMPORT_N × 16 bytes
            + Wots96::TOTAL_DIGIT_LEN as usize * 20  // wots_sig preimages
            + BTC_SIG_BYTES                          // sig_v: 32 bytes
            + BTC_SIG_BYTES                          // sig_p: 32 bytes
    }
}

impl OnchainSize for TxWronglyChallengedWitness {
    fn size_bytes(&self) -> usize {
        BTC_SIG_BYTES // sig_p: 32 bytes
            + MSG_BYTES   // msg:   32 bytes
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq, Fr, G1Affine};
    use ark_ec::AffineRepr;
    use ark_serialize::CanonicalSerialize;
    use bitvm::signatures::Wots;
    use crate::utils::pi1_xd_to_wots96_msg;
    use crate::wots::Wots96;

    // Signs an arbitrary 96-byte message to produce a TxAssertWitness.
    fn make_witness_from_raw_msg(msg: &[u8; 96]) -> TxAssertWitness {
        let sk = Wots96::generate_secret_key();
        TxAssertWitness { wots_sig: Wots96::sign(&sk, msg).to_vec() }
    }

    #[test]
    fn test_recover_valid_generator_and_fr() {
        let pi1 = G1Affine::generator();
        let x_d = Fr::from(42u64);
        let msg = pi1_xd_to_wots96_msg(&pi1, x_d);
        let witness = make_witness_from_raw_msg(&msg);

        let (recovered_pi1, recovered_xd) = witness.recover_pi1_xd_without_verify().unwrap();
        assert_eq!(recovered_pi1, pi1);
        assert_eq!(recovered_xd, x_d);
    }

    #[test]
    fn test_recover_wrong_length() {
        let witness = TxAssertWitness { wots_sig: vec![[0u8; 21]; Wots96::TOTAL_DIGIT_LEN as usize - 1] };
        assert!(witness.recover_pi1_xd_without_verify().is_none());

        let witness = TxAssertWitness { wots_sig: vec![[0u8; 21]; Wots96::TOTAL_DIGIT_LEN as usize + 1] };
        assert!(witness.recover_pi1_xd_without_verify().is_none());
    }

    #[test]
    fn test_recover_empty_sig() {
        let witness = TxAssertWitness { wots_sig: vec![] };
        assert!(witness.recover_pi1_xd_without_verify().is_none());
    }

    #[test]
    fn test_recover_off_curve_point() {
        // (1, 1) is not on BN254 G1
        let mut msg = [0u8; 96];
        let mut buf = Vec::new();
        Fq::from(1u64).serialize_uncompressed(&mut buf).unwrap();
        msg[0..32].copy_from_slice(&buf);
        buf.clear();
        Fq::from(1u64).serialize_uncompressed(&mut buf).unwrap();
        msg[32..64].copy_from_slice(&buf);
        let witness = make_witness_from_raw_msg(&msg);
        assert!(witness.recover_pi1_xd_without_verify().is_none());
    }

    #[test]
    fn test_recover_x_coordinate_out_of_field() {
        // 0xFF..FF > Fq modulus → Fq::deserialize_uncompressed returns Err
        let mut msg = [0u8; 96];
        msg[0..32].fill(0xFF);
        let witness = make_witness_from_raw_msg(&msg);
        assert!(witness.recover_pi1_xd_without_verify().is_none());
    }

    #[test]
    fn test_recover_y_coordinate_out_of_field() {
        let pi1 = G1Affine::generator();
        let mut buf = Vec::new();
        pi1.x.serialize_uncompressed(&mut buf).unwrap();
        let mut msg = [0u8; 96];
        msg[0..32].copy_from_slice(&buf);
        msg[32..64].fill(0xFF); // y > Fq modulus
        let witness = make_witness_from_raw_msg(&msg);
        assert!(witness.recover_pi1_xd_without_verify().is_none());
    }

    #[test]
    fn test_recover_xd_out_of_field() {
        let pi1 = G1Affine::generator();
        let mut msg = pi1_xd_to_wots96_msg(&pi1, Fr::from(0u64));
        msg[64..96].fill(0xFF); // x_d > Fr modulus
        let witness = make_witness_from_raw_msg(&msg);
        assert!(witness.recover_pi1_xd_without_verify().is_none());
    }
}
