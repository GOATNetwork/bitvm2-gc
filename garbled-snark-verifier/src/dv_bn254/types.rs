use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::Deserialize;
use crate::dv_bn254::dv_ckt::Proof;
use crate::dv_bn254::dv_ref::{FrRef, ProofRef, PublicInputsRef, TrapdoorRef, VerifierPayloadRef};
use crate::dv_bn254::fr::FR_LEN;
use crate::dv_bn254::g1::G1Projective;

#[derive(Deserialize)]
pub(crate) struct RawProof {
    pub commit_p: G1PPointRef,
    pub kzg_k: G1PPointRef,
    pub a0: FrBits,
    pub b0: FrBits,
}

impl Into<ProofRef> for RawProof {
    fn into(self) -> ProofRef {
        let fr_from_bits_le =
            |bits: &[bool; FR_LEN]| -> FrRef {
                let mut tmp = bits.clone().to_vec();
                // Pad to full byte
                tmp.push(false);
                tmp.push(false);
                let bytes =
                    tmp.chunks_exact(8)
                        .map(|chunk| {
                            chunk.iter().enumerate().fold(0u8, |byte, (i, &bit)| {
                                if bit { byte | (1 << i) } else { byte }
                            })
                        })
                        .collect::<Vec<u8>>();
                FrRef::from_bytes_le(&bytes)
            };
        ProofRef {
            mont_commit_p: self.commit_p.into(),
            mont_kzg_k: self.kzg_k.into(),
            mont_a0: fr_from_bits_le(&self.a0.0),
            mont_b0: fr_from_bits_le(&self.b0.0),
        }
    }
}

#[derive(Debug)]
pub struct G1PPointRef {
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub z: [u8; 32],
}

impl<'de> Deserialize<'de> for G1PPointRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;

        if bytes.len() != 96 {
            return Err(serde::de::Error::custom("expected 96 bytes for projective point"));
        }

        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        let mut z = [0u8; 32];
        x.copy_from_slice(&bytes[0..32]);
        y.copy_from_slice(&bytes[32..64]);
        z.copy_from_slice(&bytes[64..96]);

        Ok(G1PPointRef { x, y, z })
    }
}

impl Into<ark_bn254::G1Projective> for G1PPointRef {
    fn into(self) -> ark_bn254::G1Projective {
        let x = ark_bn254::Fq::from_be_bytes_mod_order(&self.x);
        let y = ark_bn254::Fq::from_be_bytes_mod_order(&self.y);
        let z = ark_bn254::Fq::from_be_bytes_mod_order(&self.z);
        ark_bn254::G1Projective::new_unchecked(x, y, z)
    }
}

#[derive(Clone, Debug, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct RawTrapdoor {
    pub tau: ark_bn254::Fr,
    pub delta: ark_bn254::Fr,
    pub epsilon: ark_bn254::Fr,
}

impl Into<TrapdoorRef> for RawTrapdoor {
    fn into(self) -> TrapdoorRef {
        TrapdoorRef {
            tau: self.tau.into_bigint().into(),
            delta: self.delta.into_bigint().into(),
            epsilon: self.epsilon.into_bigint().into(),
        }
    }
}

pub struct FrBits(pub [bool; FR_LEN]);
impl<'de> Deserialize<'de> for FrBits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut bits = [false; FR_LEN];
        for i in 0..FR_LEN {
            bits[i] = (bytes[i / 8] >> (i % 8)) & 1 == 1;
        }
        Ok(FrBits(bits))
    }
}

pub(crate) struct RawVerifierPayload {
    pub proof: RawProof,
    pub public_inputs: Vec<ark_bn254::Fr>,
    pub trapdoor: RawTrapdoor,
}

impl Into<VerifierPayloadRef> for RawVerifierPayload {
    fn into(self) -> VerifierPayloadRef {
        let public_inputs = self
            .public_inputs
            .into_iter()
            .map(|fr| fr.into_bigint().into())
            .collect::<Vec<FrRef>>();

        VerifierPayloadRef {
            proof: self.proof.into(),
            public_input: PublicInputsRef { public_inputs: public_inputs.try_into().unwrap() },
            trapdoor: self.trapdoor.into(),
        }
    }
}
