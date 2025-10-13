use crate::circuits::sect233k1::curve_ckt::AffinePointRef;
use crate::circuits::sect233k1::dv_ckt::{
    ProofRef, PublicInputsRef, TrapdoorRef, VerifierPayloadRef,
};
use crate::circuits::sect233k1::fr_ckt::FR_LEN;
use crate::circuits::sect233k1::fr_ref::FrRef;
use ark_ff::{Fp256, MontBackend, MontConfig, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::Deserialize;

#[derive(MontConfig, Debug)]
#[modulus = "3450873173395281893717377931138512760570940988862252126328087024741343"]
#[generator = "3"]
pub struct FqConfig;
pub type RawFr = Fp256<MontBackend<FqConfig, 4>>;

pub struct FrBits(pub [bool; FR_LEN]);

impl<'de> Deserialize<'de> for FrBits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        if bytes.len() != 29 {
            return Err(serde::de::Error::custom("expected 29 bytes"));
        }
        let mut bits = [false; 232];
        for i in 0..232 {
            bits[i] = (bytes[i / 8] >> (i % 8)) & 1 == 1;
        }
        Ok(FrBits(bits))
    }
}

#[derive(Deserialize)]
pub(crate) struct RawProof {
    pub commit_p: AffinePointRef,
    pub kzg_k: AffinePointRef,
    pub a0: FrBits,
    pub b0: FrBits,
}

impl Into<ProofRef> for RawProof {
    fn into(self) -> ProofRef {
        let fr_from_bits_le =
            |bits: &[bool; FR_LEN]| -> FrRef {
                let bytes =
                    bits.chunks_exact(8)
                        .map(|chunk| {
                            chunk.iter().enumerate().fold(0u8, |byte, (i, &bit)| {
                                if bit { byte | (1 << i) } else { byte }
                            })
                        })
                        .collect::<Vec<u8>>();

                FrRef::from_bytes_le(&bytes)
            };
        ProofRef {
            commit_p: self.commit_p,
            kzg_k: self.kzg_k,
            a0: fr_from_bits_le(&self.a0.0),
            b0: fr_from_bits_le(&self.b0.0),
        }
    }
}

#[derive(Clone, Debug, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct RawTrapdoor {
    pub tau: RawFr,
    pub delta: RawFr,
    pub epsilon: RawFr,
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

pub(crate) struct RawVerifierPayload {
    pub proof: RawProof,
    pub public_inputs: Vec<RawFr>,
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

pub fn load_witness_from_files(
    proof_path: &str,
    public_inputs_path: &str,
    trapdoor_path: &str,
) -> VerifierPayloadRef {
    // Read and deserialize proof
    let proof_data = std::fs::read(proof_path).unwrap();
    let proof: RawProof = bincode::deserialize(&proof_data).unwrap();

    let public_inputs_data = std::fs::read(public_inputs_path).unwrap();
    let public_inputs = Vec::<RawFr>::deserialize_compressed(&public_inputs_data[..]).unwrap();

    let trapdoor_data = std::fs::read(trapdoor_path).unwrap();
    let trapdoor: RawTrapdoor = RawTrapdoor::deserialize_compressed(&trapdoor_data[..]).unwrap();

    let w = RawVerifierPayload { proof, public_inputs, trapdoor };

    w.into()
}
