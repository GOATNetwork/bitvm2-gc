use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_groth16::VerifyingKey as Groth16VerifyingKey;

pub fn groth16_vk_x(
    vk: &Groth16VerifyingKey<ark_bn254::Bn254>,
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

pub fn g2_to_ser(p: ark_bn254::G2Projective) -> Vec<u8> {
    let mut out = Vec::new();
    p.into_affine().serialize_compressed(&mut out).expect("serialize g2");
    out
}

pub fn g1_to_ser(p: ark_bn254::G1Projective) -> Vec<u8> {
    let mut out = Vec::new();
    p.into_affine().serialize_compressed(&mut out).expect("serialize g1");
    out
}

pub fn g1_from_ser_checked(v: &[u8]) -> Option<ark_bn254::G1Projective> {
    let a = G1Affine::deserialize_compressed(v).ok()?;
    if a.is_zero() || !a.is_on_curve() || !a.is_in_correct_subgroup_assuming_on_curve() {
        return None;
    }
    Some(a.into_group())
}

pub fn g2_from_ser_checked(v: &[u8]) -> Option<ark_bn254::G2Projective> {
    let a = G2Affine::deserialize_compressed(v).ok()?;
    if a.is_zero() || !a.is_on_curve() || !a.is_in_correct_subgroup_assuming_on_curve() {
        return None;
    }
    Some(a.into_group())
}