#![cfg(test)]
//! Reference implementation of DV Verifier Program
//!
use std::str::FromStr;

use super::{
    curve_ckt::CompressedCurvePointRef,
    curve_ref::{CurvePointRef, point_add, point_equals, point_scalar_multiplication},
    dv_ckt::{ProofRef, PublicInputsRef, TrapdoorRef},
    fr_ckt::FR_LEN,
    fr_ref::FrRef,
};
use crate::circuits::sect233k1::curve_ckt::{AffinePointRef, CurvePoint};
use num_traits::{FromPrimitive, Num};

pub(crate) fn get_fs_challenge(
    commit_p: &AffinePointRef,
    public_inputs: &[FrRef],
    srs_bytes: Vec<u8>,
    circuit_info_bytes: Vec<u8>,
) -> FrRef {
    let witness_commitment_hash = {
        let (curve_point, success) = CurvePointRef::from_affine_point(commit_p);
        assert!(success, "failed to decode commitment point");

        let mut affine_bytes = Vec::with_capacity(60);
        let mut x_bytes = curve_point.x.to_bytes_le();
        x_bytes.resize(30, 0);
        let mut y_bytes = curve_point.s.to_bytes_le();
        y_bytes.resize(30, 0);
        affine_bytes.extend_from_slice(&x_bytes);
        affine_bytes.extend_from_slice(&y_bytes);

        blake3::hash(&affine_bytes)
    };

    let public_inputs_hash = {
        let mut buf = Vec::new();
        for pubin in public_inputs {
            let mut bytes = pubin.to_bytes_le();
            bytes.resize(FR_LEN / 8, 0);
            buf.append(&mut bytes);
        }
        blake3::hash(&buf)
    };

    let compile_time_hash = {
        let srs_hash = blake3::hash(&srs_bytes);
        let circuit_info_hash = blake3::hash(&circuit_info_bytes);
        let mut compile_time_bytes: Vec<u8> = Vec::new();
        compile_time_bytes.extend_from_slice(srs_hash.as_bytes());
        compile_time_bytes.extend_from_slice(circuit_info_hash.as_bytes());
        blake3::hash(&compile_time_bytes)
    };

    let runtime_hash = {
        let mut runtime_bytes: Vec<u8> = Vec::new();
        runtime_bytes.extend_from_slice(witness_commitment_hash.as_bytes());
        runtime_bytes.extend_from_slice(public_inputs_hash.as_bytes());

        blake3::hash(&runtime_bytes)
    };

    let mut root_hash = {
        let mut root_bytes: Vec<u8> = Vec::new();
        root_bytes.extend_from_slice(compile_time_hash.as_bytes());
        root_bytes.extend_from_slice(runtime_hash.as_bytes());

        let out_hash = blake3::hash(&root_bytes);
        let out_hash = out_hash.as_bytes();
        *out_hash
    };

    // truncate msb
    root_hash[28..].copy_from_slice(&[0, 0, 0, 0]); // mask top 3 bytes, 256-24=232 bits

    FrRef::from_bytes_le(&root_hash)
}

// // Referenced from Ziren's function to convert from raw public inputs to truncated scalar field element
// pub(crate) fn get_pub_hash_from_raw_pub_inputs(raw_pub_in: &PublicInputsRef) -> FrRef {
//     pub(crate) fn babybear_bytes_to_sect_fr(bytes: &[u8; 32]) -> FrRef {
//         let mut result = FrRef::ZERO;
//         for (idx, byte) in bytes.iter().enumerate() {
//             result *= FrRef::from_u16(256).unwrap();
//             let masked = if idx < 4 { 0 } else { *byte };
//             result += FrRef::from_u8(masked).unwrap();
//         }
//         result
//     }
//
//     let inps = raw_pub_in.public_inputs.to_le_bytes().to_vec();
//     let out_hash = blake3::hash(&inps);
//     babybear_bytes_to_sect_fr(&out_hash.into())
// }

const MOD_HEX: &str = "8000000000000000000000000000069d5bb915bcd46efb1ad5f173abdf"; // n

fn fr_add(a: &FrRef, b: &FrRef) -> FrRef {
    let n = FrRef::from_str_radix(MOD_HEX, 16).unwrap();
    (a + b) % n
}

fn fr_sub(a: &FrRef, b: &FrRef) -> FrRef {
    let modr = FrRef::from_str_radix(MOD_HEX, 16).unwrap();
    if a >= b { a - b } else { a + &modr - b }
}

fn fr_mul(a: &FrRef, b: &FrRef) -> FrRef {
    let n = FrRef::from_str_radix(MOD_HEX, 16).unwrap();
    (a * b) % n
}

pub(crate) fn verify(
    proof: ProofRef,
    public_inputs: PublicInputsRef,
    secrets: TrapdoorRef,
) -> bool {
    let (proof_commit_p, decode_proof_commit_p_success) =
        CurvePointRef::from_affine_point(&proof.commit_p);
    let (proof_kzg_k, decode_proof_kzg_k_success) = CurvePointRef::from_affine_point(&proof.kzg_k);
    let n = FrRef::from_str_radix(MOD_HEX, 16).unwrap();
    let decode_scalars_success = proof.a0 < n && proof.b0 < n;

    // let public_inputs_1 = get_pub_hash_from_raw_pub_inputs(&raw_public_inputs);
    // let public_inputs_0_vk_const = FrRef::from_str(ziren_vk).unwrap(); // vk

    let fs_challenge_alpha =
        get_fs_challenge(&proof.commit_p, &public_inputs.public_inputs, vec![], vec![]);

    let i0 = {
        let t0 = fr_mul(&public_inputs.public_inputs[1], &fs_challenge_alpha);
        fr_add(&t0, &public_inputs.public_inputs[0])
    };

    let r0 = {
        //&proof.a0 * &proof.b0 - &proof.i0
        let t0 = fr_mul(&proof.a0, &proof.b0);
        fr_sub(&t0, &i0)
    };

    // Step 3. Compute u₀ and v₀
    let delta2 = fr_mul(&secrets.delta, &secrets.delta);
    let u0 = {
        //(&proof.a0 + &secrets.delta * &proof.b0 + &delta2 * &r0) * &secrets.epsilon;
        let db0 = fr_mul(&secrets.delta, &proof.b0);
        let a0_p_db0 = fr_add(&proof.a0, &db0);
        let d2_r0 = fr_mul(&delta2, &r0);
        let t1 = fr_add(&a0_p_db0, &d2_r0);
        fr_mul(&t1, &secrets.epsilon)
    };
    let v0 = fr_mul(&fr_sub(&secrets.tau, &fs_challenge_alpha), &secrets.epsilon);

    let v0_k = point_scalar_multiplication(&v0, &proof_kzg_k);
    let u0_g = point_scalar_multiplication(&u0, &CurvePointRef::generator());
    let lhs = point_add(&v0_k, &u0_g);
    let rhs: CurvePointRef = proof_commit_p;

    let proof_pass = point_equals(&lhs, &rhs); // matches
    let decode_pass =
        decode_proof_commit_p_success & decode_proof_kzg_k_success & decode_scalars_success;
    proof_pass & decode_pass
}

#[cfg(test)]
mod test {
    use super::super::fr_ref::FrRef;
    use super::{ProofRef, PublicInputsRef, TrapdoorRef, verify};
    use crate::circuits::sect233k1::curve_ckt::AffinePointRef;
    use std::str::FromStr;

    #[test]
    fn test_verify_over_mock_inputs() {
        let secrets = {
            let tau = FrRef::from_str(
                "490782060457092443021184404188169115419401325819878347174959236155604",
            )
            .unwrap();
            let delta = FrRef::from_str(
                "409859792668509615016679153954612494269657711226760893245268993658466",
            )
            .unwrap();
            let epsilon = FrRef::from_str(
                "2880039972651592580549544494658966441531834740391411845954153637005104",
            )
            .unwrap();
            TrapdoorRef { tau, delta, epsilon }
        };

        let proof = ProofRef {
            commit_p: AffinePointRef {
                x: [
                    130, 16, 132, 245, 115, 118, 110, 233, 235, 58, 5, 190, 187, 230, 138, 225,
                    149, 231, 32, 45, 41, 29, 94, 89, 248, 158, 54, 19, 86, 0,
                ],
                s: [
                    93, 74, 178, 168, 173, 38, 101, 88, 181, 49, 78, 207, 89, 78, 130, 42, 242,
                    245, 88, 5, 253, 250, 54, 182, 177, 249, 82, 57, 147, 0,
                ],
            },
            kzg_k: AffinePointRef {
                x: [
                    36, 69, 122, 22, 89, 79, 186, 56, 138, 8, 183, 193, 186, 98, 21, 62, 9, 143,
                    173, 24, 89, 195, 126, 73, 241, 118, 71, 103, 223, 0,
                ],
                s: [
                    12, 122, 106, 168, 104, 248, 117, 18, 171, 218, 85, 138, 31, 80, 250, 230, 176,
                    136, 74, 129, 137, 78, 181, 48, 88, 180, 21, 139, 39, 1,
                ],
            },
            a0: FrRef::from_str(
                "1858232303623355521215721639157430371979542022979851183514844283900649",
            )
            .unwrap(),
            b0: FrRef::from_str(
                "3045644831070136055562137919853497607898653327126781771795842528553732",
            )
            .unwrap(),
        };

        let rpin = PublicInputsRef {
            public_inputs: [
                FrRef::from_str(
                    "9487159538405616582219466419827834782293111327936747259752845028149",
                )
                .unwrap(),
                FrRef::from_str(
                    "22596372664815072823112258091854569627353949811861389086305200952659",
                )
                .unwrap(),
            ],
        };
        let passed = verify(proof, rpin, secrets);
        assert!(passed);
    }

    #[test]
    fn test_invalid_proof_over_mock_inputs() {
        let secrets = {
            let tau = FrRef::from_str(
                "490782060457092443021184404188169115419401325819878347174959236155604",
            )
            .unwrap();
            let delta = FrRef::from_str(
                "409859792668509615016679153954612494269657711226760893245268993658466",
            )
            .unwrap();
            let epsilon = FrRef::from_str(
                "1880039972651592580549544494658966441531834740391411845954153637005104",
            )
            .unwrap();
            TrapdoorRef { tau, delta, epsilon }
        };

        let proof = ProofRef {
            commit_p: AffinePointRef {
                x: [
                    130, 16, 132, 245, 115, 118, 110, 233, 235, 58, 5, 190, 187, 230, 138, 225,
                    149, 231, 32, 45, 41, 29, 94, 89, 248, 158, 54, 19, 86, 0,
                ],
                s: [
                    93, 74, 178, 168, 173, 38, 101, 88, 181, 49, 78, 207, 89, 78, 130, 42, 242,
                    245, 88, 5, 253, 250, 54, 182, 177, 249, 82, 57, 147, 0,
                ],
            },
            kzg_k: AffinePointRef {
                x: [
                    36, 69, 122, 22, 89, 79, 186, 56, 138, 8, 183, 193, 186, 98, 21, 62, 9, 143,
                    173, 24, 89, 195, 126, 73, 241, 118, 71, 103, 223, 0,
                ],
                s: [
                    12, 122, 106, 168, 104, 248, 117, 18, 171, 218, 85, 138, 31, 80, 250, 230, 176,
                    136, 74, 129, 137, 78, 181, 48, 88, 180, 21, 139, 39, 1,
                ],
            },
            a0: FrRef::from_str(
                "1858232303623355521215721639157430371979542022979851183514844283900649",
            )
            .unwrap(),
            b0: FrRef::from_str(
                "3045644831070136055562137919853497607898653327126781771795842528553732",
            )
            .unwrap(),
        };

        let rpin = PublicInputsRef {
            public_inputs: [
                FrRef::from_str(
                    "20964902444291521893664765711676021715483874668026528518811070427510",
                )
                .unwrap(),
                FrRef::from_str(
                    "22596372664815072823112258091854569627353949811861389086305200952659",
                )
                .unwrap(),
            ],
        };
        let passed = verify(proof, rpin, secrets);
        assert!(!passed);
    }
}
