//! Binary circuit implementation of DV Verifier Program
//!

use crate::circuits::sect233k1::builder::{CircuitAdapter, CircuitTrait};
use crate::circuits::sect233k1::blake3_ckt;
use crate::dv_bn254::bigint::U254;
use crate::dv_bn254::fp254impl::Fp254Impl;
use super::{
    fr::{
        FR_LEN, Fr,
    },
};
use crate::dv_bn254::fq::FQ_LEN;
use crate::dv_bn254::g1::G1Projective;

const PROOF_BIT_LEN: usize = FQ_LEN * 3 * 2 + FR_LEN * 2;
const PUBINP_BIT_LEN: usize = 2 * FR_LEN;
const TRAPDOOR_BIT_LEN: usize = FR_LEN * 3;

pub(crate) const WITNESS_BIT_LEN: usize = PROOF_BIT_LEN + PUBINP_BIT_LEN + TRAPDOOR_BIT_LEN;

pub fn get_input_indexes(bld: &mut CircuitAdapter) -> (Proof, PublicInputs, Trapdoor) {
    let secrets = Trapdoor {
        tau: Fr(bld.fresh()),
        delta: Fr(bld.fresh()),
        epsilon: Fr(bld.fresh())
    };
    let rpin = PublicInputs {
        public_inputs: [Fr(bld.fresh()), Fr(bld.fresh())]
    };

    let commit_p = G1Projective::wires(bld);
    let kzg_k = G1Projective::wires(bld);

    let proof = Proof {
        mont_commit_p: commit_p,
        mont_kzg_k: kzg_k,
        mont_a0: Fr(bld.fresh()),
        mont_b0: Fr(bld.fresh()),
    };
    (proof, rpin, secrets)
}

/// Proof wires
#[derive(Debug, Clone)]
pub struct Proof {
    /// commit_p
    pub mont_commit_p: G1Projective, // commitment to witness folding & quotient
    /// kzg_k
    pub mont_kzg_k: G1Projective, // combined KZG evaluation proof
    /// a0
    pub mont_a0: Fr,
    /// b0
    pub mont_b0: Fr,
}

/// RawPublicInputs
#[derive(Debug)]
pub struct PublicInputs {
    pub public_inputs: [Fr; 2],
}

/// Trapdoor
#[derive(Debug)]
pub struct Trapdoor {
    /// tau
    pub tau: Fr, // trapdoor (only known to verifier)
    /// delta
    pub delta: Fr,
    /// epsilon
    pub epsilon: Fr,
}

#[derive(Debug)]
pub struct IndexInfo {
    /// input wire inclusive range
    pub input_wire_range: (usize, usize),
    /// const zero wire label
    pub const_zero: usize,
    /// const one wire label
    pub const_one: usize,
    /// output index
    pub output_index: usize,
}

fn u8_arr_to_labels_le<T: CircuitTrait>(bld: &mut T, ns: &[u8]) -> Vec<[usize; 8]> {
    let zero = bld.zero();
    let one = bld.one();
    let mut vs: Vec<[usize; 8]> = Vec::new();
    for n in ns {
        let v: Vec<usize> = (0..8)
            .map(|i| {
                let r = (n >> i) & 1_u8 != 0_u8;
                if r { one } else { zero }
            })
            .collect();
        let v: [usize; 8] = v.try_into().unwrap();
        vs.push(v);
    }
    vs
}

fn get_fs_challenge<T: CircuitTrait>(
    bld: &mut T,
    commit_p: &G1Projective,
    public_inputs: [Fr; 2],
    srs_bytes: Vec<u8>,
    circuit_info_bytes: Vec<u8>,
) -> Fr {
    // convert into byte-aligned representation
    let zero = bld.zero();
    let mut commit_bits = commit_p.x.0.to_vec();
    commit_bits.resize(256, zero);
    commit_bits.extend_from_slice(&commit_p.y.0.to_vec());
    commit_bits.resize(512, zero);
    commit_bits.extend_from_slice(&commit_p.z.0.to_vec());
    commit_bits.resize(768, zero);

    let commit_p_u8 = commit_bits.chunks(8).map(|chunk| chunk.try_into().unwrap()).collect();

    let witness_commitment_hash = blake3_ckt::hash(bld, commit_p_u8);

    let public_inputs_hash = {
        let mut buf = Vec::new();
        for pubin in public_inputs {
            let mut pubin_256 = [bld.zero(); 256];
            pubin_256[0..FR_LEN].copy_from_slice(&pubin.0);
            let mut r: Vec<[usize; 8]> = pubin_256
                .chunks(8)
                .map(|x| {
                    let y: [usize; 8] = x.try_into().unwrap();
                    y
                })
                .collect();
            buf.append(&mut r);
        }

        blake3_ckt::hash(bld, buf)
    };

    let compile_time_hash = {
        let srs_bytes = u8_arr_to_labels_le(bld, &srs_bytes);
        let srs_hash = blake3_ckt::hash(bld, srs_bytes);
        let circuit_info_bytes = u8_arr_to_labels_le(bld, &circuit_info_bytes);
        let circuit_info_hash = blake3_ckt::hash(bld, circuit_info_bytes);
        let mut compile_time_bytes: Vec<[usize; 8]> = Vec::new();
        compile_time_bytes.extend_from_slice(&srs_hash);
        compile_time_bytes.extend_from_slice(&circuit_info_hash);
        blake3_ckt::hash(bld, compile_time_bytes)
    };

    let runtime_hash = {
        let mut runtime_bytes: Vec<[usize; 8]> = Vec::new();
        runtime_bytes.extend_from_slice(&witness_commitment_hash);
        runtime_bytes.extend_from_slice(&public_inputs_hash);

        blake3_ckt::hash(bld, runtime_bytes)
    };

    let mut root_hash = {
        let mut root_bytes: Vec<[usize; 8]> = Vec::new();
        root_bytes.extend_from_slice(&compile_time_hash);
        root_bytes.extend_from_slice(&runtime_hash);

        blake3_ckt::hash(bld, root_bytes)
    };

    let zero_byte = [bld.zero(); 8];
    // convert to Fr
    root_hash[31..].copy_from_slice(&[zero_byte; 1]); // mask top 1 bytes, 256-8=248 bits

    let root_hash_flat: Vec<usize> = root_hash.into_iter().flatten().collect();
    let root_fr_inner: [usize; FR_LEN] = root_hash_flat[0..FR_LEN].try_into().unwrap();

    Fr(root_fr_inner)
}

// /// Convert raw public inputs into scalar field element as done by Ziren
// fn get_pub_hash_from_raw_pub_inputs<T: CircuitTrait>(bld: &mut T, raw_pub_in: &PublicInputs) -> Fr {
//     let inps: Vec<[usize; 8]> = raw_pub_in
//         .deposit_index
//         .chunks(8)
//         .map(|x| {
//             let y: [usize; 8] = x.try_into().unwrap();
//             y
//         })
//         .collect();
//     let mut out_hash = blake3_ckt::hash(bld, inps);
//     let zero_byte = [bld.zero(); 8];
//     out_hash[0..4].copy_from_slice(&[zero_byte; 4]); // MSB masked assuming BE
//     out_hash.reverse();
//
//     let out_hash_flat: Vec<usize> = out_hash.into_iter().flatten().collect();
//     let out_fr: Fr = out_hash_flat[0..FR_LEN].try_into().unwrap();
//     out_fr
// }

/// Function to compile dvsnark verifier circuit
pub fn compile_verifier() -> (CircuitAdapter, IndexInfo) {
    let mut bld = CircuitAdapter::default();

    let input_wire_start = bld.next_wire();
    let (proof, rpin, secrets) = get_input_indexes(&mut bld);
    let input_wire_end = bld.next_wire();

    // Prepare
    let passed_index = verify(&mut bld, proof, rpin, secrets);
    let index_info = IndexInfo {
        input_wire_range: (input_wire_start, input_wire_end - 1), // -1 because inclusive range
        const_zero: bld.zero(),
        const_one: bld.one(),
        output_index: passed_index,
    };
    (bld, index_info)
}

/// evaluate verifier
pub fn evaluate_verifier(
    bld: &mut CircuitAdapter,
    witness: [bool; WITNESS_BIT_LEN],
    output_wire_index: usize,
) -> bool {
    let wires = bld.eval_gates(&witness);
    wires[output_wire_index]
}

/// verify
pub(crate) fn verify<T: CircuitTrait>(
    bld: &mut T,
    proof: Proof,
    public_inputs: PublicInputs,
    secrets: Trapdoor,
) -> usize {
    let is_proof_commit_p_on_curve =
        G1Projective::emit_projective_montgomery_point_is_on_curve(bld, &proof.mont_commit_p);
    let is_proof_kzg_k_on_curve =
        G1Projective::emit_projective_montgomery_point_is_on_curve(bld, &proof.mont_kzg_k);

    let one_wire = bld.one();
    let fr_modulus = U254::wires_set_from_number(bld, &Fr::modulus_as_biguint());
    let proof_a0_invalid = Fr::ge_unsigned(bld, &proof.mont_a0.0, &fr_modulus); // a0 should be less than modulus
    let proof_b0_invalid = Fr::ge_unsigned(bld, &proof.mont_b0.0, &fr_modulus);
    let proof_scalars_invalid = bld.or_wire(proof_a0_invalid, proof_b0_invalid); // either invalid
    let proof_scalars_valid = bld.xor_wire(proof_scalars_invalid, one_wire); // both scalars valid
    let decoded_points_valid = bld.and_wire(is_proof_commit_p_on_curve, is_proof_kzg_k_on_curve); // both points valid

    let point_and_decode_valid_stats = bld.gate_counts();
    println!("point_and_decode_valid_stats: {:?}", point_and_decode_valid_stats);

    let fs_challenge_alpha =
        get_fs_challenge(bld, &proof.mont_commit_p, public_inputs.public_inputs.clone(), vec![], vec![]);
    let i0 = {
        let t0 = Fr::mul_montgomery(bld, &public_inputs.public_inputs[1].0, &fs_challenge_alpha.0);
        Fr::add(bld, &t0, &public_inputs.public_inputs[0].0)
    };

    let r0 = {
        //&proof.a0 * &proof.b0 - &proof.i0
        let t0 = Fr::mul_montgomery(bld, &proof.mont_a0.0, &proof.mont_b0.0);
        Fr::sub(bld, &t0, &i0)
    };

    // Step 3. Compute u₀ and v₀
    let u0 = {
        //(proof.a0 + secrets.delta * (proof.b0 + secrets.delta * r0)) * secrets.epsilon
        let delta_r0 = Fr::mul_montgomery(bld, &secrets.delta.0, &r0);
        let b0_plus = Fr::add(bld, &proof.mont_b0.0, &delta_r0);
        let inner = Fr::mul_montgomery(bld, &secrets.delta.0, &b0_plus);
        let sum = Fr::add(bld, &proof.mont_a0.0, &inner);

        Fr::mul_montgomery(bld, &sum, &secrets.epsilon.0)
    };

    let tmp0 = Fr::sub(bld, &secrets.tau.0, &fs_challenge_alpha.0);
    let v0 = Fr::mul_montgomery(bld, &tmp0, &secrets.epsilon.0);

    let u0_v0_stats = bld.gate_counts();
    println!("u0_v0_stats: {:?}", u0_v0_stats);

    let generator = G1Projective::wires_set_montgomery_generator(bld);
    let lhs = G1Projective::msm_montgomery_circuit(
        bld,
        &[u0, v0],
        &[generator, proof.mont_kzg_k.to_vec_wires()]
    );

    let lhs_stats = bld.gate_counts();
    println!("lhs_stats: {:?}", lhs_stats);

    let mont_r = ark_bn254::Fr::from(Fr::montgomery_r_as_biguint());
    let mont_r_wires = Fr::wires_set(bld, mont_r.clone());

    let rhs = G1Projective::scalar_mul_montgomery_circuit(
        bld,
        &mont_r_wires.0.to_vec(),
        &proof.mont_commit_p.to_vec_wires(),
    );

    let verify_success = G1Projective::equal(bld, &lhs, &rhs);
    let eq_with_valid_points = bld.and_wire(verify_success, decoded_points_valid);
    bld.and_wire(eq_with_valid_points, proof_scalars_valid)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use crate::circuits::sect233k1::builder::{CircuitAdapter, CircuitTrait};
    use crate::dv_bn254::bigint::U254;
    use crate::dv_bn254::dv_ckt::{get_fs_challenge, get_input_indexes};
    use crate::dv_bn254::dv_ref::{FrRef, ProofRef, PublicInputsRef, TrapdoorRef, VerifierPayloadRef};
    use crate::dv_bn254::fp254impl::Fp254Impl;
    use crate::dv_bn254::fr::Fr;
    use crate::dv_bn254::g1::G1Projective;

    fn initialize_witness() -> VerifierPayloadRef {
        // Prepare VerifierPayloadRef
        let tau = FrRef::from_str(
            "16182941859318853681113132547625168061780848020606917705886909352328641449447",
        )
            .unwrap();
        let delta = FrRef::from_str(
            "1386358569040211194277496369854236447924640692868989861989546836976256123776",
        )
            .unwrap();
        let epsilon = FrRef::from_str(
            "19902273041930411779697910799612905558671735917586419204128025082060670839903",
        )
            .unwrap();
        let mont_commit_p = ark_bn254::G1Projective::new_unchecked(
            ark_bn254::Fq::from_str("17828526848398818524594272010037255222158469049154221871955648825738160508900").unwrap(),
            ark_bn254::Fq::from_str("14170820817868591051981977221323237801250104508723967068773366962772917797098").unwrap(),
            ark_bn254::Fq::from_str("2513762298069720657829538045439982366122625059238132972369886427106554100054").unwrap(),
        );
        let mont_kzg_k = ark_bn254::G1Projective::new_unchecked(
            ark_bn254::Fq::from_str("16107189865462081378229596490861223404542946800177144985196035470958801847361").unwrap(),
            ark_bn254::Fq::from_str("3802773935032520992617144264570824192793931554569247968920659382962943815109").unwrap(),
            ark_bn254::Fq::from_str("80507567559795152954437834756393180561412479055708978020511381804595023465").unwrap(),
        );

        let a0 = FrRef::from_str(
            "2975525620490834464405940205011309071747726351692005111228101901132749428958",
        )
            .unwrap();
        let b0 = FrRef::from_str(
            "9701346963693590595658518476858392988245806407586431150638849218581259322452",
        )
            .unwrap();

        let public_inputs = [
            FrRef::from_str("16217006396879640651787331949151919374620611580946319582101174263628714475489")
                .unwrap(),
            FrRef::from_str("4224161200009956348416803608862024017805255356259249285367676853928926904303")
                .unwrap(),
        ];

        let witness = VerifierPayloadRef {
            proof: ProofRef { mont_commit_p, mont_kzg_k, mont_a0: a0, mont_b0: b0 },
            public_input: PublicInputsRef { public_inputs },
            trapdoor: TrapdoorRef { tau, delta, epsilon },
        };
        witness
    }

    #[test]
    fn test_proof_valid() {
        let witness = initialize_witness();
        let mut bld = CircuitAdapter::default();
        let (proof, _, _) = get_input_indexes(&mut bld);

        let is_proof_commit_p_on_curve =
            G1Projective::emit_projective_montgomery_point_is_on_curve(&mut bld, &proof.mont_commit_p);
        let is_proof_kzg_k_on_curve =
            G1Projective::emit_projective_montgomery_point_is_on_curve(&mut bld, &proof.mont_kzg_k);

        let one_wire = bld.one();
        let fr_modulus = U254::wires_set_from_number(&mut bld, &Fr::modulus_as_biguint());
        let proof_a0_invalid = Fr::ge_unsigned(&mut bld, &proof.mont_a0.0, &fr_modulus); // a0 should be less than modulus
        let proof_b0_invalid = Fr::ge_unsigned(&mut bld, &proof.mont_b0.0, &fr_modulus);
        let proof_scalars_invalid = bld.or_wire(proof_a0_invalid, proof_b0_invalid); // either invalid
        let proof_scalars_valid = bld.xor_wire(proof_scalars_invalid, one_wire); // both scalars valid
        let decoded_points_valid = bld.and_wire(is_proof_commit_p_on_curve, is_proof_kzg_k_on_curve); // both points valid
        let valid = bld.and_wire(proof_scalars_valid, decoded_points_valid);
        // eval
        let wires_bits = bld.eval_gates(&witness.to_bits());
        let valid_val = wires_bits[valid];
        assert!(valid_val);
        let stats = bld.gate_counts();
        println!("{stats}");
    }


    #[test]
    fn test_compute_u0_v0() {
        let witness = initialize_witness();

        let mut bld = CircuitAdapter::default();
        let (proof, rpin, secrets) = get_input_indexes(&mut bld);

        let fs_challenge_alpha =
            get_fs_challenge(&mut bld, &proof.mont_commit_p, rpin.public_inputs.clone(), vec![], vec![]);
        let i0 = {
            let t0 = Fr::mul_montgomery(&mut bld, &rpin.public_inputs[1].0, &fs_challenge_alpha.0);
            Fr::add(&mut bld, &t0, &rpin.public_inputs[0].0)
        };

        let r0 = {
            //&proof.a0 * &proof.b0 - &proof.i0
            let t0 = Fr::mul_montgomery(&mut bld, &proof.mont_a0.0, &proof.mont_b0.0);
            Fr::sub(&mut bld, &t0, &i0)
        };

        // Step 3. Compute u₀ and v₀
        let u0 = {
            //(proof.a0 + secrets.delta * (proof.b0 + secrets.delta * r0)) * secrets.epsilon
            let delta_r0 = Fr::mul_montgomery(&mut bld, &secrets.delta.0, &r0);
            let b0_plus = Fr::add(&mut bld, &proof.mont_b0.0, &delta_r0);
            let inner = Fr::mul_montgomery(&mut bld, &secrets.delta.0, &b0_plus);
            let sum = Fr::add(&mut bld, &proof.mont_a0.0, &inner);

            Fr::mul_montgomery(&mut bld, &sum, &secrets.epsilon.0)
        };

        let tmp0 = Fr::sub(&mut bld, &secrets.tau.0, &fs_challenge_alpha.0);
        let v0 = Fr::mul_montgomery(&mut bld, &tmp0, &secrets.epsilon.0);

        // eval:
        let wires_bits = bld.eval_gates(&witness.to_bits());

        let u0_bits = u0.iter().map(|w| wires_bits[*w]).collect::<Vec<bool>>();
        let v0_bits = v0.iter().map(|w| wires_bits[*w]).collect::<Vec<bool>>();
        let u0_val = Fr::from_bits(u0_bits);
        let v0_val = Fr::from_bits(v0_bits);

        let expected_u0 = ark_bn254::Fr::from_str(
            "9743625272928946869194351638312418140554477278217161320708001866919619239351",
        )
            .unwrap();
        let expected_v0 = ark_bn254::Fr::from_str(
            "14697703236190320965425825895501867787787703590667291868986257847520837972012",
        )
            .unwrap();

        let mont_u0 = Fr::as_montgomery(expected_u0);
        let mont_v0 = Fr::as_montgomery(expected_v0);
        assert_eq!(u0_val, mont_u0);
        assert_eq!(v0_val, mont_v0);

        let stats = bld.gate_counts();
        println!("{stats}");
    }

    #[test]
    #[ignore]
    fn test_point_computation() {

        let mont_commit_p = ark_bn254::G1Projective::new_unchecked(
            ark_bn254::Fq::from_str("17828526848398818524594272010037255222158469049154221871955648825738160508900").unwrap(),
            ark_bn254::Fq::from_str("14170820817868591051981977221323237801250104508723967068773366962772917797098").unwrap(),
            ark_bn254::Fq::from_str("2513762298069720657829538045439982366122625059238132972369886427106554100054").unwrap(),
        );
        let mont_kzg_k = ark_bn254::G1Projective::new_unchecked(
            ark_bn254::Fq::from_str("16107189865462081378229596490861223404542946800177144985196035470958801847361").unwrap(),
            ark_bn254::Fq::from_str("3802773935032520992617144264570824192793931554569247968920659382962943815109").unwrap(),
            ark_bn254::Fq::from_str("80507567559795152954437834756393180561412479055708978020511381804595023465").unwrap(),
        );

        let mont_u0 = ark_bn254::Fr::from_str("11652346764044857618553525053657312136468629477167387001167575917396119875544").unwrap();
        let mont_v0 = ark_bn254::Fr::from_str("6813834760176976181591963068295107428614621550608555479227816612274682117051").unwrap();
        let mont_r = ark_bn254::Fr::from(Fr::montgomery_r_as_biguint());

        let mut bld = CircuitAdapter::default();
        let mont_p_wires = G1Projective::wires(&mut bld);
        let mont_k_wires = G1Projective::wires(&mut bld);
        let mont_u0_wires = Fr::wires(&mut bld);
        let mont_v0_wires = Fr::wires(&mut bld);

        let mont_r_wires = Fr::wires_set(&mut bld, mont_r.clone());
        let mont_generator_wires = G1Projective::wires_set_montgomery_generator(&mut bld);

        let lhs_wires = G1Projective::msm_montgomery_circuit(
            &mut bld,
            &[mont_v0_wires.0.to_vec(), mont_u0_wires.0.to_vec()],
            &[mont_k_wires.to_vec_wires(), mont_generator_wires],
        );

        let rhs_wires = G1Projective::scalar_mul_montgomery_circuit(
            &mut bld,
            &mont_r_wires.0.to_vec(),
            &mont_p_wires.to_vec_wires(),
        );

        let witness = G1Projective::to_bits(mont_commit_p)
            .into_iter()
            .chain(G1Projective::to_bits(mont_kzg_k))
            .chain(Fr::to_bits(mont_u0).into_iter())
            .chain(Fr::to_bits(mont_v0).into_iter())
            .collect::<Vec<bool>>();

        let wires_bits = bld.eval_gates(&witness);
        let lhs_bits = lhs_wires.iter().map(|id| wires_bits[*id]).collect();
        let rhs_bits = rhs_wires.iter().map(|id| wires_bits[*id]).collect();

        let lhs = G1Projective::from_bits_unchecked(lhs_bits);
        let rhs = G1Projective::from_bits_unchecked(rhs_bits);
        assert_eq!(lhs, rhs);

        let stats = bld.gate_counts();
        println!("{stats}");
    }
}