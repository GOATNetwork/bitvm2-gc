use crate::bag::Circuit;
use std::time::Instant;
use crate::dv_bn254::dv_ckt::compile_verifier_argo_hybrid;
use crate::dv_bn254::dv_ref::VerifierPayloadRef;
use crate::argo_mac::verify_step4_with_argo_roles;

pub fn dv_snark_verifier_circuit(
    witness: &VerifierPayloadRef
) -> Circuit {
    // Argo MAC pre-check for Step4 formula:
    //   x1*G + x2*Q + z_signed*P = O.
    let argo_step4_ok = dv_snark_step4_argo_mac_verify(witness);
    assert!(argo_step4_ok, "Argo MAC Step4 check failed");

    let start = Instant::now();
    // Use hybrid compiler where Step4 heavy GC is replaced by one external input bit.
    let (builder, _) = compile_verifier_argo_hybrid();
    println!("Compile time: {:?}", start.elapsed());
    let start = Instant::now();
    let mut witness_bits = witness.to_bits().to_vec();
    // External input formula:
    //   step4_valid_external == 1  <=>  x1*G + x2*Q + z_signed*P == O.
    witness_bits.push(argo_step4_ok);
    let circuit = builder.build(&witness_bits);
    println!("build circuit time:{:?}", start.elapsed());

    circuit
}

pub fn dv_snark_verifier_bench_circuit(
    witness: &VerifierPayloadRef
) -> Circuit {
    // Argo MAC pre-check for Step4 formula:
    //   x1*G + x2*Q + z_signed*P = O.
    let argo_step4_ok = dv_snark_step4_argo_mac_verify(witness);
    assert!(argo_step4_ok, "Argo MAC Step4 check failed");

    let start = Instant::now();
    // Use hybrid compiler where Step4 heavy GC is replaced by one external input bit.
    let (builder, _) = compile_verifier_argo_hybrid();
    println!("Compile time: {:?}", start.elapsed());
    let start = Instant::now();
    let mut witness_bits = witness.to_bits().to_vec();
    // External input formula:
    //   step4_valid_external == 1  <=>  x1*G + x2*Q + z_signed*P == O.
    witness_bits.push(argo_step4_ok);
    let circuit = builder.build_benchmark(&witness_bits);
    println!("build circuit time:{:?}", start.elapsed());

    circuit
}

/// Verify DV-SNARK step4 in Argo MAC domain.
///
/// Step4 formula in current dv_ckt sign convention:
///   R = x1*G + x2*Q + z_signed*P
/// and check
///   R == O.
///
/// Here:
/// - Q = kzg_k, P = commit_p (same ordering as dv_ckt::verify)
/// - x1_neg / x2_neg follow negate_with_neg_selector
/// - z_pos follows negate_with_pos_selector
pub fn dv_snark_step4_argo_mac_verify(witness: &VerifierPayloadRef) -> bool {
    verify_step4_with_argo_roles(
        witness.proof.mont_kzg_k.clone(),
        witness.proof.mont_commit_p.clone(),
        witness.proof.x1.0.clone(),
        witness.proof.x1.1,
        witness.proof.x2.0.clone(),
        witness.proof.x2.1,
        witness.proof.z.0.clone(),
        witness.proof.z.1,
        20260225, // deterministic seed for reproducible testing
    )
}

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use crate::circuits::sect233k1::builder::CircuitTrait;
    use crate::dv_bn254::dv_ckt::compile_verifier;
    use crate::dv_bn254::dv_ref::{FrRef, ProofRef, PublicInputsRef, TrapdoorRef, VerifierPayloadRef};
    use crate::dv_bn254::dv_snark::dv_snark_step4_argo_mac_verify;


    fn initialize_witness() -> VerifierPayloadRef{
        // Prepare VerifierPayloadRef
        let tau = FrRef::from_str(
            "11862927736293505976827355338938040996519579475528107310941684119781757391039",
        )
            .unwrap();
        let delta = FrRef::from_str(
            "19144933261297331633080959100481380589633074304003794613695593869462980578759",
        )
            .unwrap();
        let epsilon = FrRef::from_str(
            "313961560996054992893313828582054121800731311457442837960229611969948337040",
        )
            .unwrap();
        let mont_commit_p = ark_bn254::G1Projective::new_unchecked(
            ark_bn254::Fq::from_str("7945797433559704849311923614598929259737771858793098395236612582183144719173").unwrap(),
            ark_bn254::Fq::from_str("17012034996486701113694275047646644230671894233797105837810220927620239598653").unwrap(),
            ark_bn254::Fq::from_str("1904029105985936155224998850934598237583320194268951485119152920799350410912").unwrap(),
        );
        let mont_kzg_k = ark_bn254::G1Projective::new_unchecked(
            ark_bn254::Fq::from_str("218840416271392248134913265936769272628298608502613289864227836162651470083").unwrap(),
            ark_bn254::Fq::from_str("12507096977197660920086344758001040257535547413335347824125243167552228396643").unwrap(),
            ark_bn254::Fq::from_str("7718594443256972252891810807829015169125545629599067047189461244308075009980").unwrap(),
        );

        let mont_a0 = FrRef::from_str(
            "2379383345977345328483769109781010318500935685616923216261946203557840245156",
        )
            .unwrap();
        let mont_b0 = FrRef::from_str(
            "10710067834367256827276997192305278081193710391606660405083208486036847880486",
        )
            .unwrap();

        let x1_val = FrRef::from_str(
            "117254209170240570118468483301402360720011190156626"
        ).unwrap();
        let x1 = (x1_val, false);
        let x2_val = FrRef::from_str(
            "428956628384832546334058967498472364665310775024525"
        ).unwrap();
        let x2 = (x2_val, false);
        let z_val = FrRef::from_str(
            "382966261084432891439040614202494776072682302885809"
        ).unwrap();
        let z = (z_val, true);

        let public_inputs = [
            FrRef::from_str("16217006396879640651787331949151919374620611580946319582101174263628714475489")
                .unwrap(),
            FrRef::from_str("4224161200009956348416803608862024017805255356259249285367676853928926904303")
                .unwrap(),
        ];

        let witness = VerifierPayloadRef {
            proof: ProofRef { mont_commit_p, mont_kzg_k, mont_a0, mont_b0, x1, x2, z },
            public_input: PublicInputsRef { public_inputs },
            trapdoor: TrapdoorRef { tau, delta, epsilon },
        };
        witness
    }
    #[test]
    fn test_dv_snark_verifier_circuit_dvbn254() {
        // Prepare VerifierPayloadRef
        let witness = initialize_witness();

        let (bld, info) = compile_verifier();
        let wires_bits = bld.eval_gates(&witness.to_bits());
        println!("number of wires: {}", wires_bits.len());

        let output_value = wires_bits[info.output_index];
        println!("output_value: {}", output_value);
        assert_eq!(output_value, true);

        let stats = bld.gate_counts();
        println!("Gate counts: {:?}", stats);
    }

    #[test]
    fn test_dv_snark_step4_argo_mac_verify() {
        let witness = initialize_witness();
        // Formula-level check in Argo MAC domain:
        //   x1*G + x2*Q + z_signed*P == O
        assert!(dv_snark_step4_argo_mac_verify(&witness));
    }
}
