use crate::bag::Circuit;
use crate::circuits::sect233k1::dv_ckt::{
    ProofRef, PublicInputsRef, TrapdoorRef, VerifierPayloadRef, compile_verifier,
};
use crate::circuits::sect233k1::fr_ref::FrRef;
use std::str::FromStr;
use std::time::Instant;

pub fn dv_snark_verifier_circuit(witness: &VerifierPayloadRef) -> Circuit {
    let start = Instant::now();
    let (builder, _) = compile_verifier();
    println!("Compile time: {:?}", start.elapsed());

    let start = Instant::now();
    let circuit = builder.build(witness.to_bits());
    println!("build circuit time:{:?}", start.elapsed());

    circuit
}

#[test]
fn test_dv_snark_verifier_circuit() {
    // Prepare VerifierPayloadRef
    let tau =
        FrRef::from_str("490782060457092443021184404188169115419401325819878347174959236155604")
            .unwrap();
    let delta =
        FrRef::from_str("409859792668509615016679153954612494269657711226760893245268993658466")
            .unwrap();
    let epsilon =
        FrRef::from_str("2880039972651592580549544494658966441531834740391411845954153637005104")
            .unwrap();

    let commit_p: [u8; 30] = [
        168, 213, 19, 178, 72, 50, 17, 173, 121, 162, 3, 162, 60, 63, 237, 145, 179, 165, 165, 135,
        87, 158, 208, 2, 246, 88, 48, 98, 79, 1,
    ];
    let kzg_k: [u8; 30] = [
        231, 54, 75, 155, 102, 116, 56, 195, 20, 172, 98, 121, 191, 219, 4, 75, 2, 26, 23, 57, 159,
        205, 208, 26, 222, 157, 94, 111, 97, 0,
    ];
    let a0 =
        FrRef::from_str("2787213486297295799494233727790939750249020822604491580499143810600903")
            .unwrap();
    let b0 =
        FrRef::from_str("1072602516393469765221017154198322485985591404674386889774270216915229")
            .unwrap();

    let public_inputs = [
        FrRef::from_str("10964902444291521893664765711676021715483874668026528518811070427510")
            .unwrap(),
        FrRef::from_str("22596372664815072823112258091854569627353949811861389086305200952659")
            .unwrap(),
    ];

    let witness = VerifierPayloadRef {
        proof: ProofRef { commit_p, kzg_k, a0, b0 },
        public_input: PublicInputsRef { public_inputs },
        trapdoor: TrapdoorRef { tau, delta, epsilon },
    };

    let mut circuit = dv_snark_verifier_circuit(&witness);
    let start = Instant::now();
    let total_gates = circuit.gate_counts();
    println!("gate_counts time: {:?}", start.elapsed());
    total_gates.print();

    // for gate in &mut circuit.1 {
    //     gate.evaluate();
    // }
    // assert!(circuit.0[0].borrow().get_value());
}
