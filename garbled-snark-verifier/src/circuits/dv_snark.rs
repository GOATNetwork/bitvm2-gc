use crate::bag::Circuit;
use crate::circuits::sect233k1::dv_ckt::{VerifierPayloadRef, compile_verifier};
use std::time::Instant;

pub fn dv_snark_verifier_circuit(witness: &VerifierPayloadRef) -> Circuit {
    let start = Instant::now();
    let (builder, _) = compile_verifier();
    println!("Compile time: {:?}", start.elapsed());

    let start = Instant::now();
    let circuit = builder.build(&witness.to_bits());
    println!("build circuit time:{:?}", start.elapsed());

    circuit
}

#[cfg(test)]
mod test {
    use crate::circuits::dv_snark::dv_snark_verifier_circuit;
    use crate::circuits::sect233k1::curve_ckt::AffinePointRef;
    use crate::circuits::sect233k1::dv_ckt::{
        ProofRef, PublicInputsRef, TrapdoorRef, VerifierPayloadRef,
    };
    use crate::circuits::sect233k1::fr_ref::FrRef;
    use std::str::FromStr;
    use std::time::Instant;
    #[test]
    #[ignore]
    fn test_dv_snark_verifier_circuit() {
        // Prepare VerifierPayloadRef
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
        let commit_p = AffinePointRef {
            x: [
                130, 16, 132, 245, 115, 118, 110, 233, 235, 58, 5, 190, 187, 230, 138, 225, 149,
                231, 32, 45, 41, 29, 94, 89, 248, 158, 54, 19, 86, 0,
            ],
            s: [
                93, 74, 178, 168, 173, 38, 101, 88, 181, 49, 78, 207, 89, 78, 130, 42, 242, 245,
                88, 5, 253, 250, 54, 182, 177, 249, 82, 57, 147, 0,
            ],
        };
        let kzg_k = AffinePointRef {
            x: [
                36, 69, 122, 22, 89, 79, 186, 56, 138, 8, 183, 193, 186, 98, 21, 62, 9, 143, 173,
                24, 89, 195, 126, 73, 241, 118, 71, 103, 223, 0,
            ],
            s: [
                12, 122, 106, 168, 104, 248, 117, 18, 171, 218, 85, 138, 31, 80, 250, 230, 176,
                136, 74, 129, 137, 78, 181, 48, 88, 180, 21, 139, 39, 1,
            ],
        };
        let a0 = FrRef::from_str(
            "1858232303623355521215721639157430371979542022979851183514844283900649",
        )
        .unwrap();
        let b0 = FrRef::from_str(
            "3045644831070136055562137919853497607898653327126781771795842528553732",
        )
        .unwrap();

        let public_inputs = [
            FrRef::from_str("9487159538405616582219466419827834782293111327936747259752845028149")
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

        for gate in &mut circuit.1 {
            gate.evaluate();
        }
        assert!(circuit.0[0].borrow().get_value());
    }
}
