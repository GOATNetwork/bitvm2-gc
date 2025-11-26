use crate::bag::Circuit;
use std::time::Instant;
use crate::dv_bn254::dv_ckt::compile_verifier;
use crate::dv_bn254::dv_ref::VerifierPayloadRef;

pub fn dv_snark_verifier_circuit(
    witness: &VerifierPayloadRef
) -> Circuit {
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
    use std::str::FromStr;
    use crate::circuits::sect233k1::builder::CircuitTrait;
    use crate::dv_bn254::dv_ckt::compile_verifier;
    use crate::dv_bn254::dv_ref::{FrRef, ProofRef, PublicInputsRef, TrapdoorRef, VerifierPayloadRef};


    fn initialize_witness() -> VerifierPayloadRef{
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
    fn test_dv_snark_verifier_circuit_vjp() {
        // Prepare VerifierPayloadRef
        let witness = initialize_witness();

        let (bld, info) = compile_verifier();
        let wires_bits = bld.eval_gates(&witness.to_bits());

        let output_value = wires_bits[info.output_index];
        println!("output_value: {}", output_value);

        let stats = bld.gate_counts();
        println!("Gate counts: {:?}", stats);
    }
}
