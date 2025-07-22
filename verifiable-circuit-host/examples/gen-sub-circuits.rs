//! cargo run -r --example gen-sub-circuits -- --nocapture
use garbled_snark_verifier::circuits::bigint::{
    U254,
    utils::{biguint_from_wires, random_biguint_n_bits},
};
use garbled_snark_verifier::circuits::bn254::fp254impl::Fp254Impl;
use garbled_snark_verifier::circuits::bn254::fq::Fq;

fn main() {
    let a = Fq::random();
    let mut circuit = Fq::div6(Fq::wires_set(a));
    circuit.gate_counts().print();
    for gate in &mut circuit.1 {
        gate.evaluate();
    }

    let c = Fq::from_wires(circuit.0.clone());
    assert_eq!(c + c + c + c + c + c, a);

    let garbled = circuit.garbled_gates();

    // split the GC into sub-circuits
    println!("garbled:{:?}", garbled.len());
}
