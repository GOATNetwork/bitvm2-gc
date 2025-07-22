//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

use garbled_snark_verifier::circuits::bigint::{
    utils::{biguint_from_wires, random_biguint_n_bits},
    U254,
};
use garbled_snark_verifier::circuits::bn254::fp254impl::Fp254Impl;
use garbled_snark_verifier::circuits::bn254::fq::Fq;

fn main() {
    let a = Fq::random();
    let mut circuit = Fq::div6(Fq::wires_set(a));
    circuit.gate_counts().print();
    //for mut gate in circuit.1 {
    //    gate.evaluate();
    //}

    //let c = Fq::from_wires(circuit.0);
    //assert_eq!(c + c + c + c + c + c, a);

    let garbled = circuit.garbled_gates();
    zkm_zkvm::io::commit(&garbled.len());
}
