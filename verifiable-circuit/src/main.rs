//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_std]
#![no_main]
extern crate alloc;

zkm_zkvm::entrypoint!(main);
use garbled_snark_verifier::{
    bag::{Circuit, S},
    core::utils::SerializableCircuit,
};
fn main() {
    let sc: SerializableCircuit = zkm_zkvm::io::read();
    let circuit: Circuit = (&sc).into();

    let garblings = circuit.garbled_gates();

    assert!(garblings == sc.garblings);

    zkm_zkvm::io::commit(&garblings.len());
    zkm_zkvm::io::commit(&garblings[0]);
    zkm_zkvm::io::commit(&sc.garblings[0]);
}
