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

use alloc::vec::Vec;
use garbled_snark_verifier::core::utils::{check_guest, SUB_INPUT_GATES_PARTS};
use zkm_zkvm::lib::ciphertext_check::ciphertext_check;
fn main() {
    let mut sub_gates: [Vec<u8>; SUB_INPUT_GATES_PARTS] = core::array::from_fn(|_| Vec::new());
    for i in 0..SUB_INPUT_GATES_PARTS {
        sub_gates[i] = zkm_zkvm::io::read_vec();
    }
    let sub_wires = zkm_zkvm::io::read_vec();
    let sub_ciphertexts = zkm_zkvm::io::read_vec();
    let input = check_guest(&sub_gates, &sub_wires, &sub_ciphertexts);
    let output = ciphertext_check(&input);
    assert!(output);
}
