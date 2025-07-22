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
    core::utils::check_guest,
};
fn main() {
    let mut buf = zkm_zkvm::io::read_vec();
    check_guest(&buf);
}
