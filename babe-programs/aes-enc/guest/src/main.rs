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
use garbled_snark_verifier::bag::S;
use verifiable_circuit_babe::gc::utils::aes_enc;

fn main() {
    let tmp = ark_bn254::Fq::from(20_u64);
    let key = S::from_slice(&[0u8; 16]);
    let res = aes_enc(&tmp, &key.0);
    zkm_zkvm::io::commit::<[u8; 32]>(&res);
}
