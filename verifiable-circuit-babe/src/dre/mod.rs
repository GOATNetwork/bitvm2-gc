use ark_bn254::{Fq, G1Affine};

pub mod utils;
pub mod matrices;
mod weighted_dre;
mod affine_dre;

pub const N: usize = 254;
pub const L: usize = 1 + 5 * N; // 1271

pub trait DRE {
    type Input;
    type Encoding;
    type Decoding;

    fn enc(input: Self::Input) -> Self::Encoding;

    fn dec(encoding: Self::Encoding) -> Self::Decoding;
}
