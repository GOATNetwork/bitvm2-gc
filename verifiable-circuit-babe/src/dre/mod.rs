use ark_bn254::Fq;

pub mod utils;
pub mod matrices;
pub const N: usize = 254;
pub const L: usize = 1 + 5 * N; // 1271

/// Decoding: f_i = r_i·π + ρ_i  (Jacobian coords)
pub struct DREDecoding {
    pub f_i: (Fq, Fq, Fq),
}