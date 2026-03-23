use ark_bn254::{Fq, Fr, G1Affine};
use ark_ff::{UniformRand, Zero};
use garbled_snark_verifier::bag::S;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::dre::{N, utils::sample_rhos};

pub struct InstanceSecrets {
    pub delta:         S,
    pub r:             Fr,
    pub msg:           [u8; 32],
    /// label0 per input wire, size = 2 * N
    pub encoding_keys: Vec<S>,
    /// Two constant-wire 0-labels
    pub constant_0labels: [S; 2],
    /// N rho_i which sum = 0
    pub rhos:          Vec<G1Affine>,
    /// N non-zero Fq scalars for each diag()
    pub fq_deltas:     Vec<Fq>,
}

/// Derive all per-instance secrets deterministically from a single seed.
/// with fixed order.
pub fn derive_instance(seed: u64) -> InstanceSecrets {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let mut delta_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rng, &mut delta_bytes);
    delta_bytes[15] |= 1;
    let delta = S(delta_bytes);

    let r = Fr::rand(&mut rng);

    let mut msg = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut msg);

    let encoding_keys: Vec<S> = (0..2 * N)
        .map(|_| {
            let mut b = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rng, &mut b);
            S(b)
        })
        .collect();

    let constant_0labels = {
        let mut b0 = [0u8; 16];
        let mut b1 = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rng, &mut b0);
        rand::RngCore::fill_bytes(&mut rng, &mut b1);
        [S(b0), S(b1)]
    };

    let rhos = sample_rhos(&mut rng);
    
    let fq_deltas: Vec<Fq> = (0..N)
        .map(|_| loop {
            let v = Fq::rand(&mut rng);
            if !v.is_zero() {
                break v;
            }
        })
        .collect();

    InstanceSecrets { delta, r, msg, encoding_keys, constant_0labels, rhos, fq_deltas }
}
